use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use asc_daemon::DaemonHandler;
use asc_daemon_core::PeerCredentials;
use asc_daemon_protocol::{DaemonError, DaemonRequest, DaemonResponse, RequestId};
use asc_foundation_types::{ResourceId, Revision};
use asc_pap::{
    BindingRevisionState, Page, PapError, PapRepository, PapService, PolicyCompiler,
    PolicyRevisionState, ScopeRevisionState,
};
use asc_policy_types::authoring::TemplateEnvelope;
use asc_policy_types::binding::{BindingStatus, BindingView, PreparedBinding};
use asc_policy_types::error::ValidationError;
use asc_policy_types::identifiers::PolicyId;
use asc_policy_types::policy::{PolicyEnvelope, PreparedPolicy};
use asc_policy_types::scope::PreparedScope;
use serde_json::{Value, json};

const COMPLETE_BINDING: &str =
    include_str!("../../../crates/policy/asc-policy-types/tests/fixtures/prepared-binding.json");

#[derive(Default)]
struct FakeState {
    policy_heads: BTreeMap<String, u32>,
    policies: BTreeMap<(String, u32), PreparedPolicy>,
    scope_heads: BTreeMap<String, u32>,
    scopes: BTreeMap<(String, u32), PreparedScope>,
    binding_heads: BTreeMap<String, u32>,
    binding_specs: BTreeMap<(String, u32), PreparedBinding>,
    binding_statuses: BTreeMap<String, BindingStatus>,
}

#[derive(Default)]
struct FakeRepository {
    state: Mutex<FakeState>,
    fail_persistence: AtomicBool,
}

impl FakeRepository {
    fn lock(&self) -> Result<MutexGuard<'_, FakeState>, PapError> {
        if self.fail_persistence.load(Ordering::Relaxed) {
            return Err(PapError::Persistence);
        }
        self.state.lock().map_err(|_| PapError::Persistence)
    }

    fn set_fail_persistence(&self, value: bool) {
        self.fail_persistence.store(value, Ordering::Relaxed);
    }
}

impl PapRepository for FakeRepository {
    fn put_policy(&self, policy: &PreparedPolicy) -> Result<PreparedPolicy, PapError> {
        let mut state = self.lock()?;
        let id = policy.policy_id.as_str().to_owned();
        let revision = policy.revision.get();
        let key = (id.clone(), revision);
        if let Some(existing) = state.policies.get(&key) {
            return if existing == policy {
                Ok(existing.clone())
            } else {
                Err(PapError::Conflict)
            };
        }
        if next_raw_revision(state.policy_heads.get(&id).copied()) != Some(revision) {
            return Err(PapError::Conflict);
        }
        state.policies.insert(key, policy.clone());
        state.policy_heads.insert(id, revision);
        Ok(policy.clone())
    }

    fn get_policy_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<PolicyRevisionState>, PapError> {
        let state = self.lock()?;
        let Some(last) = state.policy_heads.get(id.as_str()).copied() else {
            return Ok(None);
        };
        let latest = state
            .policies
            .iter()
            .filter(|((candidate, _), _)| candidate == id.as_str())
            .max_by_key(|((_, revision), _)| *revision)
            .map(|(_, policy)| policy.clone());
        Ok(Some(PolicyRevisionState {
            last_allocated_revision: Revision::new(last).map_err(|_| PapError::Persistence)?,
            latest,
        }))
    }

    fn get_policy(&self, id: &ResourceId, revision: Revision) -> Result<PreparedPolicy, PapError> {
        self.lock()?
            .policies
            .get(&(id.as_str().to_owned(), revision.get()))
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError> {
        let items = self.lock()?.policies.values().cloned().collect();
        Ok(page(items, limit, offset))
    }

    fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        self.lock()?
            .policies
            .remove(&(id.as_str().to_owned(), revision.get()))
            .ok_or(PapError::NotFound)
    }

    fn put_scope(&self, scope: &PreparedScope) -> Result<PreparedScope, PapError> {
        let mut state = self.lock()?;
        let id = scope.scope_id.as_str().to_owned();
        let revision = scope.revision.get();
        let key = (id.clone(), revision);
        if let Some(existing) = state.scopes.get(&key) {
            return if existing == scope {
                Ok(existing.clone())
            } else {
                Err(PapError::Conflict)
            };
        }
        if next_raw_revision(state.scope_heads.get(&id).copied()) != Some(revision) {
            return Err(PapError::Conflict);
        }
        state.scopes.insert(key, scope.clone());
        state.scope_heads.insert(id, revision);
        Ok(scope.clone())
    }

    fn get_scope_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<ScopeRevisionState>, PapError> {
        let state = self.lock()?;
        let Some(last) = state.scope_heads.get(id.as_str()).copied() else {
            return Ok(None);
        };
        let latest = state
            .scopes
            .iter()
            .filter(|((candidate, _), _)| candidate == id.as_str())
            .max_by_key(|((_, revision), _)| *revision)
            .map(|(_, scope)| scope.clone());
        Ok(Some(ScopeRevisionState {
            last_allocated_revision: Revision::new(last).map_err(|_| PapError::Persistence)?,
            latest,
        }))
    }

    fn get_scope(&self, id: &ResourceId, revision: Revision) -> Result<PreparedScope, PapError> {
        self.lock()?
            .scopes
            .get(&(id.as_str().to_owned(), revision.get()))
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError> {
        let items = self.lock()?.scopes.values().cloned().collect();
        Ok(page(items, limit, offset))
    }

    fn delete_scope_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedScope, PapError> {
        self.lock()?
            .scopes
            .remove(&(id.as_str().to_owned(), revision.get()))
            .ok_or(PapError::NotFound)
    }

    fn put_binding_revision(
        &self,
        spec: &PreparedBinding,
        initial_status: BindingStatus,
    ) -> Result<BindingView, PapError> {
        let mut state = self.lock()?;
        if initial_status != BindingStatus::PendingApply {
            return Err(PapError::Conflict);
        }

        let id = spec.binding_id.as_str().to_owned();
        let revision = spec.binding_revision.get();
        let key = (id.clone(), revision);
        if let Some(existing) = state.binding_specs.get(&key) {
            if existing != spec {
                return Err(PapError::Conflict);
            }
            let current = state
                .binding_statuses
                .get(&id)
                .copied()
                .ok_or(PapError::Persistence)?;
            if current != initial_status {
                return Err(PapError::Conflict);
            }
            return Ok(BindingView {
                spec: existing.clone(),
                status: current,
            });
        }

        if next_raw_revision(state.binding_heads.get(&id).copied()) != Some(revision) {
            return Err(PapError::Conflict);
        }
        state.binding_specs.insert(key, spec.clone());
        state.binding_heads.insert(id.clone(), revision);
        state.binding_statuses.insert(id, initial_status);
        Ok(BindingView {
            spec: spec.clone(),
            status: initial_status,
        })
    }

    fn update_binding_status(
        &self,
        id: &ResourceId,
        binding_revision: Revision,
        expected_status: BindingStatus,
        next_status: BindingStatus,
    ) -> Result<BindingStatus, PapError> {
        let mut state = self.lock()?;
        let id = id.as_str().to_owned();
        if state.binding_heads.get(&id).copied() != Some(binding_revision.get()) {
            return Err(PapError::Conflict);
        }
        let current = state.binding_statuses.get(&id).ok_or(PapError::NotFound)?;
        if *current != expected_status {
            return Err(PapError::Conflict);
        }
        expected_status
            .validate_successor(next_status)
            .map_err(|_| PapError::Conflict)?;
        state.binding_statuses.insert(id, next_status);
        Ok(next_status)
    }

    fn get_binding_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<BindingRevisionState>, PapError> {
        let state = self.lock()?;
        let Some(last) = state.binding_heads.get(id.as_str()).copied() else {
            return Ok(None);
        };
        let status = state
            .binding_statuses
            .get(id.as_str())
            .copied()
            .ok_or(PapError::Persistence)?;
        Ok(Some(BindingRevisionState {
            last_allocated_revision: Revision::new(last).map_err(|_| PapError::Persistence)?,
            status,
        }))
    }

    fn get_binding_spec(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedBinding, PapError> {
        self.lock()?
            .binding_specs
            .get(&(id.as_str().to_owned(), revision.get()))
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        let state = self.lock()?;
        binding_view(&state, id.as_str())
    }

    fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError> {
        let state = self.lock()?;
        let items = state
            .binding_statuses
            .keys()
            .map(|id| binding_view(&state, id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(page(items, limit, offset))
    }
}

fn binding_view(state: &FakeState, id: &str) -> Result<BindingView, PapError> {
    let status = state
        .binding_statuses
        .get(id)
        .copied()
        .ok_or(PapError::NotFound)?;
    let revision = state
        .binding_heads
        .get(id)
        .copied()
        .ok_or(PapError::Persistence)?;
    let spec = state
        .binding_specs
        .get(&(id.to_owned(), revision))
        .cloned()
        .ok_or(PapError::Persistence)?;
    Ok(BindingView { spec, status })
}

#[derive(Default)]
struct FixtureCompiler {
    calls: AtomicUsize,
}

impl PolicyCompiler for FixtureCompiler {
    fn lower(&self, template: &TemplateEnvelope) -> Result<PolicyEnvelope, ValidationError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let fixture: PreparedBinding = serde_json::from_str(COMPLETE_BINDING)
            .map_err(|error| ValidationError::new("fixture", error.to_string()))?;
        let mut policy = fixture.policy.canonical_policy;
        policy.policy_id = PolicyId::new(template.policy_id.as_str())
            .map_err(|error| ValidationError::new("policyId", error))?;
        policy.revision = template.revision;
        Ok(policy)
    }
}

type TestHandler = DaemonHandler;

fn handler() -> (TestHandler, Arc<FakeRepository>, Arc<FixtureCompiler>) {
    let repository = Arc::new(FakeRepository::default());
    let compiler = Arc::new(FixtureCompiler::default());
    let pap = PapService::new(Arc::clone(&repository), Arc::clone(&compiler));
    (DaemonHandler::new(pap), repository, compiler)
}

fn call(handler: &TestHandler, method: &str, params: Value) -> DaemonResponse {
    let mut request = json!({"method": method});
    request["params"] = params;
    let request: DaemonRequest = serde_json::from_value(request).unwrap();
    handler.handle(
        RequestId::new(format!("request-{method}")).unwrap(),
        PeerCredentials::new(1000, 100, 4242),
        request,
    )
}

fn result(response: DaemonResponse) -> Value {
    match response {
        DaemonResponse::Success(response) => response.result,
        DaemonResponse::Error(response) => panic!("request failed: {:?}", response.error),
    }
}

fn error(response: DaemonResponse) -> DaemonError {
    match response {
        DaemonResponse::Success(_) => panic!("request unexpectedly succeeded"),
        DaemonResponse::Error(response) => response.error,
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one serialized CRUD scenario makes the complete request-to-PAP path reviewable"
)]
fn serialized_policy_scope_and_binding_crud_reaches_the_concrete_pap_service() {
    let (handler, _, compiler) = handler();

    let created_policy = result(call(
        &handler,
        "policy.templates.create",
        json!({
            "policyName": "protect important files",
            "template": {
                "kind": "prevent_file_deletion",
                "files": ["/workspace/important"]
            }
        }),
    ));
    assert_eq!(created_policy["policy"]["revision"], 1);
    assert!(created_policy.get("disposition").is_none());
    let policy_id = created_policy["policy"]["policyId"]
        .as_str()
        .unwrap()
        .to_owned();

    let updated_policy = result(call(
        &handler,
        "policy.templates.update",
        json!({
            "policyId": policy_id,
            "policyName": "protect more files",
            "template": {
                "kind": "prevent_file_deletion",
                "files": ["/workspace/more"]
            }
        }),
    ));
    assert_eq!(updated_policy["policy"]["revision"], 2);
    assert_eq!(compiler.calls.load(Ordering::Relaxed), 2);

    let fetched_policy = result(call(
        &handler,
        "policy.templates.get",
        json!({"id": policy_id, "revision": 1}),
    ));
    assert_eq!(fetched_policy["policy"]["revision"], 1);

    let listed_policies = result(call(&handler, "policy.templates.list", json!({})));
    assert_eq!(listed_policies["total"], 2);
    assert_eq!(listed_policies["items"].as_array().unwrap().len(), 2);

    let deleted_policy = result(call(
        &handler,
        "policy.templates.delete",
        json!({"id": policy_id, "revision": 2}),
    ));
    assert_eq!(deleted_policy["policy"]["revision"], 2);
    assert!(deleted_policy.get("disposition").is_none());

    let created_scope = result(call(
        &handler,
        "policy.scopes.create",
        json!({"selector": {"kind": "pid", "pid": 4242}}),
    ));
    assert_eq!(created_scope["scope"]["revision"], 1);
    assert!(created_scope.get("disposition").is_none());
    let scope_id = created_scope["scope"]["scopeId"]
        .as_str()
        .unwrap()
        .to_owned();

    let updated_scope = result(call(
        &handler,
        "policy.scopes.update",
        json!({
            "scopeId": scope_id,
            "selector": {"kind": "cgroup_id", "cgroupId": 99}
        }),
    ));
    assert_eq!(updated_scope["scope"]["revision"], 2);

    let fetched_scope = result(call(
        &handler,
        "policy.scopes.get",
        json!({"id": scope_id, "revision": 1}),
    ));
    assert_eq!(fetched_scope["scope"]["selector"]["pid"], 4242);

    let listed_scopes = result(call(
        &handler,
        "policy.scopes.list",
        json!({"limit": 100, "offset": 0}),
    ));
    assert_eq!(listed_scopes["total"], 2);

    let created_binding = result(call(
        &handler,
        "policy.bindings.create",
        json!({
            "policyId": policy_id,
            "policyRevision": 1,
            "scopeId": scope_id,
            "scopeRevision": 1
        }),
    ));
    assert!(created_binding.get("disposition").is_none());
    assert_eq!(created_binding["binding"]["status"], "PENDING_APPLY");
    assert_eq!(created_binding["binding"]["spec"]["bindingRevision"], 1);
    let binding_id = created_binding["binding"]["spec"]["bindingId"]
        .as_str()
        .unwrap()
        .to_owned();

    let updated_binding = result(call(
        &handler,
        "policy.bindings.update",
        json!({
            "bindingId": binding_id,
            "policyId": policy_id,
            "policyRevision": 1,
            "scopeId": scope_id,
            "scopeRevision": 2
        }),
    ));
    assert_eq!(updated_binding["binding"]["spec"]["bindingRevision"], 2);
    assert_eq!(updated_binding["binding"]["spec"]["scope"]["revision"], 2);
    assert_eq!(updated_binding["binding"]["status"], "PENDING_APPLY");

    let fetched_binding = result(call(
        &handler,
        "policy.bindings.get",
        json!({"id": binding_id}),
    ));
    assert_eq!(fetched_binding["binding"], updated_binding["binding"]);

    let listed_bindings = result(call(&handler, "policy.bindings.list", json!({})));
    assert_eq!(listed_bindings["total"], 1);
    assert_eq!(listed_bindings["items"][0], updated_binding["binding"]);

    let deleted_binding = result(call(
        &handler,
        "policy.bindings.delete",
        json!({"id": binding_id}),
    ));
    assert_eq!(deleted_binding["binding"]["status"], "PENDING_DELETE");
    assert_eq!(deleted_binding["binding"]["spec"]["bindingRevision"], 2);
    assert!(deleted_binding.get("disposition").is_none());

    let deleted_scope = result(call(
        &handler,
        "policy.scopes.delete",
        json!({"id": scope_id, "revision": 2}),
    ));
    assert_eq!(deleted_scope["scope"]["revision"], 2);
    assert!(deleted_scope.get("disposition").is_none());
}

#[test]
fn admission_and_application_failures_use_structured_errors() {
    let (handler, repository, _) = handler();

    let unknown = error(call(&handler, "policy.unknown", json!({})));
    assert_eq!(unknown.code.as_str(), "unknown_method");

    let legacy_put = error(call(
        &handler,
        "policy.templates.put",
        json!({
            "policyName": "must not create",
            "template": {
                "kind": "prevent_file_deletion",
                "files": ["/workspace/important"]
            }
        }),
    ));
    assert_eq!(legacy_put.code.as_str(), "unknown_method");

    let missing_update_id = error(call(
        &handler,
        "policy.templates.update",
        json!({
            "policyName": "must not create",
            "template": {
                "kind": "prevent_file_deletion",
                "files": ["/workspace/important"]
            }
        }),
    ));
    assert_eq!(missing_update_id.code.as_str(), "invalid_request");

    let bad_request = error(call(
        &handler,
        "policy.templates.get",
        json!({"id": "policy-1", "revision": 0}),
    ));
    assert_eq!(bad_request.code.as_str(), "invalid_request");

    let not_found = error(call(
        &handler,
        "policy.templates.get",
        json!({"id": "missing-policy", "revision": 1}),
    ));
    assert_eq!(not_found.code.as_str(), "not_found");

    repository.set_fail_persistence(true);
    let persistence = error(call(&handler, "policy.templates.list", json!({})));
    assert_eq!(persistence.code.as_str(), "internal");
}

fn next_raw_revision(current: Option<u32>) -> Option<u32> {
    match current {
        Some(revision) => revision.checked_add(1),
        None => Some(1),
    }
}

fn page<T>(items: Vec<T>, limit: u32, offset: u32) -> Page<T> {
    let total = u64::try_from(items.len()).expect("test item count fits u64");
    let offset = usize::try_from(offset).expect("u32 offset fits usize");
    let limit = usize::try_from(limit).expect("u32 limit fits usize");
    Page {
        items: items.into_iter().skip(offset).take(limit).collect(),
        total,
    }
}
