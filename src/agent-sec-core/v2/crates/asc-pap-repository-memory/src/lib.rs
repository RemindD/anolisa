//! **TEMPORARY PROCESS-LOCAL IMPLEMENTATION -- NO DURABLE PERSISTENCE.**
//!
//! This process-local adapter exists only to make the PAP daemon request path
//! runnable before the durable Repository work package lands. Its internal
//! implementation is replaceable and must not be treated as a durable storage
//! design. Reconciliation transactions are reviewed/tested as logical atomicity.
//! All state is lost when the daemon restarts.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

mod binding_state;

use asc_foundation_types::{ResourceId, Revision};
use asc_pap::{Page, PapError, PapRepository, PolicyRevisionState};
use asc_policy_types::Validate;
use asc_policy_types::binding::{BindingScope, BindingStatus, BindingView, PreparedBinding};
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::process_discovery::ProcessIdentity;
use asc_policy_types::scope::{PreparedScope, ScopeStatus};

/// Process-local PAP Repository used until durable persistence is integrated.
///
/// This adapter implements the current-record Repository contract but loses all
/// state on daemon restart. It is an explicitly replaceable composition-root
/// dependency, not production persistence evidence.
#[derive(Debug, Default)]
pub struct ProcessLocalPapRepository {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    policy_heads: BTreeMap<String, Revision>,
    policies: BTreeMap<String, PreparedPolicy>,
    // Lifetime tombstones preserve deletion idempotency; grow with all created Scopes.
    scope_ids: BTreeSet<String>,
    // Cleanup barriers are retained only until their Scope is finalized.
    stopped_scopes: BTreeSet<String>,
    scopes: BTreeMap<String, PreparedScope>,
    bindings: BTreeMap<String, BindingView>,
    binding_states: BTreeMap<String, BindingStateData>,
}

#[derive(Debug, Default, Clone)]
struct BindingStateData {
    deployments: Vec<asc_policy_repository::Deployment>,
    // Latest atomic write receipt, independent of reconciliation decisions.
    last_write: Option<asc_policy_repository::BindingStateWrite>,
}

impl ProcessLocalPapRepository {
    fn lock(&self) -> Result<MutexGuard<'_, State>, PapError> {
        self.state.lock().map_err(|_| PapError::Persistence)
    }
}

impl PapRepository for ProcessLocalPapRepository {
    fn put_policy(&self, policy: &PreparedPolicy) -> Result<PreparedPolicy, PapError> {
        if encoded_size(policy)? > MAX_RECORD_BYTES {
            return Err(PapError::InvalidPolicy(
                asc_policy_types::error::ValidationError::new(
                    "template",
                    "serialized policy exceeds 1 MiB",
                ),
            ));
        }
        let mut state = self.lock()?;
        let id = policy.policy_id.as_str().to_owned();
        if let Some(existing) = state.policies.get(&id)
            && existing.revision == policy.revision
        {
            return if existing == policy {
                Ok(existing.clone())
            } else {
                Err(PapError::Conflict)
            };
        }
        if !is_next_revision(state.policy_heads.get(&id).copied(), policy.revision) {
            return Err(PapError::Conflict);
        }
        state.policies.insert(id.clone(), policy.clone());
        state.policy_heads.insert(id, policy.revision);
        Ok(policy.clone())
    }

    fn get_policy_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<PolicyRevisionState>, PapError> {
        let state = self.lock()?;
        Ok(state
            .policy_heads
            .get(id.as_str())
            .copied()
            .map(|last_allocated_revision| PolicyRevisionState {
                last_allocated_revision,
                current: state.policies.get(id.as_str()).cloned(),
            }))
    }

    fn get_policy(&self, id: &ResourceId, revision: Revision) -> Result<PreparedPolicy, PapError> {
        self.lock()?
            .policies
            .get(id.as_str())
            .filter(|policy| policy.revision == revision)
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError> {
        let state = self.lock()?;
        bounded_page(state.policies.values(), limit, offset)
    }

    fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        let mut state = self.lock()?;
        if state
            .policies
            .get(id.as_str())
            .is_none_or(|policy| policy.revision != revision)
        {
            return Err(PapError::NotFound);
        }
        state
            .policies
            .remove(id.as_str())
            .ok_or(PapError::Persistence)
    }

    fn put_scope(&self, scope: &PreparedScope) -> Result<PreparedScope, PapError> {
        scope.validate().map_err(PapError::InvalidScope)?;
        if encoded_size(scope)? > MAX_RECORD_BYTES {
            return Err(PapError::InvalidScope(
                asc_policy_types::error::ValidationError::new(
                    "policyTemplates",
                    "serialized assignment exceeds 1 MiB",
                ),
            ));
        }
        if scope.status != ScopeStatus::Active {
            return Err(PapError::Conflict);
        }
        let mut state = self.lock()?;
        let id = scope.scope_id.to_string();
        if state.scope_ids.contains(&id) {
            return Err(PapError::Conflict);
        }
        // Snapshot verification and insertion share the policy mutation lock.
        for policy in &scope.policy_snapshots {
            if state.policies.get(policy.policy_id.as_str()) != Some(policy) {
                return Err(PapError::ReferencedPolicyRevisionNotFound);
            }
        }
        state.scope_ids.insert(id.clone());
        state.scopes.insert(id, scope.clone());
        Ok(scope.clone())
    }

    fn get_scope(&self, id: &ResourceId) -> Result<PreparedScope, PapError> {
        self.lock()?
            .scopes
            .get(id.as_str())
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError> {
        bounded_page(self.lock()?.scopes.values(), limit, offset)
    }

    fn begin_scope_delete(&self, id: &ResourceId) -> Result<Option<PreparedScope>, PapError> {
        let mut state = self.lock()?;
        if let Some(scope) = state.scopes.get_mut(id.as_str()) {
            scope.status = ScopeStatus::Deleting;
            return Ok(Some(scope.clone()));
        }
        if state.scope_ids.contains(id.as_str()) {
            Ok(None)
        } else {
            Err(PapError::NotFound)
        }
    }

    fn finish_scope_discovery(&self, id: &ResourceId) -> Result<Vec<BindingView>, PapError> {
        let mut state = self.lock()?;
        let Some(scope) = state.scopes.get(id.as_str()) else {
            return Ok(Vec::new());
        };
        if scope.status != ScopeStatus::Deleting {
            return Err(PapError::Conflict);
        }
        state.stopped_scopes.insert(id.to_string());
        let mut changed = Vec::new();
        for binding in state
            .bindings
            .values_mut()
            .filter(|b| b.spec.scope.scope_id == *id)
        {
            if request_retirement(binding) {
                changed.push(binding.clone());
            }
        }
        for binding in &changed {
            state
                .binding_states
                .entry(binding.spec.binding_id.to_string())
                .or_default()
                .last_write = None;
        }
        finalize_scope(&mut state, id.as_str());
        Ok(changed)
    }

    fn sync_scope_instances(
        &self,
        id: &ResourceId,
        instances: &[ProcessIdentity],
    ) -> Result<Vec<BindingView>, PapError> {
        let mut state = self.lock()?;
        let scope = state
            .scopes
            .get(id.as_str())
            .ok_or(PapError::NotFound)?
            .clone();
        if scope.status != ScopeStatus::Active {
            return Err(PapError::OperationInProgress);
        }
        let mut changed = Vec::new();
        // Validate the complete batch before modifying any existing intent.
        let mut candidates = Vec::new();
        for instance in instances {
            for policy in &scope.policy_snapshots {
                if state.bindings.values().any(|b| {
                    b.spec.scope.scope_id == *id
                        && b.spec.scope.process == *instance
                        && b.spec.policy.policy_id == policy.policy_id
                }) || candidates.iter().any(|b: &BindingView| {
                    b.spec.scope.process == *instance && b.spec.policy.policy_id == policy.policy_id
                }) {
                    continue;
                }
                let binding = BindingView {
                    spec: PreparedBinding {
                        binding_id: ResourceId::new(uuid::Uuid::new_v4().to_string())
                            .map_err(|_| PapError::Persistence)?,
                        binding_revision: Revision::new(1).map_err(|_| PapError::Persistence)?,
                        policy: policy.clone(),
                        scope: BindingScope {
                            scope_id: id.clone(),
                            selector: scope.selector.clone(),
                            process: instance.clone(),
                        },
                    },
                    status: BindingStatus::PendingApply.into(),
                };
                binding.validate().map_err(PapError::InvalidBinding)?;
                candidates.push(binding);
            }
        }
        for binding in state
            .bindings
            .values_mut()
            .filter(|b| b.spec.scope.scope_id == *id)
        {
            if !instances.contains(&binding.spec.scope.process) && request_retirement(binding) {
                changed.push(binding.clone());
            }
        }
        for binding in candidates {
            state
                .bindings
                .insert(binding.spec.binding_id.to_string(), binding.clone());
            changed.push(binding);
        }
        for binding in &changed {
            state
                .binding_states
                .entry(binding.spec.binding_id.to_string())
                .or_default()
                .last_write = None;
        }
        Ok(changed)
    }

    fn retry_scope(&self, id: &ResourceId) -> Result<Vec<BindingView>, PapError> {
        let mut state = self.lock()?;
        if !state.scopes.contains_key(id.as_str()) {
            return Err(PapError::NotFound);
        }
        let mut changed = Vec::new();
        for binding in state
            .bindings
            .values_mut()
            .filter(|b| b.spec.scope.scope_id == *id)
        {
            let phase = match binding.status.phase {
                BindingStatus::ApplyFailed => BindingStatus::PendingApply,
                BindingStatus::DeleteFailed => BindingStatus::PendingDelete,
                _ => continue,
            };
            binding.status = phase.into();
            changed.push(binding.clone());
        }
        for binding in &changed {
            state
                .binding_states
                .entry(binding.spec.binding_id.to_string())
                .or_default()
                .last_write = None;
        }
        Ok(changed)
    }

    fn update_binding(
        &self,
        expected: Option<&BindingView>,
        binding: &BindingView,
    ) -> Result<BindingView, PapError> {
        if !matches!(
            binding.status.phase,
            BindingStatus::PendingApply | BindingStatus::PendingDelete
        ) {
            return Err(PapError::Conflict);
        }
        let mut state = self.lock()?;
        let id = binding.spec.binding_id.as_str().to_owned();
        let current = state.bindings.get(&id);
        if expected.is_some() && current.is_none() {
            return Err(PapError::NotFound);
        }
        if current.map(|b| (&b.spec, &b.status)) != expected.map(|b| (&b.spec, &b.status)) {
            return Err(PapError::Conflict);
        }
        if binding.status == BindingStatus::PendingApply {
            let owner = state
                .scopes
                .get(binding.spec.scope.scope_id.as_str())
                .ok_or(PapError::NotFound)?;
            if owner.status != ScopeStatus::Active
                || current.is_some_and(|b| {
                    state
                        .scopes
                        .get(b.spec.scope.scope_id.as_str())
                        .is_none_or(|s| s.status != ScopeStatus::Active)
                })
            {
                return Err(PapError::OperationInProgress);
            }
            if current.is_none()
                && (owner.selector != binding.spec.scope.selector
                    || !owner.policy_snapshots.contains(&binding.spec.policy))
            {
                return Err(PapError::Conflict);
            }
        }
        if let Some(current) = current {
            if current.spec == binding.spec && current.status == binding.status {
                return Ok(current.clone());
            }
            let same_spec = current.spec.policy == binding.spec.policy
                && current.spec.scope == binding.spec.scope;
            let permitted = if binding.status == BindingStatus::PendingDelete {
                same_spec && current.status.request_delete() == binding.status
            } else if same_spec {
                current.status.request_apply().ok() == Some(binding.status.phase)
            } else {
                current.status.request_apply().is_ok() && current.status != BindingStatus::Applying
            };
            if !permitted {
                return Err(PapError::OperationInProgress);
            }
            let valid_revision = if same_spec {
                current.spec.binding_revision == binding.spec.binding_revision
            } else {
                is_next_revision(
                    Some(current.spec.binding_revision),
                    binding.spec.binding_revision,
                )
            };
            if !valid_revision {
                return Err(PapError::Conflict);
            }
        } else if binding.spec.binding_revision.get() != 1
            || binding.status != BindingStatus::PendingApply
        {
            return Err(PapError::Conflict);
        }
        state.bindings.insert(id, binding.clone());
        Ok(binding.clone())
    }

    fn fail_pending_binding(
        &self,
        expected: &BindingView,
        reason: asc_pap::EnqueueError,
    ) -> Result<bool, PapError> {
        let failed = match expected.status.phase {
            BindingStatus::PendingApply => BindingStatus::ApplyFailed,
            BindingStatus::PendingDelete => BindingStatus::DeleteFailed,
            _ => return Err(PapError::Conflict),
        };
        let mut state = self.lock()?;
        let id = expected.spec.binding_id.as_str();
        let Some(current) = state.bindings.get_mut(id) else {
            return Ok(false);
        };
        if current.spec.binding_revision != expected.spec.binding_revision
            || current.status != expected.status
        {
            return Ok(false);
        }
        current.status = failed.into();
        current.status.error = Some(reason.failure());
        let data = state.binding_states.entry(id.to_owned()).or_default();

        // Invalidate an earlier worker write replay after this lifecycle change.
        data.last_write = None;
        Ok(true)
    }

    fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        let state = self.lock()?;
        let binding = state.bindings.get(id.as_str()).ok_or(PapError::NotFound)?;
        let mut view = binding.clone();
        project_binding_error(&state, &mut view);
        Ok(view)
    }

    fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError> {
        let state = self.lock()?;
        let mut result = bounded_page(state.bindings.values(), limit, offset)?;
        for binding in &mut result.items {
            project_binding_error(&state, binding);
        }
        Ok(result)
    }
}

fn request_retirement(binding: &mut BindingView) -> bool {
    if matches!(
        binding.status.phase,
        BindingStatus::PendingDelete
            | BindingStatus::Deleting
            | BindingStatus::DeleteFailed
            | BindingStatus::Deleted
    ) {
        return false;
    }
    binding.status = BindingStatus::PendingDelete.into();
    true
}

fn finalize_scope(state: &mut State, id: &str) {
    if state.stopped_scopes.contains(id)
        && state
            .scopes
            .get(id)
            .is_some_and(|s| s.status == ScopeStatus::Deleting)
        && !state
            .bindings
            .values()
            .any(|b| b.spec.scope.scope_id.as_str() == id)
    {
        state.scopes.remove(id);
        state.stopped_scopes.remove(id);
    }
}

fn project_binding_error(_state: &State, view: &mut BindingView) {
    view.status.error = view
        .status
        .error
        .as_ref()
        .map(|error| asc_policy_types::target::Failure::new(error.kind, &error.code));
}

fn is_next_revision(current: Option<Revision>, candidate: Revision) -> bool {
    match current {
        None => candidate.get() == 1,
        Some(current) => current.checked_next() == Ok(candidate),
    }
}

// Leave room for the result envelope within the default 4 MiB response frame.
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_PAGE_BYTES: usize = 3 * 1024 * 1024;

fn encoded_size(value: &impl serde::Serialize) -> Result<usize, PapError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| PapError::Persistence)
}

fn bounded_page<'a, T: Clone + serde::Serialize + 'a>(
    items: impl ExactSizeIterator<Item = &'a T>,
    limit: u32,
    offset: u32,
) -> Result<Page<T>, PapError> {
    let total = items.len() as u64;
    let mut selected = Vec::new();
    let mut bytes = 0;
    for item in items.skip(offset as usize).take(limit as usize) {
        let size = encoded_size(item)? + 1;
        if bytes + size > MAX_PAGE_BYTES {
            if selected.is_empty() {
                return Err(PapError::Persistence);
            }
            break;
        }
        bytes += size;
        selected.push(item.clone());
    }
    Ok(Page {
        items: selected,
        total,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use asc_pap::PapService;
    use asc_policy_engine::PolicyTemplateCompiler;
    use asc_policy_types::authoring::PolicyTemplate;
    use asc_policy_types::binding::BindingStatus;
    use asc_policy_types::scope::ScopeSelector;

    use super::*;

    #[derive(Debug, serde::Serialize)]
    struct CloneTracked<'a> {
        value: u32,
        #[serde(skip)]
        clones: &'a AtomicUsize,
    }

    impl Clone for CloneTracked<'_> {
        fn clone(&self) -> Self {
            self.clones.fetch_add(1, Ordering::Relaxed);
            Self {
                value: self.value,
                clones: self.clones,
            }
        }
    }

    #[test]
    fn pagination_clones_only_the_selected_records() {
        let clones = AtomicUsize::new(0);
        let records: Vec<_> = (0..5)
            .map(|value| CloneTracked {
                value,
                clones: &clones,
            })
            .collect();

        let selected = bounded_page(records.iter(), 2, 2).unwrap();

        assert_eq!(selected.total, 5);
        assert_eq!(
            selected
                .items
                .iter()
                .map(|record| record.value)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(clones.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn page_byte_budget_preserves_count_and_allows_progress() {
        let records = vec!["x".repeat(MAX_RECORD_BYTES); 4];
        let first = bounded_page(records.iter(), 100, 0).unwrap();
        assert_eq!(first.total, 4);
        assert_eq!(first.items.len(), 2);
        assert!(encoded_size(&first).unwrap() < MAX_PAGE_BYTES);
        let second = bounded_page(records.iter(), 100, 2).unwrap();
        assert_eq!(second.items.len(), 2);
    }

    #[test]
    fn oversized_policy_and_assignment_are_rejected_before_commit() {
        let repository = Arc::new(ProcessLocalPapRepository::default());
        let pap = PapService::new(repository.clone(), Arc::new(PolicyTemplateCompiler));
        let huge = PolicyTemplate::PreventFileDeletion {
            files: (0..200)
                .map(|n| format!("/{n}{}", "x".repeat(3000)))
                .collect(),
        };
        assert!(matches!(
            pap.create_policy("large", &huge),
            Err(PapError::InvalidPolicy(_))
        ));
        assert_eq!(pap.list_policies(10, 0).unwrap().total, 0);
        let medium = PolicyTemplate::PreventFileDeletion {
            files: (0..100)
                .map(|n| format!("/{n}{}", "x".repeat(3000)))
                .collect(),
        };
        let a = pap.create_policy("a", &medium).unwrap();
        let b = pap.create_policy("b", &medium).unwrap();
        let scope = PreparedScope {
            scope_id: ResourceId::new("oversized").unwrap(),
            selector: ScopeSelector::Pid { pid: 42 },
            policy_snapshots: vec![a, b],
            status: ScopeStatus::Active,
        };
        assert!(matches!(
            repository.put_scope(&scope),
            Err(PapError::InvalidScope(_))
        ));
        assert_eq!(pap.list_scopes(10, 0).unwrap().total, 0);
    }

    #[test]
    fn repository_runs_the_current_pap_request_slice_without_a_reconciler() {
        let repository = Arc::new(ProcessLocalPapRepository::default());
        let pap = PapService::new(Arc::clone(&repository), Arc::new(PolicyTemplateCompiler));
        let policy = pap
            .create_policy(
                "protect files",
                &PolicyTemplate::PreventFileDeletion {
                    files: vec!["/workspace/important".to_owned()],
                },
            )
            .unwrap();
        let scope = PreparedScope {
            scope_id: ResourceId::new("scope").unwrap(),
            selector: ScopeSelector::Pid { pid: 4242 },
            policy_snapshots: vec![policy],
            status: ScopeStatus::Active,
        };
        repository.put_scope(&scope).unwrap();
        let binding = repository
            .sync_scope_instances(
                &scope.scope_id,
                &[ProcessIdentity {
                    boot_id: "boot".into(),
                    pid_namespace: "pid:[42]".into(),
                    pid: 4242,
                    start_time: 99,
                }],
            )
            .unwrap()
            .remove(0);

        assert_eq!(binding.status, BindingStatus::PendingApply);
        assert_eq!(pap.list_policies(10, 0).unwrap().total, 1);
        assert_eq!(pap.list_scopes(10, 0).unwrap().total, 1);
        assert_eq!(pap.list_bindings(10, 0).unwrap().items, [binding]);
        assert_eq!(
            ProcessLocalPapRepository::default()
                .list_policies(10, 0)
                .unwrap()
                .total,
            0,
            "a new process-local Repository intentionally has no prior state"
        );
    }
}
