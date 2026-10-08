use std::sync::{Arc, Mutex};

use asc_foundation_types::{ResourceId, Revision};
use asc_pap::{Page, PapError, PapRepository, PapService, PolicyCompiler, PolicyRevisionState};
use asc_pap_repository_memory::ProcessLocalPapRepository;
use asc_policy_repository::{
    BindingStateRepository, BindingStateSnapshot, BindingStateWrite, WriteResult,
};
use asc_policy_types::authoring::{PolicyTemplate, TemplateEnvelope};
use asc_policy_types::binding::{BindingStatus, BindingView, PreparedBinding};
use asc_policy_types::error::ValidationError;
use asc_policy_types::identifiers::PolicyId;
use asc_policy_types::policy::{PolicyEnvelope, PreparedPolicy};
use asc_policy_types::scope::{PreparedScope, ScopeSelector};

const COMPLETE_BINDING: &str =
    include_str!("../../asc-policy-types/tests/fixtures/prepared-binding.json");

#[derive(Default)]
struct FakeRepository {
    inner: ProcessLocalPapRepository,
    failure_write_mode: std::sync::atomic::AtomicUsize,
    policy_read_override: Mutex<Option<PolicyRevisionState>>,
    scope_cleanup_failure: std::sync::atomic::AtomicUsize,
}

impl FakeRepository {
    fn binding_state(&self, id: &ResourceId) -> BindingStateSnapshot {
        self.inner.get_binding_state(id).unwrap().unwrap()
    }

    // Set up worker-owned state through the same aggregate CAS used by the reconciler.
    fn transition(&self, id: &ResourceId, status: BindingStatus) {
        let current = self.binding_state(id);
        current
            .binding
            .status
            .phase
            .validate_successor(status)
            .unwrap();
        let mut next = current.clone();
        next.binding.status.phase = status;
        assert_eq!(
            self.inner
                .compare_exchange_binding_state(&current, &BindingStateWrite::new(next)),
            Ok(WriteResult::Applied)
        );
    }
}

impl PapRepository for FakeRepository {
    fn put_policy(&self, policy: &PreparedPolicy) -> Result<PreparedPolicy, PapError> {
        self.inner.put_policy(policy)
    }

    fn get_policy_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<PolicyRevisionState>, PapError> {
        if let Some(result) = self.policy_read_override.lock().unwrap().take() {
            return Ok(Some(result));
        }
        self.inner.get_policy_revision_state(id)
    }

    fn get_policy(&self, id: &ResourceId, revision: Revision) -> Result<PreparedPolicy, PapError> {
        self.inner.get_policy(id, revision)
    }

    fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError> {
        self.inner.list_policies(limit, offset)
    }

    fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        self.inner.delete_policy_revision(id, revision)
    }

    fn put_scope(&self, scope: &PreparedScope) -> Result<PreparedScope, PapError> {
        self.inner.put_scope(scope)
    }

    fn get_scope(&self, id: &ResourceId) -> Result<PreparedScope, PapError> {
        self.inner.get_scope(id)
    }

    fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError> {
        self.inner.list_scopes(limit, offset)
    }

    fn begin_scope_delete(&self, id: &ResourceId) -> Result<Option<PreparedScope>, PapError> {
        if self
            .scope_cleanup_failure
            .load(std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            return Err(PapError::Persistence);
        }
        self.inner.begin_scope_delete(id)
    }
    fn finish_scope_discovery(&self, id: &ResourceId) -> Result<Vec<BindingView>, PapError> {
        if self
            .scope_cleanup_failure
            .load(std::sync::atomic::Ordering::SeqCst)
            == 2
        {
            return Err(PapError::Persistence);
        }
        self.inner.finish_scope_discovery(id)
    }
    fn sync_scope_instances(
        &self,
        id: &ResourceId,
        instances: &[asc_policy_types::process_discovery::ProcessIdentity],
    ) -> Result<Vec<BindingView>, PapError> {
        self.inner.sync_scope_instances(id, instances)
    }
    fn retry_scope(&self, id: &ResourceId) -> Result<Vec<BindingView>, PapError> {
        self.inner.retry_scope(id)
    }
    fn update_binding(
        &self,
        expected: Option<&BindingView>,
        binding: &BindingView,
    ) -> Result<BindingView, PapError> {
        self.inner.update_binding(expected, binding)
    }

    fn fail_pending_binding(
        &self,
        expected: &BindingView,
        reason: asc_pap::EnqueueError,
    ) -> Result<bool, PapError> {
        match self
            .failure_write_mode
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            1 => return Err(PapError::Persistence),
            2 => return Ok(false),
            3 => {
                self.failure_write_mode
                    .store(4, std::sync::atomic::Ordering::SeqCst);
                return Ok(false);
            }
            _ => {}
        }
        self.inner.fail_pending_binding(expected, reason)
    }

    fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        if self
            .failure_write_mode
            .load(std::sync::atomic::Ordering::SeqCst)
            == 4
        {
            return Err(PapError::Persistence);
        }
        self.inner.get_binding(id)
    }

    fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError> {
        self.inner.list_bindings(limit, offset)
    }
}

struct FixtureCompiler {
    mismatch_identity: bool,
}

impl PolicyCompiler for FixtureCompiler {
    fn lower(&self, template: &TemplateEnvelope) -> Result<PolicyEnvelope, ValidationError> {
        let fixture: PreparedBinding = serde_json::from_str(COMPLETE_BINDING)
            .map_err(|error| ValidationError::new("fixture", error.to_string()))?;
        let mut policy = fixture.policy.canonical_policy;
        policy.policy_id = if self.mismatch_identity {
            PolicyId::new("compiler-mismatch")
                .map_err(|error| ValidationError::new("policyId", error))?
        } else {
            template.policy_id.clone()
        };
        policy.revision = template.revision;
        Ok(policy)
    }
}

type Service = PapService<FakeRepository, FixtureCompiler>;

fn service() -> (Service, Arc<FakeRepository>) {
    let repository = Arc::new(FakeRepository::default());
    let compiler = Arc::new(FixtureCompiler {
        mismatch_identity: false,
    });
    (
        PapService::new(Arc::clone(&repository), compiler),
        repository,
    )
}

fn policy_template(path: &str) -> PolicyTemplate {
    PolicyTemplate::PreventFileDeletion {
        files: vec![path.to_owned()],
    }
}

#[test]
fn policy_crud_keeps_only_the_current_record_and_never_reuses_revisions() {
    let (pap, repository) = service();
    let first = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap();
    assert_eq!(first.revision.get(), 1);
    assert_eq!(
        pap.update_policy(
            &first.policy_id,
            "protect files",
            &policy_template("/workspace/a")
        )
        .unwrap(),
        first
    );

    let second = pap
        .update_policy(
            &first.policy_id,
            "protect more files",
            &policy_template("/workspace/b"),
        )
        .unwrap();
    assert_eq!(second.revision.get(), 2);
    assert_eq!(
        pap.list_policies(100, 0).unwrap().items,
        vec![second.clone()]
    );
    assert_eq!(
        pap.get_policy(&first.policy_id, first.revision),
        Err(PapError::NotFound)
    );
    assert_eq!(
        pap.delete_policy_revision(&first.policy_id, second.revision)
            .unwrap(),
        second
    );
    assert_eq!(pap.list_policies(100, 0).unwrap().total, 0);

    let third = pap
        .update_policy(
            &first.policy_id,
            "protect newest files",
            &policy_template("/workspace/c"),
        )
        .unwrap();
    assert_eq!(third.revision.get(), 3);
    assert_eq!(
        pap.get_policy(&first.policy_id, second.revision),
        Err(PapError::NotFound)
    );
    assert_eq!(pap.list_policies(100, 0).unwrap().items, vec![third]);
    assert_eq!(repository.list_policies(100, 0).unwrap().total, 1);
    assert_eq!(
        repository
            .get_policy_revision_state(&first.policy_id)
            .unwrap()
            .unwrap()
            .last_allocated_revision
            .get(),
        3
    );

    let missing = ResourceId::new("missing-policy").unwrap();
    assert_eq!(
        pap.update_policy(&missing, "missing", &policy_template("/workspace/missing")),
        Err(PapError::NotFound)
    );
}

#[test]
fn compiler_output_identity_is_checked_before_storage() {
    let repository = Arc::new(FakeRepository::default());
    let compiler = Arc::new(FixtureCompiler {
        mismatch_identity: true,
    });
    let pap = PapService::new(repository, compiler);

    let error = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap_err();
    let PapError::InvalidPolicy(error) = error else {
        panic!("expected invalid compiler output");
    };
    assert_eq!(error.path, "canonicalPolicy.policyId");
}

#[test]
fn revision_exhaustion_and_pagination_bounds_are_explicit() {
    let (pap, repository) = service();
    let first = pap
        .create_policy("protect files", &policy_template("/workspace/a"))
        .unwrap();
    let maximum = Revision::new(u32::MAX).unwrap();
    let mut exhausted = first.clone();
    exhausted.revision = maximum;
    exhausted.canonical_policy.revision = maximum;
    *repository.policy_read_override.lock().unwrap() = Some(PolicyRevisionState {
        last_allocated_revision: maximum,
        current: Some(exhausted),
    });

    assert_eq!(
        pap.update_policy(
            &first.policy_id,
            "changed",
            &policy_template("/workspace/b"),
        ),
        Err(PapError::RevisionExhausted)
    );
    assert_eq!(pap.list_policies(0, 0), Err(PapError::InvalidPagination));
    assert_eq!(
        pap.list_policies(1_001, 0),
        Err(PapError::InvalidPagination)
    );
}

#[test]
fn scheduling_failure_write_error_does_not_claim_terminal_state() {
    struct Reject;
    impl asc_pap::BindingReconcileEnqueuer for Reject {
        fn check_ready(&self) -> Result<(), PapError> {
            Ok(())
        }
        fn enqueue(&self, _: &ResourceId) -> Result<(), asc_pap::EnqueueError> {
            Err(asc_pap::EnqueueError::Full)
        }
    }
    // Failed write, unchanged Pending after conflict, and failed conflict reread.
    for mode in [1, 2, 3] {
        let (pap, repo) = service();
        repo.failure_write_mode
            .store(mode, std::sync::atomic::Ordering::SeqCst);
        let pap = pap
            .with_reconcile_enqueuer(Arc::new(Reject))
            .with_scope_discovery(Arc::new(Discovery));
        let policy = pap
            .create_policy("test", &policy_template("/workspace/a"))
            .unwrap();
        let scope = pap
            .create_scope_assignment(
                &ScopeSelector::Pid { pid: 4242 },
                &[asc_policy_types::scope::PolicyReference {
                    policy_id: policy.policy_id.clone(),
                    policy_revision: policy.revision,
                }],
            )
            .unwrap();
        let process = serde_json::from_str::<PreparedBinding>(COMPLETE_BINDING)
            .unwrap()
            .scope
            .process;
        let error = asc_pap::ScopeBindingSink::sync_instances(&pap, &scope.scope_id, &[process])
            .unwrap_err();
        let PapError::SchedulingRejected { id, .. } = error else {
            panic!("expected scheduling rejection")
        };
        let state = repo.binding_state(&id);
        assert_eq!(state.binding.status.phase, BindingStatus::PendingApply);
        assert_eq!(state.binding.status.error, None);
    }
}

struct Discovery;
impl asc_pap::ScopeDiscovery for Discovery {
    fn start(&self, _: &PreparedScope) -> Result<(), PapError> {
        Ok(())
    }
    fn stop(&self, _: &ResourceId) -> Result<(), PapError> {
        Ok(())
    }
}

fn assignment(pap: &Service, policy: &PreparedPolicy) -> PreparedScope {
    pap.create_scope_assignment(
        &ScopeSelector::Pid { pid: 4242 },
        &[asc_policy_types::scope::PolicyReference {
            policy_id: policy.policy_id.clone(),
            policy_revision: policy.revision,
        }],
    )
    .unwrap()
}

#[test]
fn assignment_snapshots_survive_policy_update_delete_and_later_discovery() {
    use asc_pap::ScopeBindingSink;
    let (pap, repo) = service();
    let pap = pap.with_scope_discovery(Arc::new(Discovery));
    let original = pap.create_policy("old", &policy_template("/a")).unwrap();
    let scope = assignment(&pap, &original);
    let updated = pap
        .update_policy(&original.policy_id, "new", &policy_template("/b"))
        .unwrap();
    assert_eq!(updated.revision.get(), 2);
    assert!(matches!(
        pap.create_scope_assignment(
            &scope.selector,
            &[asc_policy_types::scope::PolicyReference {
                policy_id: original.policy_id.clone(),
                policy_revision: original.revision
            }]
        ),
        Err(PapError::ReferencedPolicyRevisionNotFound)
    ));
    pap.delete_policy_revision(&updated.policy_id, updated.revision)
        .unwrap();
    assert_eq!(pap.get_scope(&scope.scope_id).unwrap(), scope);
    let instance = serde_json::from_str::<PreparedBinding>(COMPLETE_BINDING)
        .unwrap()
        .scope
        .process;
    pap.sync_instances(&scope.scope_id, std::slice::from_ref(&instance))
        .unwrap();
    pap.sync_instances(&scope.scope_id, std::slice::from_ref(&instance))
        .unwrap();
    let bindings = pap.list_bindings(10, 0).unwrap();
    assert_eq!(bindings.total, 1);
    assert_eq!(bindings.items[0].spec.policy, original);
    assert_eq!(bindings.items[0].spec.scope.process, instance);
    let wire = serde_json::to_value(&scope).unwrap();
    assert!(wire.get("revision").is_none());
    assert!(wire.get("policyTemplates").is_none());
    assert_eq!(wire["policySnapshots"], serde_json::json!([original]));
    assert_eq!(repo.list_policies(10, 0).unwrap().total, 0);
}

#[test]
fn snapshot_admission_races_policy_mutation_atomically() {
    use std::sync::Barrier;
    for delete in [false, true] {
        for iteration in 0..32 {
            let (pap, repo) = service();
            let original = pap.create_policy("old", &policy_template("/a")).unwrap();
            let candidate = PreparedScope {
                scope_id: ResourceId::new(format!("scope-{iteration}")).unwrap(),
                selector: ScopeSelector::Pid { pid: 4242 },
                policy_snapshots: vec![original.clone()],
                status: asc_policy_types::scope::ScopeStatus::Active,
            };
            let gate = Arc::new(Barrier::new(2));
            let admission = {
                let gate = gate.clone();
                let repo = repo.clone();
                let candidate = candidate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    repo.put_scope(&candidate)
                })
            };
            gate.wait();
            if delete {
                pap.delete_policy_revision(&original.policy_id, original.revision)
                    .unwrap();
            } else {
                pap.update_policy(&original.policy_id, "new", &original.template)
                    .unwrap();
            }
            match admission.join().unwrap() {
                Ok(saved) => assert_eq!(saved, candidate),
                Err(error) => assert_eq!(error, PapError::ReferencedPolicyRevisionNotFound),
            }
            if let Ok(saved) = pap.get_scope(&candidate.scope_id) {
                assert_eq!(saved.policy_snapshots, vec![original]);
            }
        }
    }
}

#[test]
fn deleting_scope_fences_discovery_and_retains_failures_until_explicit_retry() {
    use asc_pap::ScopeBindingSink;
    let (pap, repo) = service();
    let pap = pap.with_scope_discovery(Arc::new(Discovery));
    let policy = pap.create_policy("policy", &policy_template("/a")).unwrap();
    let scope = assignment(&pap, &policy);
    let other = assignment(&pap, &policy);
    let instance = serde_json::from_str::<PreparedBinding>(COMPLETE_BINDING)
        .unwrap()
        .scope
        .process;
    for scope in [&scope, &other] {
        pap.sync_instances(&scope.scope_id, std::slice::from_ref(&instance))
            .unwrap();
    }
    let binding = pap
        .list_bindings(10, 0)
        .unwrap()
        .items
        .into_iter()
        .find(|b| b.spec.scope.scope_id == scope.scope_id)
        .unwrap();
    repo.transition(&binding.spec.binding_id, BindingStatus::Applying);
    let stale_apply = repo.binding_state(&binding.spec.binding_id);
    pap.delete_scope(&scope.scope_id).unwrap();
    assert_eq!(
        pap.sync_instances(&scope.scope_id, &[instance]),
        Err(PapError::OperationInProgress)
    );
    let mut late_ready = stale_apply.clone();
    late_ready.binding.status = BindingStatus::Ready.into();
    assert_eq!(
        repo.inner
            .compare_exchange_binding_state(&stale_apply, &BindingStateWrite::new(late_ready)),
        Ok(WriteResult::Conflict)
    );
    repo.transition(&binding.spec.binding_id, BindingStatus::Deleting);
    repo.transition(&binding.spec.binding_id, BindingStatus::DeleteFailed);
    let failed = pap.get_binding(&binding.spec.binding_id).unwrap();
    pap.delete_scope(&scope.scope_id).unwrap();
    assert_eq!(pap.get_binding(&binding.spec.binding_id).unwrap(), failed);
    assert_eq!(pap.get_scope(&other.scope_id).unwrap(), other);
    pap.retry_scope(&scope.scope_id).unwrap();
    assert_eq!(
        pap.get_binding(&binding.spec.binding_id).unwrap().status,
        BindingStatus::PendingDelete
    );
    assert_eq!(
        pap.get_binding(&binding.spec.binding_id).unwrap().spec,
        binding.spec
    );
    assert_eq!(pap.list_bindings(10, 0).unwrap().total, 2);
}

#[test]
fn instance_reuse_retires_old_binding_and_creates_distinct_identity() {
    use asc_pap::ScopeBindingSink;
    let (pap, _) = service();
    let pap = pap.with_scope_discovery(Arc::new(Discovery));
    let policy = pap.create_policy("policy", &policy_template("/a")).unwrap();
    let scope = assignment(&pap, &policy);
    let mut instance = serde_json::from_str::<PreparedBinding>(COMPLETE_BINDING)
        .unwrap()
        .scope
        .process;
    pap.sync_instances(&scope.scope_id, std::slice::from_ref(&instance))
        .unwrap();
    let first = pap.list_bindings(10, 0).unwrap().items.remove(0);
    instance.start_time += 1;
    pap.sync_instances(&scope.scope_id, std::slice::from_ref(&instance))
        .unwrap();
    assert_eq!(
        pap.get_binding(&first.spec.binding_id).unwrap().status,
        BindingStatus::PendingDelete
    );
    let all = pap.list_bindings(10, 0).unwrap();
    assert_eq!(all.total, 2);
    let second = all
        .items
        .iter()
        .find(|b| b.spec.binding_id != first.spec.binding_id)
        .unwrap();
    assert_eq!(second.spec.scope.process, instance);
    assert_eq!(second.status, BindingStatus::PendingApply);
}

#[test]
fn discovery_start_error_survives_compensation_failures() {
    struct UnavailableDiscovery;
    impl asc_pap::ScopeDiscovery for UnavailableDiscovery {
        fn start(&self, _: &PreparedScope) -> Result<(), PapError> {
            Err(PapError::Unavailable)
        }
        fn stop(&self, _: &ResourceId) -> Result<(), PapError> {
            panic!("failed start must not leave a worker to stop")
        }
    }
    for failure in 0..=2 {
        let (pap, repo) = service();
        repo.scope_cleanup_failure
            .store(failure, std::sync::atomic::Ordering::SeqCst);
        let pap = pap.with_scope_discovery(Arc::new(UnavailableDiscovery));
        let policy = pap
            .create_policy("test", &policy_template("/protected"))
            .unwrap();
        assert_eq!(
            pap.create_scope_assignment(
                &ScopeSelector::Pid { pid: 4242 },
                &[asc_policy_types::scope::PolicyReference {
                    policy_id: policy.policy_id.clone(),
                    policy_revision: policy.revision,
                }],
            ),
            Err(PapError::Unavailable),
            "compensation failure at step {failure} must not replace the startup error"
        );
        let remaining = pap.list_scopes(10, 0).unwrap();
        if failure == 0 {
            assert_eq!(remaining.total, 0);
        } else {
            assert_eq!(remaining.total, 1);
            let scope = &remaining.items[0];
            assert_eq!(scope.policy_snapshots, vec![policy]);
            assert_eq!(
                scope.status,
                if failure == 1 {
                    asc_policy_types::scope::ScopeStatus::Active
                } else {
                    asc_policy_types::scope::ScopeStatus::Deleting
                }
            );
            repo.scope_cleanup_failure
                .store(0, std::sync::atomic::Ordering::SeqCst);
            // After the storage failure clears, explicit deletion can finish cleanup.
            let pap = pap.with_scope_discovery(Arc::new(Discovery));
            assert!(pap.delete_scope(&scope.scope_id).unwrap().completed);
        }
    }
}
