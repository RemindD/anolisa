use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use asc_pcp::{
    AgentSightClient, ClientError, Controller, ControllerError, FileStateStore, MemoryStateStore,
    StateStore,
};
use asc_policy_engine::{PolicyTemplate, TemplateEnvelope};
use asc_policy_types::binding::{ExecutionIdentity, ProcessIdentity, RuntimeContext};
use asc_policy_types::identifiers::{Digest, Revision};
use asc_policy_types::mapping::{
    AtomMapping, BindingState, GuaranteeMapping, MappingRelation, MappingReport, PolicyState,
    RuleMapping,
};
use asc_policy_types::policy::EffectivePolicyRef;
use asc_policy_types::receipt::{PullReceiptsRequest, PullReceiptsResponse, Receipt, ReceiptType};
use asc_policy_types::reconcile::{
    BindingApproval, BindingPrecondition, PolicyPrecondition, ReadyBindingRequest,
    ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse, StaticCompileReport, StaticCompileStage, ValidationReport,
    ValidationStatus,
};
use asc_policy_types::scope::{
    BindingActivation, BindingEndCondition, BindingLifetime, BindingScope, NamespaceChangeAction,
    NamespaceScope, NestedExecutionDomainAction, ProcessMembership, ProcessScope,
};
use asc_policy_types::state::{
    CapabilitySnapshot, GetStateRequest, GetStateResponse, ServiceState,
};

const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ONE_DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const PROFILE: &str = "agentseccore-canonical-ir/v1alpha1-demo1";

struct FakeClient {
    policy_response: ReconcilePolicyResponse,
    binding_response: ReconcileBindingResponse,
    state_response: GetStateResponse,
    receipt_pages: Mutex<VecDeque<PullReceiptsResponse>>,
    receipt_requests: Arc<Mutex<Vec<PullReceiptsRequest>>>,
    policy_calls: Arc<AtomicUsize>,
    binding_calls: Arc<AtomicUsize>,
    state_calls: Arc<AtomicUsize>,
    fail_policy_once: AtomicBool,
}

impl AgentSightClient for FakeClient {
    fn reconcile_policy(
        &self,
        _request: &ReconcilePolicyRequest,
    ) -> Result<ReconcilePolicyResponse, ClientError> {
        self.policy_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_policy_once.swap(false, Ordering::SeqCst) {
            return Err(ClientError::AmbiguousTransport(
                "connection reset".to_owned(),
            ));
        }
        Ok(self.policy_response.clone())
    }

    fn reconcile_binding(
        &self,
        _request: &ReconcileBindingRequest,
    ) -> Result<ReconcileBindingResponse, ClientError> {
        self.binding_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.binding_response.clone())
    }

    fn get_state(&self, _request: &GetStateRequest) -> Result<GetStateResponse, ClientError> {
        self.state_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.state_response.clone())
    }

    fn pull_receipts(
        &self,
        request: &PullReceiptsRequest,
    ) -> Result<PullReceiptsResponse, ClientError> {
        self.receipt_requests.lock().unwrap().push(request.clone());
        self.receipt_pages
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| ClientError::InvalidResponse("no scripted receipt page".to_owned()))
    }
}

fn id<T>(value: &str) -> T
where
    T: TryFrom<String, Error = String>,
{
    T::try_from(value.to_owned()).unwrap()
}

fn rev(value: u64) -> Revision {
    Revision::new(value).unwrap()
}

fn digest(value: &str) -> Digest {
    Digest::new(value).unwrap()
}

fn product_template(policy_id: &str) -> TemplateEnvelope {
    TemplateEnvelope {
        policy_id: id(policy_id),
        revision: rev(1),
        template: PolicyTemplate::HighSensitivityReadDeny {
            files: vec!["/secrets/**".to_owned()],
        },
    }
}

fn policy_request(operation_id: &str, policy_id: &str) -> ReconcilePolicyRequest {
    let policy = asc_policy_engine::lower_template(product_template(policy_id)).unwrap();
    ReconcilePolicyRequest::Present {
        operation_id: id(operation_id),
        policy,
        precondition: PolicyPrecondition {
            expected_current_revision: None,
            expected_payload_digest: None,
        },
    }
}

fn policy_response(operation_id: &str, policy_id: &str) -> ReconcilePolicyResponse {
    ReconcilePolicyResponse {
        operation_id: id(operation_id),
        state: PolicyState::Available,
        policy_id: id(policy_id),
        revision: Some(rev(1)),
        payload_digest: None,
        validation: Some(ValidationReport {
            status: ValidationStatus::Valid,
            diagnostics: vec![],
        }),
        static_compile: Some(StaticCompileReport {
            stage: StaticCompileStage::DeferredToBinding,
            compiler_version: "fake-v1".to_owned(),
            diagnostics: vec![],
        }),
        error: None,
    }
}

fn mapping(binding_id: &str, relation: MappingRelation) -> MappingReport {
    MappingReport {
        binding_id: id(binding_id),
        policy_id: id("high-sensitive"),
        policy_revision: rev(1),
        target_id: id("fake-target"),
        policy_relation: relation,
        mapping_digest: digest(ZERO_DIGEST),
        capability_snapshot_digest: digest(ZERO_DIGEST),
        rules: vec![RuleMapping {
            rule_id: id("deny-high-sensitive-read"),
            relation,
            atoms: vec![AtomMapping {
                expression_path: "when.atom".to_owned(),
                relation,
                diagnostics: vec![],
            }],
            diagnostics: vec![],
        }],
        guarantees: GuaranteeMapping {
            relation,
            diagnostics: vec![],
        },
    }
}

fn binding_request(allow_narrower: bool) -> ReconcileBindingRequest {
    ReconcileBindingRequest::Ready(Box::new(ReadyBindingRequest {
        operation_id: id("binding-op"),
        binding_id: id("binding-1"),
        run_id: id("run-1"),
        effective_policy: EffectivePolicyRef {
            policy_id: id("high-sensitive"),
            revision: rev(1),
            profile_id: id(PROFILE),
            payload_digest: None,
        },
        identity: ExecutionIdentity {
            execution_domain_id: id("domain-1"),
            identity_epoch: 1,
            root_process: ProcessIdentity {
                pid: 1000,
                start_time_ticks: 5000,
            },
            cgroup_id: 2000,
        },
        scope: BindingScope {
            processes: ProcessScope {
                membership: ProcessMembership::ExecutionDomain,
                include_root: true,
                include_existing_members: false,
                include_future_members: true,
                preserve_across_exec: true,
                nested_execution_domains: NestedExecutionDomainAction::Inherit,
            },
            namespaces: NamespaceScope {
                pid_namespace_id: 10,
                mount_namespace_id: 11,
                network_namespace_id: 12,
                on_change: NamespaceChangeAction::Deny,
            },
            lifetime: BindingLifetime {
                activate_at: BindingActivation::BindingReady,
                expires_at: None,
                end_condition: BindingEndCondition::ExecutionDomainDrained,
            },
        },
        scope_digest: digest(ZERO_DIGEST),
        runtime_context: RuntimeContext {
            baseline_id: id("baseline-1"),
            runtime_profile_digest: digest(ZERO_DIGEST),
        },
        approval: BindingApproval {
            allow_narrower,
            approval_ref: allow_narrower.then(|| "approval-1".to_owned()),
            expected_mapping_digest: allow_narrower.then(|| digest(ONE_DIGEST)),
        },
        precondition: BindingPrecondition {
            expected_binding_revision: None,
            capability_snapshot_digest: digest(ZERO_DIGEST),
        },
    }))
}

fn binding_response(relation: MappingRelation) -> ReconcileBindingResponse {
    ReconcileBindingResponse {
        operation_id: id("binding-op"),
        state: BindingState::BindingReady,
        binding_id: id("binding-1"),
        binding_revision: Some(rev(1)),
        execution_domain_id: Some(id("domain-1")),
        identity_epoch: Some(1),
        effective_policy: Some(EffectivePolicyRef {
            policy_id: id("high-sensitive"),
            revision: rev(1),
            profile_id: id(PROFILE),
            payload_digest: None,
        }),
        scope_digest: Some(digest(ZERO_DIGEST)),
        scope_state: None,
        mapping_digest: Some(digest(ONE_DIGEST)),
        mappings: vec![mapping("binding-1", relation)],
        target_digests: vec![digest(ZERO_DIGEST)],
        pep_instances: vec![id("fake-pep")],
        effective_at: Some("2026-08-19T00:00:00Z".to_owned()),
        error: None,
    }
}

fn get_state(
    policies: Vec<ReconcilePolicyResponse>,
    bindings: Vec<ReconcileBindingResponse>,
) -> GetStateResponse {
    GetStateResponse {
        service: ServiceState {
            ready: true,
            api_version: "agentsight.enforcement/v1".to_owned(),
            agent_sight_instance_id: id("fake-agentsight"),
        },
        capability_snapshot: CapabilitySnapshot {
            schema_version: "v1".to_owned(),
            snapshot_digest: digest(ZERO_DIGEST),
            matrix: vec![],
        },
        operations: vec![],
        policies,
        bindings,
    }
}

fn deployment_receipt() -> Receipt {
    Receipt {
        receipt_id: id("receipt-1"),
        receipt_type: ReceiptType::Deployment,
        sequence: 1,
        operation_id: Some(id("policy-op")),
        policy_id: Some(id("high-sensitive")),
        policy_revision: Some(rev(1)),
        binding_id: None,
        scope_digest: None,
        rule_id: None,
        expression_path: None,
        resource_set_id: None,
        mapping_digest: None,
        target_id: None,
        target_digest: None,
        pep_instance_id: id("fake-pep"),
        execution_domain_id: None,
        operation: "policy_install".to_owned(),
        block_point: None,
        actual_result: "installed".to_owned(),
        raw_receipt_digest: None,
        occurred_at: "2026-08-19T00:00:00Z".to_owned(),
    }
}

fn fake_client(
    policy: ReconcilePolicyResponse,
    binding: ReconcileBindingResponse,
    state: GetStateResponse,
    pages: Vec<PullReceiptsResponse>,
) -> FakeClient {
    FakeClient {
        policy_response: policy,
        binding_response: binding,
        state_response: state,
        receipt_pages: Mutex::new(pages.into()),
        receipt_requests: Arc::new(Mutex::new(vec![])),
        policy_calls: Arc::new(AtomicUsize::new(0)),
        binding_calls: Arc::new(AtomicUsize::new(0)),
        state_calls: Arc::new(AtomicUsize::new(0)),
        fail_policy_once: AtomicBool::new(false),
    }
}

#[test]
fn policy_reconcile_is_durable_and_idempotent() {
    let client = fake_client(
        policy_response("policy-op", "high-sensitive"),
        binding_response(MappingRelation::Exact),
        get_state(vec![], vec![]),
        vec![],
    );
    let policy_calls = Arc::clone(&client.policy_calls);
    let controller = Controller::new(client, MemoryStateStore::default()).unwrap();
    let prepared = controller
        .prepare_policy(product_template("high-sensitive"))
        .unwrap();
    assert_eq!(prepared.policy_id.as_str(), "high-sensitive");

    let request = policy_request("policy-op", "high-sensitive");
    controller.reconcile_policy(&request).unwrap();
    controller.reconcile_policy(&request).unwrap();

    assert_eq!(
        controller.state_snapshot().unwrap().policy_operations.len(),
        1
    );
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn ambiguous_policy_result_is_recovered_through_get_state() {
    let response = policy_response("policy-op", "high-sensitive");
    let client = fake_client(
        response.clone(),
        binding_response(MappingRelation::Exact),
        get_state(vec![response], vec![]),
        vec![],
    );
    let state_calls = Arc::clone(&client.state_calls);
    client.fail_policy_once.store(true, Ordering::SeqCst);
    let controller = Controller::new(client, MemoryStateStore::default()).unwrap();

    let observed = controller
        .reconcile_policy(&policy_request("policy-op", "high-sensitive"))
        .unwrap();
    assert_eq!(observed.state, PolicyState::Available);
    assert_eq!(state_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn operation_id_cannot_be_reused_with_different_content() {
    let client = fake_client(
        policy_response("policy-op", "high-sensitive"),
        binding_response(MappingRelation::Exact),
        get_state(vec![], vec![]),
        vec![],
    );
    let controller = Controller::new(client, MemoryStateStore::default()).unwrap();
    controller
        .reconcile_policy(&policy_request("policy-op", "high-sensitive"))
        .unwrap();

    assert!(matches!(
        controller.reconcile_policy(&policy_request("policy-op", "other-policy")),
        Err(ControllerError::IdempotencyConflict(_))
    ));
}

#[test]
fn binding_activation_checks_nested_mapping_and_narrower_approval_digest() {
    let client = fake_client(
        policy_response("policy-op", "high-sensitive"),
        binding_response(MappingRelation::Unsupported),
        get_state(vec![], vec![]),
        vec![],
    );
    let controller = Controller::new(client, MemoryStateStore::default()).unwrap();
    assert!(matches!(
        controller.reconcile_binding(&binding_request(false)),
        Err(ControllerError::UnsafeMapping(_))
    ));

    let client = fake_client(
        policy_response("policy-op", "high-sensitive"),
        binding_response(MappingRelation::Narrower),
        get_state(vec![], vec![]),
        vec![],
    );
    let controller = Controller::new(client, MemoryStateStore::default()).unwrap();
    controller
        .reconcile_binding(&binding_request(true))
        .unwrap();
}

#[test]
fn ready_response_must_correlate_to_the_desired_binding() {
    let mut response = binding_response(MappingRelation::Exact);
    response.execution_domain_id = Some(id("other-domain"));
    let client = fake_client(
        policy_response("policy-op", "high-sensitive"),
        response,
        get_state(vec![], vec![]),
        vec![],
    );
    let controller = Controller::new(client, MemoryStateStore::default()).unwrap();

    assert!(matches!(
        controller.reconcile_binding(&binding_request(false)),
        Err(ControllerError::ResponseCorrelation(_))
    ));
}

#[test]
fn receipt_cursor_advances_atomically_and_receipts_are_deduplicated() {
    let receipt = deployment_receipt();
    let client = fake_client(
        policy_response("policy-op", "high-sensitive"),
        binding_response(MappingRelation::Exact),
        get_state(vec![], vec![]),
        vec![
            PullReceiptsResponse {
                next_cursor: "cursor-1".to_owned(),
                receipts: vec![receipt.clone()],
            },
            PullReceiptsResponse {
                next_cursor: "cursor-2".to_owned(),
                receipts: vec![receipt],
            },
        ],
    );
    let receipt_requests = Arc::clone(&client.receipt_requests);
    let controller = Controller::new(client, MemoryStateStore::default()).unwrap();

    assert_eq!(controller.pull_receipts(100).unwrap().len(), 1);
    assert!(controller.pull_receipts(100).unwrap().is_empty());
    let requests = receipt_requests.lock().unwrap();
    assert_eq!(requests[0].cursor, None);
    assert_eq!(requests[1].cursor.as_deref(), Some("cursor-1"));
    drop(requests);
    assert_eq!(
        controller
            .state_snapshot()
            .unwrap()
            .receipt_cursor
            .as_deref(),
        Some("cursor-2")
    );
}

#[test]
fn file_store_survives_reload() {
    let unique = format!(
        "asc-pcp-state-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    );
    let path = std::env::temp_dir().join(unique);
    let store = FileStateStore::new(&path);
    let state = asc_pcp::ControllerState {
        receipt_cursor: Some("cursor-9".to_owned()),
        ..asc_pcp::ControllerState::default()
    };
    store.save(&state).unwrap();
    assert_eq!(store.load().unwrap(), state);
    std::fs::remove_file(path).unwrap();
}
