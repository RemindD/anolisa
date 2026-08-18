use agentsight_enforcement_protocol::{Binding, BindingState as RuntimeBindingState};
use asc_policy_types::identifiers::{BindingId, Digest, OperationId, PolicyId};
use asc_policy_types::mapping::{BindingState, MappingRelation, PolicyState};
use asc_policy_types::reconcile::{
    ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse,
};

use super::{BindingPlan, CanonicalPolicyController, EnforcementStore};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            "../../../agent-sec-core/v2/fixtures/pcp-agentsight/",
            $name
        ))
    };
}

fn policy_request(name: &str) -> ReconcilePolicyRequest {
    let json = match name {
        "high" => fixture!("policy-present-high.request.json"),
        "low" => fixture!("policy-present-low-egress.request.json"),
        "absent" => fixture!("policy-absent.request.json"),
        _ => panic!("unknown policy fixture {name}"),
    };
    serde_json::from_str(json).expect("policy fixture should decode")
}

fn binding_request(name: &str) -> ReconcileBindingRequest {
    let json = match name {
        "exact" => fixture!("binding-exact.request.json"),
        "unsupported" => fixture!("binding-direct-flow-unsupported.request.json"),
        _ => panic!("unknown binding fixture {name}"),
    };
    serde_json::from_str(json).expect("binding fixture should decode")
}

fn deletion_policy_request() -> ReconcilePolicyRequest {
    let policy = serde_json::from_str(include_str!(
        "../../../agent-sec-core/v2/fixtures/canonical-policy-prevent-file-deletion.json"
    ))
    .expect("deletion policy fixture should decode");
    let mut request = policy_request("high");
    let ReconcilePolicyRequest::Present {
        operation_id,
        policy: request_policy,
        ..
    } = &mut request
    else {
        panic!("fixture should contain PRESENT");
    };
    *operation_id =
        OperationId::new("policy-delete-op-1").expect("operation identifier should be valid");
    *request_policy = policy;
    request
}

fn deletion_binding_request() -> ReconcileBindingRequest {
    let mut request = binding_request("exact");
    let ReconcileBindingRequest::Ready(ready) = &mut request else {
        panic!("fixture should contain READY");
    };
    ready.operation_id =
        OperationId::new("binding-delete-op-1").expect("operation identifier should be valid");
    ready.binding_id =
        BindingId::new("binding-delete-1").expect("binding identifier should be valid");
    ready.effective_policy.policy_id =
        PolicyId::new("prevent-file-deletion").expect("policy identifier should be valid");
    request
}

#[test]
fn policy_json_examples_drive_create_idempotency_and_delete() {
    let controller = CanonicalPolicyController::new_mock(
        EnforcementStore::open(":memory:").expect("store should open"),
    );
    let request = policy_request("high");
    let expected: ReconcilePolicyResponse =
        serde_json::from_str(fixture!("policy-present-high.response.json"))
            .expect("response fixture should decode");

    let response = controller
        .reconcile_policy(request.clone())
        .expect("policy should reconcile");
    assert_eq!(response, expected);
    assert_eq!(
        controller
            .reconcile_policy(request)
            .expect("retry should be idempotent"),
        expected
    );

    let absent_expected: ReconcilePolicyResponse =
        serde_json::from_str(fixture!("policy-absent.response.json"))
            .expect("absent response fixture should decode");
    assert_eq!(
        controller
            .reconcile_policy(policy_request("absent"))
            .expect("policy should be removable"),
        absent_expected
    );
}

#[test]
fn exact_binding_json_example_installs_through_mock_target() {
    let store = EnforcementStore::open(":memory:").expect("store should open");
    let controller = CanonicalPolicyController::new_mock(store);
    controller
        .reconcile_policy(policy_request("high"))
        .expect("policy should reconcile");
    let plan = match controller
        .plan_binding(binding_request("exact"))
        .expect("binding should map")
    {
        BindingPlan::Install(plan) => plan,
        BindingPlan::Complete(response) => {
            panic!("expected install plan, received {:?}", response.state)
        }
    };
    assert!(plan.apply_policy.policy_dsl.contains("block open file"));
    let acknowledgement = Binding {
        request: plan.apply_policy.clone(),
        state: RuntimeBindingState::Enforced,
        message: None,
        domain_id: Some(42),
    };
    let response = controller
        .complete_binding(plan, acknowledgement)
        .expect("acknowledgement should complete the binding");
    let expected: ReconcileBindingResponse =
        serde_json::from_str(fixture!("binding-exact.response.json"))
            .expect("binding response fixture should decode");

    assert_eq!(response.state, expected.state);
    assert_eq!(response.binding_id, expected.binding_id);
    assert_eq!(response.effective_policy, expected.effective_policy);
    assert_eq!(response.scope_state, expected.scope_state);
    assert_eq!(response.mappings[0].policy_relation, MappingRelation::Exact);
    assert_eq!(response.mappings[0].target_id.as_str(), "mock-pep-v1");
}

#[test]
fn low_egress_json_examples_defer_at_policy_and_reject_at_binding() {
    let controller = CanonicalPolicyController::new(
        EnforcementStore::open(":memory:").expect("store should open"),
    );
    let response = controller
        .reconcile_policy(policy_request("low"))
        .expect("valid policy should be available");
    let expected: ReconcilePolicyResponse =
        serde_json::from_str(fixture!("policy-present-low-egress.response.json"))
            .expect("policy response fixture should decode");
    assert_eq!(response, expected);
    assert_eq!(response.state, PolicyState::Available);

    let response = match controller
        .plan_binding(binding_request("unsupported"))
        .expect("unsupported semantics should produce a terminal response")
    {
        BindingPlan::Complete(response) => response,
        BindingPlan::Install(_) => panic!("direct flow must not reach the PEP"),
    };
    let expected: ReconcileBindingResponse =
        serde_json::from_str(fixture!("binding-direct-flow-unsupported.response.json"))
            .expect("binding response fixture should decode");
    assert_eq!(response.state, expected.state);
    assert_eq!(response.binding_id, expected.binding_id);
    assert_eq!(
        response.mappings[0].policy_relation,
        MappingRelation::Unsupported
    );
    assert_eq!(
        response.mappings[0].rules[0].atoms[0].diagnostics[0].code,
        "UNSUPPORTED_DIRECT_FLOW"
    );
    assert!(response.target_digests.is_empty());
    assert!(response.pep_instances.is_empty());
}

#[test]
fn actplane_read_mapping_requires_digest_bound_narrower_approval() {
    let controller = CanonicalPolicyController::new(
        EnforcementStore::open(":memory:").expect("store should open"),
    );
    controller
        .reconcile_policy(policy_request("high"))
        .expect("policy should reconcile");
    let response = match controller
        .plan_binding(binding_request("exact"))
        .expect("mapping should complete")
    {
        BindingPlan::Complete(response) => response,
        BindingPlan::Install(_) => panic!("unapproved narrower mapping must not install"),
    };
    assert_eq!(response.state, BindingState::ApprovalRequired);
    assert_eq!(
        response.mappings[0].policy_relation,
        MappingRelation::Narrower
    );
    let approved_digest = response
        .mapping_digest
        .expect("approval response should contain its mapping digest");

    let mut approved = binding_request("exact");
    let ReconcileBindingRequest::Ready(ready) = &mut approved else {
        panic!("fixture should contain READY");
    };
    ready.operation_id =
        OperationId::new("binding-high-op-approved").expect("operation identifier should be valid");
    ready.approval.allow_narrower = true;
    ready.approval.expected_mapping_digest =
        Some(Digest::new(approved_digest.to_string()).expect("mapping digest should remain valid"));
    assert!(matches!(
        controller
            .plan_binding(approved)
            .expect("approved mapping should prepare"),
        BindingPlan::Install(_)
    ));
}

#[test]
fn namespace_mutation_lowers_directly_to_unlink() {
    let controller = CanonicalPolicyController::new(
        EnforcementStore::open(":memory:").expect("store should open"),
    );
    controller
        .reconcile_policy(deletion_policy_request())
        .expect("deletion policy should reconcile");
    let plan = match controller
        .plan_binding(deletion_binding_request())
        .expect("namespace mutation should map")
    {
        BindingPlan::Install(plan) => plan,
        BindingPlan::Complete(response) => {
            panic!("expected install plan, received {:?}", response.state)
        }
    };
    assert!(
        plan.apply_policy
            .policy_dsl
            .contains("block unlink file \"/workspace/important/**\"")
    );
    assert!(
        plan.apply_policy
            .policy_dsl
            .contains("block unlink file \"/etc/agent/config.yaml\"")
    );
    assert!(!plan.apply_policy.policy_dsl.contains("block open file"));
}
