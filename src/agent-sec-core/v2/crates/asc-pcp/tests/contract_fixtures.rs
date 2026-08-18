use std::collections::HashSet;

use asc_policy_engine::{PolicyTemplate, TemplateEnvelope, lower_template};
use asc_policy_types::Validate;
use asc_policy_types::identifiers::{PolicyId, Revision};
use asc_policy_types::mapping::{BindingState, MappingRelation, PolicyState};
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::receipt::{PullReceiptsResponse, ReceiptType};
use asc_policy_types::reconcile::{
    ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse,
};
use asc_policy_types::state::GetStateResponse;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn round_trip<T>(wire: &str) -> T
where
    T: DeserializeOwned + Serialize,
{
    let value: serde_json::Value = serde_json::from_str(wire).unwrap();
    let decoded: T = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
    decoded
}

fn assert_lowering(template_wire: &str, policy_id: &str, policy_wire: &str) {
    let template: PolicyTemplate = round_trip(template_wire);
    let actual = lower_template(TemplateEnvelope {
        policy_id: PolicyId::new(policy_id).unwrap(),
        revision: Revision::new(1).unwrap(),
        template,
    })
    .unwrap();
    let expected: PolicyEnvelope = round_trip(policy_wire);
    expected.validate().unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn pap_inputs_lower_to_the_frozen_canonical_ir() {
    assert_lowering(
        include_str!("../../../fixtures/pap/high-sensitivity-read.json"),
        "high-sensitive-read",
        include_str!("../../../fixtures/canonical-policy-high-sensitive-read.json"),
    );
    assert_lowering(
        include_str!("../../../fixtures/pap/prevent-file-deletion.json"),
        "prevent-file-deletion",
        include_str!("../../../fixtures/canonical-policy-prevent-file-deletion.json"),
    );
    assert_lowering(
        include_str!("../../../fixtures/pap/low-sensitivity-egress.json"),
        "low-sensitivity-egress",
        include_str!("../../../fixtures/canonical-policy-low-sensitivity-egress.json"),
    );
}

#[test]
fn policy_present_and_absent_wire_pairs_are_frozen() {
    let high_request: ReconcilePolicyRequest = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/policy-present-high.request.json"
    ));
    high_request.validate().unwrap();
    let high_response: ReconcilePolicyResponse = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/policy-present-high.response.json"
    ));
    assert_eq!(high_response.state, PolicyState::Available);

    let low_request: ReconcilePolicyRequest = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/policy-present-low-egress.request.json"
    ));
    low_request.validate().unwrap();
    let low_response: ReconcilePolicyResponse = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/policy-present-low-egress.response.json"
    ));
    assert_eq!(low_response.state, PolicyState::Available);

    let absent_request: ReconcilePolicyRequest = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/policy-absent.request.json"
    ));
    absent_request.validate().unwrap();
    let absent_response: ReconcilePolicyResponse = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/policy-absent.response.json"
    ));
    assert_eq!(absent_response.state, PolicyState::Absent);
}

#[test]
fn binding_exact_and_unsupported_wire_pairs_are_frozen() {
    let exact_request: ReconcileBindingRequest = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/binding-exact.request.json"
    ));
    exact_request.validate().unwrap();
    let exact_response: ReconcileBindingResponse = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/binding-exact.response.json"
    ));
    assert_eq!(exact_response.state, BindingState::BindingReady);
    assert_eq!(
        exact_response.mappings[0].policy_relation,
        MappingRelation::Exact
    );

    let unsupported_request: ReconcileBindingRequest = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/binding-direct-flow-unsupported.request.json"
    ));
    unsupported_request.validate().unwrap();
    let unsupported_response: ReconcileBindingResponse = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/binding-direct-flow-unsupported.response.json"
    ));
    assert_eq!(unsupported_response.state, BindingState::Rejected);
    assert_eq!(
        unsupported_response.mappings[0].policy_relation,
        MappingRelation::Unsupported
    );
}

#[test]
fn state_and_all_three_receipt_types_are_frozen() {
    let state: GetStateResponse = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/state-policy-available.response.json"
    ));
    assert!(state.service.ready);
    assert_eq!(state.policies[0].state, PolicyState::Available);

    let page: PullReceiptsResponse = round_trip(include_str!(
        "../../../fixtures/pcp-agentsight/receipts-three-types.response.json"
    ));
    for receipt in &page.receipts {
        receipt.validate().unwrap();
    }
    let types: HashSet<_> = page
        .receipts
        .iter()
        .map(|receipt| receipt.receipt_type)
        .collect();
    assert_eq!(
        types,
        HashSet::from([
            ReceiptType::Deployment,
            ReceiptType::Enforcement,
            ReceiptType::Effect,
        ])
    );
}
