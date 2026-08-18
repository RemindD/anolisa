use asc_policy_types::identifiers::{Digest, Revision};
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::receipt::Receipt;
use asc_policy_types::reconcile::{ReconcileBindingRequest, ReconcilePolicyRequest};
use asc_policy_types::scope::BindingScope;
use asc_policy_types::{Validate, ValidationError};
use serde_json::{Value, json};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PROFILE: &str = "agentseccore-canonical-ir/v1alpha1-demo1";

fn canonical_policy_json() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/canonical-policy-high-sensitive-read.json"
    ))
    .unwrap()
}

fn binding_request_json() -> Value {
    json!({
        "operationId": "bind-123",
        "desiredState": "READY",
        "bindingId": "binding-123",
        "runId": "run-123",
        "effectivePolicy": {
            "policyId": "high-sensitive-read",
            "revision": 1,
            "profileId": PROFILE
        },
        "identity": {
            "executionDomainId": "domain-456",
            "identityEpoch": 17,
            "rootProcess": {"pid": 8191, "startTimeTicks": 654_321},
            "cgroupId": 8192
        },
        "scope": {
            "processes": {
                "membership": "execution_domain",
                "includeRoot": true,
                "includeExistingMembers": false,
                "includeFutureMembers": true,
                "preserveAcrossExec": true,
                "nestedExecutionDomains": "inherit"
            },
            "namespaces": {
                "pidNamespaceId": 4_026_531_836_u64,
                "mountNamespaceId": 4_026_531_840_u64,
                "networkNamespaceId": 4_026_531_841_u64,
                "onChange": "deny"
            },
            "lifetime": {
                "activateAt": "binding_ready",
                "expiresAt": null,
                "endCondition": "execution_domain_drained"
            }
        },
        "scopeDigest": DIGEST,
        "runtimeContext": {
            "baselineId": "image:sha256:baseline",
            "runtimeProfileDigest": DIGEST
        },
        "approval": {
            "allowNarrower": false,
            "approvalRef": null,
            "expectedMappingDigest": null
        },
        "precondition": {
            "expectedBindingRevision": null,
            "capabilitySnapshotDigest": DIGEST
        }
    })
}

#[test]
fn canonical_policy_wire_contract_round_trips() {
    let wire = canonical_policy_json();
    let policy: PolicyEnvelope = serde_json::from_value(wire.clone()).unwrap();

    policy.validate().unwrap();
    assert_eq!(serde_json::to_value(policy).unwrap(), wire);
}

#[test]
fn canonical_policy_rejects_unknown_fields_versions_and_invalid_references() {
    let mut unknown = canonical_policy_json();
    unknown["payload"]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<PolicyEnvelope>(unknown).is_err());

    let mut version = canonical_policy_json();
    version["irSchemaVersion"] = json!(2);
    let policy: PolicyEnvelope = serde_json::from_value(version).unwrap();
    assert_eq!(policy.validate().unwrap_err().path, "irSchemaVersion");

    let mut reference = canonical_policy_json();
    reference["payload"]["rules"][0]["when"]["atom"]["target"]["resourceSet"] = json!("missing");
    let policy: PolicyEnvelope = serde_json::from_value(reference).unwrap();
    assert!(
        policy
            .validate()
            .unwrap_err()
            .message
            .contains("does not exist")
    );
}

#[test]
fn canonical_policy_rejects_operation_resource_mismatch() {
    let mut wire = canonical_policy_json();
    wire["payload"]["rules"][0]["when"]["atom"]["operation"] = json!("connect");
    let policy: PolicyEnvelope = serde_json::from_value(wire).unwrap();

    assert!(
        policy
            .validate()
            .unwrap_err()
            .message
            .contains("incompatible")
    );
}

#[test]
fn canonical_policy_rejects_nested_resource_sets_derived_flow_and_environment_paths() {
    let mut nested = canonical_policy_json();
    let resource = nested["payload"]["resources"][0].as_object_mut().unwrap();
    let kind = resource.remove("kind").unwrap();
    let matchers = resource.remove("matchers").unwrap();
    resource.insert(
        "selector".to_owned(),
        json!({"kind": kind, "matchers": matchers}),
    );
    assert!(serde_json::from_value::<PolicyEnvelope>(nested).is_err());

    let derived: PolicyEnvelope = serde_json::from_str(include_str!(
        "../../../fixtures/canonical-policy-low-sensitivity-egress.json"
    ))
    .unwrap();
    let mut derived = serde_json::to_value(derived).unwrap();
    derived["payload"]["rules"][0]["when"]["atom"]["propagation"] = json!("derived");
    let derived: PolicyEnvelope = serde_json::from_value(derived).unwrap();
    assert_eq!(
        derived.validate().unwrap_err().path,
        "payload.rules[0].atom.propagation"
    );

    let mut environment = canonical_policy_json();
    environment["payload"]["resources"][0]["matchers"][0]["path"]["pattern"] =
        json!("/workspace/$SECRET/**");
    let environment: PolicyEnvelope = serde_json::from_value(environment).unwrap();
    assert!(environment.validate().is_err());
}

#[test]
fn reconcile_policy_variants_are_mutually_exclusive() {
    let present = json!({
        "operationId": "policy-op-123",
        "desiredState": "PRESENT",
        "policy": canonical_policy_json(),
        "precondition": {
            "expectedCurrentRevision": null,
            "expectedPayloadDigest": null
        }
    });
    let request: ReconcilePolicyRequest = serde_json::from_value(present).unwrap();
    request.validate().unwrap();

    let invalid = json!({
        "operationId": "policy-op-123",
        "desiredState": "PRESENT",
        "policyId": "high-sensitive-read",
        "policy": canonical_policy_json(),
        "precondition": {
            "expectedCurrentRevision": null,
            "expectedPayloadDigest": null
        }
    });
    assert!(serde_json::from_value::<ReconcilePolicyRequest>(invalid).is_err());
}

#[test]
fn binding_scope_identity_and_narrower_approval_are_validated() {
    let wire = binding_request_json();
    let scope: BindingScope = serde_json::from_value(wire["scope"].clone()).unwrap();
    scope.validate().unwrap();

    let request: ReconcileBindingRequest = serde_json::from_value(wire.clone()).unwrap();
    request.validate().unwrap();
    assert_eq!(serde_json::to_value(request).unwrap(), wire);

    let mut stale_pid = binding_request_json();
    stale_pid["identity"]["rootProcess"]["startTimeTicks"] = json!(0);
    let request: ReconcileBindingRequest = serde_json::from_value(stale_pid).unwrap();
    assert_eq!(request.validate().unwrap_err().path, "identity.rootProcess");

    let mut invalid_scope = binding_request_json();
    invalid_scope["scope"]["processes"]["includeFutureMembers"] = json!(false);
    let request: ReconcileBindingRequest = serde_json::from_value(invalid_scope).unwrap();
    assert_eq!(request.validate().unwrap_err().path, "scope.processes");

    let mut unbound_approval = binding_request_json();
    unbound_approval["approval"]["allowNarrower"] = json!(true);
    let request: ReconcileBindingRequest = serde_json::from_value(unbound_approval).unwrap();
    assert_eq!(
        request.validate().unwrap_err().path,
        "approval.expectedMappingDigest"
    );
}

#[test]
fn enforcement_receipt_carries_ir_correlation_without_content() {
    let wire = json!({
        "receiptId": "receipt-789",
        "type": "enforcement",
        "sequence": 456,
        "operationId": null,
        "policyId": "high-sensitive-read",
        "policyRevision": 1,
        "bindingId": "binding-123",
        "scopeDigest": DIGEST,
        "ruleId": "deny-high-sensitive-read",
        "expressionPath": "when.atom",
        "resourceSetId": "high-sensitive-files",
        "mappingDigest": DIGEST,
        "targetId": "actplane-v1",
        "targetDigest": DIGEST,
        "pepInstanceId": "actplane-1",
        "executionDomainId": "domain-456",
        "operation": "read",
        "blockPoint": "pre_effect",
        "actualResult": "blocked",
        "rawReceiptDigest": DIGEST,
        "occurredAt": "2026-08-18T10:02:00Z"
    });
    let receipt: Receipt = serde_json::from_value(wire.clone()).unwrap();

    receipt.validate().unwrap();
    assert_eq!(serde_json::to_value(receipt).unwrap(), wire);
}

#[test]
fn identifiers_reject_zero_revision_and_noncanonical_digest() {
    assert!(Revision::new(0).is_err());
    assert!(Digest::new("sha256:ABC").is_err());
    assert!(serde_json::from_value::<Revision>(json!(0)).is_err());
}

#[test]
fn validation_errors_have_stable_paths() {
    let error = ValidationError::new("scope.processes", "invalid scope");
    assert_eq!(error.to_string(), "scope.processes: invalid scope");
}
