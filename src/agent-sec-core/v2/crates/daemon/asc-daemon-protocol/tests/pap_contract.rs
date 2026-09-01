use std::collections::BTreeSet;

use asc_daemon_protocol::method;
use asc_daemon_protocol::{
    CreateBindingParams, CreateBindingResult, CreatePolicyParams, CreatePolicyResult,
    CreateScopeParams, CreateScopeResult, DaemonRequest, DaemonResponse, DeleteBindingResult,
    DeletePolicyResult, DeleteScopeResult, ErrorCode, GetBindingResult, GetPolicyResult,
    GetScopeResult, ListBindingsResult, ListParams, ListPoliciesResult, ListScopesResult,
    RequestId, ResourceParams, RevisionParams, UpdateBindingParams, UpdateBindingResult,
    UpdatePolicyParams, UpdatePolicyResult, UpdateScopeParams, UpdateScopeResult, error_code,
};
use asc_foundation_types::ResourceId;
use asc_policy_types::binding::{BindingStatus, BindingView, PreparedBinding};
use asc_policy_types::scope::ScopeSelector;
use serde_json::{Value, json};

#[test]
fn every_pap_method_has_a_strict_canonical_request_fixture() {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!("fixtures/pap-requests.json"))
        .expect("PAP request fixtures must be valid JSON");
    assert_eq!(fixtures.len(), method::PAP_METHODS.len());

    let fixture_methods = fixtures
        .iter()
        .map(|fixture| {
            fixture["method"]
                .as_str()
                .expect("fixture method must be a string")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fixture_methods,
        method::PAP_METHODS.into_iter().collect::<BTreeSet<_>>()
    );

    for fixture in fixtures {
        let method_name = fixture["method"].as_str().unwrap();
        let params = fixture["params"].clone();
        let canonical = fixture["canonicalParams"].clone();
        let encoded = match method_name {
            method::POLICY_TEMPLATES_CREATE => round_trip::<CreatePolicyParams>(params),
            method::POLICY_TEMPLATES_UPDATE => round_trip::<UpdatePolicyParams>(params),
            method::POLICY_SCOPES_CREATE => round_trip::<CreateScopeParams>(params),
            method::POLICY_SCOPES_UPDATE => round_trip::<UpdateScopeParams>(params),
            method::POLICY_BINDINGS_CREATE => round_trip::<CreateBindingParams>(params),
            method::POLICY_BINDINGS_UPDATE => round_trip::<UpdateBindingParams>(params),
            method::POLICY_TEMPLATES_GET
            | method::POLICY_TEMPLATES_DELETE
            | method::POLICY_SCOPES_GET
            | method::POLICY_SCOPES_DELETE => round_trip::<RevisionParams>(params),
            method::POLICY_BINDINGS_GET | method::POLICY_BINDINGS_DELETE => {
                round_trip::<ResourceParams>(params)
            }
            method::POLICY_TEMPLATES_LIST
            | method::POLICY_SCOPES_LIST
            | method::POLICY_BINDINGS_LIST => round_trip::<ListParams>(params),
            unexpected => panic!("unregistered fixture method {unexpected}"),
        };
        assert_eq!(encoded, canonical, "noncanonical fixture for {method_name}");
    }
}

#[test]
fn policy_create_and_update_params_are_distinct_and_reuse_the_domain_template() {
    let create = json!({
        "policyName": "protect-important-files",
        "template": {
            "kind": "prevent_file_deletion",
            "files": ["/workspace/important"]
        }
    });
    let decoded: CreatePolicyParams = serde_json::from_value(create.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), create);

    let mut update = create.clone();
    update["policyId"] = json!("policy-1");
    let decoded: UpdatePolicyParams = serde_json::from_value(update.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), update);

    assert!(serde_json::from_value::<CreatePolicyParams>(update).is_err());
    assert!(serde_json::from_value::<UpdatePolicyParams>(create.clone()).is_err());

    for forbidden in ["revision", "canonicalPolicy", "templateDigest"] {
        let mut changed = create.clone();
        changed[forbidden] = json!(1);
        assert!(serde_json::from_value::<CreatePolicyParams>(changed).is_err());
    }

    let mut unknown_template_field = create;
    unknown_template_field["template"]["targetDsl"] = json!("not allowed");
    assert!(serde_json::from_value::<CreatePolicyParams>(unknown_template_field).is_err());
}

#[test]
fn scope_params_accept_only_new_authored_selectors() {
    let create = json!({"selector": {"kind": "pid", "pid": 4242}});
    serde_json::from_value::<CreateScopeParams>(create.clone()).unwrap();
    let update = json!({
        "scopeId": "scope-1",
        "selector": {"kind": "cgroup_id", "cgroupId": 99}
    });
    serde_json::from_value::<UpdateScopeParams>(update.clone()).unwrap();

    assert!(serde_json::from_value::<CreateScopeParams>(update).is_err());
    assert!(serde_json::from_value::<UpdateScopeParams>(create).is_err());

    for invalid in [
        json!({"selector": {"kind": "pid", "pid": 0}}),
        json!({"selector": {"kind": "cgroup_id", "cgroupId": 0}}),
        json!({
            "selector": {
                "kind": "legacy_execution_domain",
                "executionDomainId": "legacy-domain"
            }
        }),
        json!({
            "selector": {"kind": "pid", "pid": 4242},
            "template": {}
        }),
    ] {
        assert!(serde_json::from_value::<CreateScopeParams>(invalid).is_err());
    }

    let invalid_outbound = CreateScopeParams {
        selector: ScopeSelector::LegacyExecutionDomain {
            execution_domain_id: ResourceId::new("legacy-domain").unwrap(),
        },
    };
    assert!(serde_json::to_value(invalid_outbound).is_err());
}

#[test]
fn binding_params_reference_exact_policy_and_scope_revisions() {
    let create = json!({
        "policyId": "policy-1",
        "policyRevision": 2,
        "scopeId": "scope-1",
        "scopeRevision": 3
    });
    let decoded: CreateBindingParams = serde_json::from_value(create.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), create);

    let mut update = create.clone();
    update["bindingId"] = json!("binding-1");
    let decoded: UpdateBindingParams = serde_json::from_value(update.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), update);

    assert!(serde_json::from_value::<CreateBindingParams>(update).is_err());
    assert!(serde_json::from_value::<UpdateBindingParams>(create).is_err());

    for invalid in [
        json!({
            "policyId": "policy-1",
            "policyRevision": 0,
            "scopeId": "scope-1",
            "scopeRevision": 1
        }),
        json!({
            "policyId": "policy-1",
            "policyRevision": 1,
            "scopeId": "invalid/id",
            "scopeRevision": 1
        }),
        json!({
            "policyId": "policy-1",
            "policyRevision": 1,
            "scopeId": "scope-1",
            "scopeRevision": 1,
            "status": "READY"
        }),
    ] {
        assert!(serde_json::from_value::<CreateBindingParams>(invalid).is_err());
    }
}

#[test]
fn revision_and_pagination_wire_values_are_bounded() {
    let maximum = serde_json::from_value::<RevisionParams>(json!({
        "id": "policy-1",
        "revision": u32::MAX
    }))
    .unwrap();
    assert_eq!(maximum.revision.get(), u32::MAX);

    for invalid in [
        json!({"id": "policy-1", "revision": 0}),
        json!({"id": "policy-1", "revision": -1}),
        json!({"id": "policy-1", "revision": u64::from(u32::MAX) + 1}),
        json!({"id": "invalid/id", "revision": 1}),
    ] {
        assert!(serde_json::from_value::<RevisionParams>(invalid).is_err());
    }

    assert_eq!(
        serde_json::from_value::<ListParams>(json!({})).unwrap(),
        ListParams::default()
    );
    for invalid in [
        json!({"limit": 0}),
        json!({"limit": 1001}),
        json!({"limit": 1, "offset": -1}),
        json!({"limit": 1, "offset": u64::from(u32::MAX) + 1}),
    ] {
        assert!(serde_json::from_value::<ListParams>(invalid).is_err());
    }
}

#[test]
fn method_registry_contains_policy_scope_and_binding_methods() {
    use method::{BindingMethod, PapMethod, PolicyMethod, ScopeMethod};

    let expected = [
        PapMethod::Policy(PolicyMethod::Create),
        PapMethod::Policy(PolicyMethod::Update),
        PapMethod::Policy(PolicyMethod::Get),
        PapMethod::Policy(PolicyMethod::List),
        PapMethod::Policy(PolicyMethod::Delete),
        PapMethod::Scope(ScopeMethod::Create),
        PapMethod::Scope(ScopeMethod::Update),
        PapMethod::Scope(ScopeMethod::Get),
        PapMethod::Scope(ScopeMethod::List),
        PapMethod::Scope(ScopeMethod::Delete),
        PapMethod::Binding(BindingMethod::Create),
        PapMethod::Binding(BindingMethod::Update),
        PapMethod::Binding(BindingMethod::Get),
        PapMethod::Binding(BindingMethod::List),
        PapMethod::Binding(BindingMethod::Delete),
    ];
    for (method_name, pap_method) in method::PAP_METHODS.into_iter().zip(expected) {
        assert_eq!(
            method::resolve(method_name),
            Some(method::MethodId::Pap(pap_method))
        );
        let metadata = method::metadata(method_name).unwrap();
        assert_eq!(metadata.capability, method::Capability::Pap);
        assert_eq!(metadata.access, method::AccessPolicy::LocalPeer);
    }

    for absent in [
        "daemon.health",
        "policy.templates.put",
        "policy.scopes.put",
        "policy.bindings.put",
        "policy.operations.get",
        "policy.unregistered",
    ] {
        assert!(method::resolve(absent).is_none());
        assert!(method::metadata(absent).is_none());
        assert!(!method::is_pap(absent));
    }
}

#[test]
fn request_envelope_rejects_untrusted_metadata() {
    let envelope = json!({
        "method": method::POLICY_TEMPLATES_LIST,
        "params": {}
    });
    serde_json::from_value::<DaemonRequest>(envelope.clone()).unwrap();

    let mut unknown = envelope.clone();
    unknown["callerUid"] = json!(1000);
    assert!(serde_json::from_value::<DaemonRequest>(unknown).is_err());

    let mut premature_auth = envelope;
    premature_auth["auth"] = json!({"scheme": "bearer", "token": "not-supported"});
    assert!(serde_json::from_value::<DaemonRequest>(premature_auth).is_err());
}

#[test]
fn responses_have_mutually_exclusive_result_and_error_shapes() {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!("fixtures/daemon-responses.json"))
        .expect("daemon response fixtures must be valid JSON");

    for fixture in fixtures {
        let response = fixture["response"].clone();
        let decoded: DaemonResponse = serde_json::from_value(response.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            response,
            "noncanonical response fixture {}",
            fixture["name"]
        );
    }

    for invalid in [
        json!({"requestId": "request-1"}),
        json!({
            "requestId": "request-1",
            "result": {},
            "error": {"code": "internal", "message": "failed"}
        }),
        json!({"requestId": "request-1", "ok": true, "data": {}}),
        json!({"requestId": " ", "result": {}}),
        json!({
            "requestId": "request-1",
            "error": {"code": "INVALID-CODE", "message": "failed"}
        }),
    ] {
        assert!(serde_json::from_value::<DaemonResponse>(invalid).is_err());
    }

    let response: DaemonResponse = DaemonResponse::error(
        RequestId::new("request-2").unwrap(),
        error_code::INTERNAL,
        "daemon failed",
    );
    assert_eq!(response.request_id().to_string(), "request-2");
    match response {
        DaemonResponse::Error(response) => {
            assert_eq!(response.request_id.as_str(), "request-2");
            assert_eq!(response.error.code.as_str(), error_code::INTERNAL);
        }
        DaemonResponse::Success(_) => panic!("error constructor returned a success response"),
    }

    let future_code: ErrorCode = serde_json::from_value(json!("future_error")).unwrap();
    assert_eq!(future_code.as_str(), "future_error");
    assert_eq!(future_code.to_string(), "future_error");

    let success = DaemonResponse::success(
        RequestId::new("request-3").unwrap(),
        json!({"items": [], "total": 0}),
    );
    assert_eq!(success.request_id().as_str(), "request-3");

    for registered in [
        error_code::INVALID_REQUEST,
        error_code::INVALID_ARGUMENT,
        error_code::UNKNOWN_METHOD,
        error_code::PERMISSION_DENIED,
        error_code::NOT_FOUND,
        error_code::CONFLICT,
        error_code::RESOURCE_EXHAUSTED,
        error_code::DEADLINE_EXCEEDED,
        error_code::UNAVAILABLE,
        error_code::INTERNAL,
    ] {
        assert_eq!(ErrorCode::new(registered).unwrap().as_str(), registered);
    }
}

#[test]
fn request_envelope_requires_a_method_and_object_params() {
    let defaulted: DaemonRequest = serde_json::from_value(json!({
        "method": method::POLICY_TEMPLATES_LIST
    }))
    .unwrap();
    assert_eq!(defaulted.params, json!({}));

    for invalid in [
        json!({"method": "", "params": {}}),
        json!({"method": "  \t", "params": {}}),
        json!({"method": method::POLICY_TEMPLATES_LIST, "params": null}),
        json!({"method": method::POLICY_TEMPLATES_LIST, "params": []}),
        json!({"method": method::POLICY_TEMPLATES_LIST, "params": "invalid"}),
    ] {
        assert!(serde_json::from_value::<DaemonRequest>(invalid).is_err());
    }
}

#[test]
fn pap_results_wrap_complete_prepared_domain_structures() {
    let binding: PreparedBinding = serde_json::from_str(include_str!(
        "../../../policy/asc-policy-types/tests/fixtures/prepared-binding.json"
    ))
    .unwrap();
    let policy = binding.policy.clone();
    let scope = binding.scope.clone();
    let binding = BindingView {
        spec: binding,
        status: BindingStatus::PendingApply,
    };

    round_trip_value(&CreatePolicyResult {
        policy: policy.clone(),
    });
    round_trip_value(&UpdatePolicyResult {
        policy: policy.clone(),
    });
    round_trip_value(&GetPolicyResult {
        policy: policy.clone(),
    });
    round_trip_value(&ListPoliciesResult {
        items: vec![policy.clone()],
        total: 1,
    });
    round_trip_value(&DeletePolicyResult { policy });

    round_trip_value(&CreateScopeResult {
        scope: scope.clone(),
    });
    round_trip_value(&UpdateScopeResult {
        scope: scope.clone(),
    });
    round_trip_value(&GetScopeResult {
        scope: scope.clone(),
    });
    round_trip_value(&ListScopesResult {
        items: vec![scope.clone()],
        total: 1,
    });
    round_trip_value(&DeleteScopeResult { scope });

    round_trip_value(&CreateBindingResult {
        binding: binding.clone(),
    });
    round_trip_value(&UpdateBindingResult {
        binding: binding.clone(),
    });
    round_trip_value(&GetBindingResult {
        binding: binding.clone(),
    });
    round_trip_value(&ListBindingsResult {
        items: vec![binding.clone()],
        total: 1,
    });
    let pending_delete = BindingView {
        status: BindingStatus::PendingDelete,
        ..binding
    };
    round_trip_value(&DeleteBindingResult {
        binding: pending_delete,
    });
}

fn round_trip<T>(value: Value) -> Value
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let decoded: T = serde_json::from_value(value).unwrap();
    serde_json::to_value(decoded).unwrap()
}

fn round_trip_value<T>(value: &T)
where
    T: serde::de::DeserializeOwned + serde::Serialize + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_value(value).unwrap();
    let decoded: T = serde_json::from_value(encoded).unwrap();
    assert_eq!(&decoded, value);
}
