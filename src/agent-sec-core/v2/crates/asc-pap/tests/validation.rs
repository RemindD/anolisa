use std::sync::Arc;

use asc_pap::{PapError, PapRepository, PapService};
use asc_pap_repository_memory::ProcessLocalPapRepository;
use asc_policy_types::Validate;
use asc_policy_types::authoring::PolicyTemplate;
use asc_policy_types::binding::PreparedBinding;
use asc_policy_types::error::ValidationError;
use asc_policy_types::scope::ScopeSelector;

fn binding() -> PreparedBinding {
    serde_json::from_str(include_str!(
        "../../asc-policy-types/tests/fixtures/prepared-binding.json"
    ))
    .unwrap()
}

#[test]
fn shared_name_validation_preserves_pap_and_snapshot_errors() {
    let repository = Arc::new(ProcessLocalPapRepository::default());
    let pap = PapService::new(repository.clone());
    for (name, reason) in [
        (String::new(), "must contain a visible character"),
        (" \t\n".into(), "must contain a visible character"),
        (" ".repeat(257), "must contain a visible character"),
        ("a".repeat(257), "must not exceed 256 bytes"),
        ("é".repeat(129), "must not exceed 256 bytes"),
        (
            format!("{}\n", "a".repeat(256)),
            "must not exceed 256 bytes",
        ),
        ("visible\n".into(), "must not contain control characters"),
    ] {
        let mut policy = binding().policy;
        policy.policy_name.clone_from(&name);
        assert_eq!(
            pap.create_policy(&name, &policy.template),
            Err(PapError::InvalidPolicyName(reason.into()))
        );
        assert_eq!(
            policy.validate(),
            Err(ValidationError::new(
                "policyName",
                "must contain a visible, control-free value of at most 256 bytes"
            ))
        );
    }
    assert_eq!(repository.list_policies(100, 0).unwrap().total, 0);
}

#[test]
fn validated_construction_still_produces_valid_policy_and_scope_snapshots() {
    let repository = Arc::new(ProcessLocalPapRepository::default());
    let pap = PapService::new(repository);
    for name in ["a".repeat(256), "é".repeat(128), " visible name ".into()] {
        let policy = pap
            .create_policy(&name, &binding().policy.template)
            .unwrap();
        assert_eq!(policy.policy_name, name);
        policy.validate().unwrap();
    }
    let mut scope = asc_policy_types::scope::PreparedScope {
        scope_id: binding().scope.scope_id,
        selector: ScopeSelector::Pid { pid: 1 },
        policy_snapshots: vec![binding().policy],
        status: asc_policy_types::scope::ScopeStatus::Active,
    };
    scope.validate().unwrap();
    scope.policy_snapshots.clear();
    assert!(scope.validate().is_err());
    for (selector, path) in [
        (ScopeSelector::Pid { pid: 0 }, "pid"),
        (ScopeSelector::CgroupId { cgroup_id: 0 }, "cgroupId"),
    ] {
        assert_eq!(
            pap.create_scope_assignment(&selector, &[]),
            Err(PapError::InvalidScope(ValidationError::new(
                path,
                "must be positive"
            )))
        );
    }
}

#[test]
fn invalid_template_rejects_create_and_update_without_writing() {
    let repository = Arc::new(ProcessLocalPapRepository::default());
    let pap = PapService::new(repository.clone());
    let saved = pap
        .create_policy("policy", &binding().policy.template)
        .unwrap();
    for (template, path) in [
        (
            PolicyTemplate::PreventFileDeletion { files: vec![] },
            "template.files",
        ),
        (
            PolicyTemplate::PreventFileDeletion {
                files: vec!["relative".into()],
            },
            "template.files[0]",
        ),
        (
            PolicyTemplate::PreventFileDeletion {
                files: vec!["/same".into(), "/same".into()],
            },
            "template.files[1]",
        ),
        (
            PolicyTemplate::HighSensitivityReadDeny {
                files: vec!["/secret".into()],
            },
            "template.kind",
        ),
    ] {
        for result in [
            pap.create_policy("invalid", &template),
            pap.update_policy(&saved.policy_id, "invalid", &template),
        ] {
            let Err(PapError::InvalidPolicy(error)) = result else {
                panic!("invalid template was admitted");
            };
            assert_eq!(error.path, path);
        }
        assert_eq!(
            repository.list_policies(100, 0).unwrap().items,
            vec![saved.clone()]
        );
    }
}
