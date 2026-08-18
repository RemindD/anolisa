use asc_policy_engine::{
    EngineError, PolicyTemplate, TemplateEnvelope, TrustedDestination, compose_policies,
    lower_template,
};
use asc_policy_types::Validate;
use asc_policy_types::identifiers::{PolicyId, Revision};
use asc_policy_types::ir::{
    ActivationRequirement, Expression, FlowPropagation, ResourceOperation, ResourceTarget,
    RuntimeFailurePolicy, SemanticAtom,
};
use asc_policy_types::resource::{FileResolution, ResourceSelector};
use serde_json::json;

fn policy_id(value: &str) -> PolicyId {
    PolicyId::new(value).unwrap()
}

fn revision(value: u64) -> Revision {
    Revision::new(value).unwrap()
}

fn files(pattern: &str) -> Vec<String> {
    vec![pattern.to_owned()]
}

fn template(policy: &str, kind: PolicyTemplate) -> TemplateEnvelope {
    TemplateEnvelope {
        policy_id: policy_id(policy),
        revision: revision(1),
        template: kind,
    }
}

#[test]
fn high_sensitivity_template_lowers_to_read_deny() {
    let policy = lower_template(template(
        "high-sensitive",
        PolicyTemplate::HighSensitivityReadDeny {
            files: files("/secrets/**"),
        },
    ))
    .unwrap();

    policy.validate().unwrap();
    let Expression::Atom {
        atom: SemanticAtom::ResourceOperation { operation, .. },
    } = &policy.payload.rules[0].when
    else {
        panic!("expected one resource operation atom");
    };
    assert_eq!(*operation, ResourceOperation::Read);
    let ResourceSelector::File { matchers } = &policy.payload.resources[0].selector else {
        panic!("expected a file resource set");
    };
    assert!(matches!(
        matchers[0].resolution,
        FileResolution::FinalObject {
            follow_final_symlink: true,
            match_hardlink_identity: true
        }
    ));
}

#[test]
fn deletion_template_lowers_to_namespace_mutation() {
    let policy = lower_template(template(
        "prevent-delete",
        PolicyTemplate::PreventFileDeletion {
            files: files("/important/**"),
        },
    ))
    .unwrap();

    let Expression::Atom {
        atom: SemanticAtom::ResourceOperation { operation, .. },
    } = &policy.payload.rules[0].when
    else {
        panic!("expected one resource operation atom");
    };
    assert_eq!(*operation, ResourceOperation::NamespaceMutation);
    let ResourceSelector::File { matchers } = &policy.payload.resources[0].selector else {
        panic!("expected a file resource set");
    };
    assert_eq!(
        matchers[0].resolution,
        FileResolution::FinalObject {
            follow_final_symlink: true,
            match_hardlink_identity: true,
        }
    );
    assert_eq!(
        policy.payload.rules[0].enforcement.required_evidence,
        vec![
            asc_policy_types::ir::EvidenceRequirement::BindingReady,
            asc_policy_types::ir::EvidenceRequirement::OperationDenied,
        ]
    );
}

#[test]
fn low_sensitivity_template_allows_read_and_denies_direct_untrusted_flow() {
    let policy = lower_template(template(
        "low-sensitive-egress",
        PolicyTemplate::LowSensitivityEgress {
            files: files("/customer-data/**"),
            trusted_destinations: vec![TrustedDestination::Host {
                pattern: "audit.example.com".to_owned(),
                ports: vec![443],
            }],
        },
    ))
    .unwrap();

    let Expression::Atom {
        atom:
            SemanticAtom::InformationFlow {
                destination,
                propagation,
                ..
            },
    } = &policy.payload.rules[0].when
    else {
        panic!("expected one information-flow atom");
    };
    assert_eq!(*propagation, FlowPropagation::Direct);
    assert!(matches!(destination, ResourceTarget::Except { .. }));
    assert!(policy.payload.rules.iter().all(|rule| !matches!(
        &rule.when,
        Expression::Atom {
            atom: SemanticAtom::ResourceOperation {
                operation: ResourceOperation::Read,
                ..
            }
        }
    )));
}

#[test]
fn composition_namespaces_local_ids_and_merges_activation() {
    let mut high = lower_template(template(
        "high-sensitive",
        PolicyTemplate::HighSensitivityReadDeny {
            files: files("/secrets/**"),
        },
    ))
    .unwrap();
    high.payload.activation = ActivationRequirement::BeforeWorkerStart;
    let deletion = lower_template(template(
        "prevent-delete",
        PolicyTemplate::PreventFileDeletion {
            files: files("/important/**"),
        },
    ))
    .unwrap();

    let composed =
        compose_policies(policy_id("effective-demo"), revision(1), &[high, deletion]).unwrap();

    composed.validate().unwrap();
    assert_eq!(
        composed.payload.activation,
        ActivationRequirement::BeforeWorkerStart
    );
    assert_eq!(composed.payload.resources.len(), 2);
    assert_eq!(composed.payload.rules.len(), 2);
    for rule in &composed.payload.rules {
        assert!(rule.id.as_str().contains(':'));
    }
}

#[test]
fn composition_rejects_conflicting_immutable_revision_and_failure_semantics() {
    let high = lower_template(template(
        "same-policy",
        PolicyTemplate::HighSensitivityReadDeny {
            files: files("/secrets/**"),
        },
    ))
    .unwrap();
    let deletion = lower_template(template(
        "same-policy",
        PolicyTemplate::PreventFileDeletion {
            files: files("/important/**"),
        },
    ))
    .unwrap();
    assert!(matches!(
        compose_policies(
            policy_id("effective-conflict"),
            revision(1),
            &[high.clone(), deletion]
        ),
        Err(EngineError::ConflictingRevision { .. })
    ));

    let mut other = lower_template(template(
        "other-policy",
        PolicyTemplate::PreventFileDeletion {
            files: files("/important/**"),
        },
    ))
    .unwrap();
    other.payload.failure_policy.runtime = RuntimeFailurePolicy::FreezeBinding;
    assert!(matches!(
        compose_policies(policy_id("effective-failure"), revision(1), &[high, other]),
        Err(EngineError::IncompatibleFailurePolicy)
    ));
}

#[test]
fn template_wire_shape_rejects_unknown_fields() {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/template-high-sensitive-read.json"
    ))
    .unwrap();
    let decoded: TemplateEnvelope = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), value);

    let mut unknown = value;
    unknown["unexpected"] = json!(true);
    assert!(serde_json::from_value::<TemplateEnvelope>(unknown).is_err());
}
