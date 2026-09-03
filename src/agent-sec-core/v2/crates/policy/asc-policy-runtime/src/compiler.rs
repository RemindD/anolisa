use asc_pap::PolicyCompiler;
use asc_policy_types::Validate;
use asc_policy_types::authoring::{PolicyTemplate, TemplateEnvelope};
use asc_policy_types::error::ValidationError;
use asc_policy_types::identifiers::{ProfileId, ResourceSetId, RuleId};
use asc_policy_types::ir::{
    ActivationRequirement, CanonicalPolicyIr, DecisionTiming, EvidenceRequirement, Expression,
    FailurePolicy, Obligation, ResourceOperation, ResourceTarget, RestrictiveDecision,
    RuleEnforcement, RuleIr, RuleOutcome, RuntimeFailurePolicy, SemanticAtom, SubjectRemediation,
    UpdateFailurePolicy,
};
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::profile::{IR_SCHEMA_VERSION_V1, PROFILE_V1ALPHA1_DEMO1};
use asc_policy_types::resource::{
    FileMatcher, FileResolution, PathMatcher, ResourceSelector, ResourceSet,
};

/// POC compiler for the one Policy kind accepted by the current `AgentSight` Adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct PocPolicyCompiler;

impl PolicyCompiler for PocPolicyCompiler {
    fn lower(&self, template: &TemplateEnvelope) -> Result<PolicyEnvelope, ValidationError> {
        let PolicyTemplate::PreventFileDeletion { files } = &template.template else {
            return Err(ValidationError::new(
                "template.kind",
                "the POC compiler supports only prevent_file_deletion",
            ));
        };
        if files.is_empty() {
            return Err(ValidationError::new("template.files", "must not be empty"));
        }

        let resource_id = ResourceSetId::new("protected-file-entries")
            .map_err(|message| ValidationError::new("payload.resources[0].id", message))?;
        let matchers = files
            .iter()
            .map(|path| FileMatcher {
                path: if path.contains(['*', '?']) {
                    PathMatcher::Glob {
                        pattern: path.clone(),
                    }
                } else {
                    PathMatcher::Exact { path: path.clone() }
                },
                resolution: FileResolution::PathEntry,
            })
            .collect();
        let policy = PolicyEnvelope {
            ir_schema_version: IR_SCHEMA_VERSION_V1,
            profile_id: ProfileId::new(PROFILE_V1ALPHA1_DEMO1)
                .map_err(|message| ValidationError::new("profileId", message))?,
            policy_id: template.policy_id.clone(),
            revision: template.revision,
            payload_digest: None,
            payload: CanonicalPolicyIr {
                resources: vec![ResourceSet {
                    id: resource_id.clone(),
                    selector: ResourceSelector::File { matchers },
                }],
                rules: vec![RuleIr {
                    id: RuleId::new("deny-protected-file-deletion")
                        .map_err(|message| ValidationError::new("payload.rules[0].id", message))?,
                    when: Expression::Atom {
                        atom: SemanticAtom::ResourceOperation {
                            operation: ResourceOperation::Delete,
                            target: ResourceTarget::In {
                                resource_set: resource_id,
                            },
                        },
                    },
                    outcome: RuleOutcome {
                        decision: RestrictiveDecision::Deny,
                        obligations: vec![Obligation::Audit, Obligation::EmitReceipt],
                        remediation: SubjectRemediation::None,
                    },
                    enforcement: RuleEnforcement {
                        decision_timing: DecisionTiming::PreEffect,
                        required_evidence: vec![
                            EvidenceRequirement::BindingReady,
                            EvidenceRequirement::OperationDenied,
                        ],
                    },
                }],
                activation: ActivationRequirement::PostAttachAllowed,
                failure_policy: FailurePolicy {
                    runtime: RuntimeFailurePolicy::FailClosed,
                    update: UpdateFailurePolicy::KeepLastKnownGood,
                },
            },
        };
        policy.validate()?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use asc_foundation_types::Revision;
    use asc_policy_types::authoring::{PolicyTemplate, TemplateEnvelope};
    use asc_policy_types::identifiers::PolicyId;
    use asc_policy_types::ir::{ResourceOperation, SemanticAtom};
    use asc_policy_types::resource::FileResolution;

    use super::*;

    #[test]
    fn lowers_the_unchanged_pcp_template_to_the_current_adapter_contract() {
        let template: PolicyTemplate = serde_json::from_str(include_str!(
            "../../../../fixtures/pap/prevent-file-deletion.json"
        ))
        .unwrap();
        let envelope = TemplateEnvelope {
            policy_id: PolicyId::new("prevent-file-deletion").unwrap(),
            revision: Revision::new(1).unwrap(),
            template,
        };

        let policy = PocPolicyCompiler.lower(&envelope).unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../fixtures/compiler/prevent-file-deletion.policy.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(&policy).unwrap(), expected);
        assert!(policy.payload.resources.iter().all(|resource| {
            let ResourceSelector::File { matchers } = &resource.selector else {
                return false;
            };
            matchers
                .iter()
                .all(|matcher| matcher.resolution == FileResolution::PathEntry)
        }));
        assert!(policy.payload.rules.iter().all(|rule| matches!(
            &rule.when,
            Expression::Atom {
                atom: SemanticAtom::ResourceOperation {
                    operation: ResourceOperation::Delete,
                    ..
                }
            }
        )));
    }

    #[test]
    fn rejects_policy_kinds_outside_the_poc_slice() {
        let envelope = TemplateEnvelope {
            policy_id: PolicyId::new("unsupported").unwrap(),
            revision: Revision::new(1).unwrap(),
            template: PolicyTemplate::HighSensitivityReadDeny {
                files: vec!["/secret".to_owned()],
            },
        };

        let error = PocPolicyCompiler.lower(&envelope).unwrap_err();
        assert_eq!(error.path, "template.kind");
    }
}
