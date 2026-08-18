//! Binding-time Canonical read-policy translation and mapping reports.

use asc_policy_types::identifiers::{Digest, PepInstanceId, TargetId};
use asc_policy_types::ir::{
    ActivationRequirement, Expression, ResourceOperation, ResourceTarget, SemanticAtom,
};
use asc_policy_types::mapping::{
    AtomMapping, GuaranteeMapping, MappingRelation, MappingReport, RuleMapping,
};
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::protocol::Diagnostic;
use asc_policy_types::reconcile::ReadyBindingRequest;
use asc_policy_types::resource::{PathMatcher, ResourceSelector};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

use super::CanonicalError;
use crate::enforcement::EnforcementStoreError;

#[derive(Clone, Copy, Debug)]
pub(super) enum CanonicalTarget {
    ActPlane,
    #[cfg(test)]
    MockExact,
}

impl CanonicalTarget {
    pub(super) fn actplane() -> Self {
        Self::ActPlane
    }

    #[cfg(test)]
    pub(super) fn mock_exact() -> Self {
        Self::MockExact
    }

    fn target_id(self) -> &'static str {
        match self {
            Self::ActPlane => "actplane-v1",
            #[cfg(test)]
            Self::MockExact => "mock-pep-v1",
        }
    }

    fn pep_instance_id(self) -> &'static str {
        match self {
            Self::ActPlane => "actplane-pep-1",
            #[cfg(test)]
            Self::MockExact => "mock-pep-1",
        }
    }

    fn resource_operation_relation(self, policy: &PolicyEnvelope) -> MappingRelation {
        match self {
            Self::ActPlane
                if policy.payload.rules.iter().all(|rule| {
                    matches!(
                        &rule.when,
                        Expression::Atom {
                            atom: SemanticAtom::ResourceOperation {
                                operation: ResourceOperation::NamespaceMutation,
                                ..
                            }
                        }
                    )
                }) =>
            {
                MappingRelation::Exact
            }
            Self::ActPlane => MappingRelation::Narrower,
            #[cfg(test)]
            Self::MockExact => MappingRelation::Exact,
        }
    }
}

pub(super) struct CompiledBinding {
    pub(super) dsl: Option<String>,
    pub(super) mapping: MappingReport,
    pub(super) mapping_digest: Digest,
    pub(super) target_digest: Option<Digest>,
    pub(super) pep_instance_id: PepInstanceId,
}

pub(super) fn compile_binding(
    target: CanonicalTarget,
    ready: &ReadyBindingRequest,
    policy: &PolicyEnvelope,
) -> Result<CompiledBinding, CanonicalError> {
    let target_id = TargetId::new(target.target_id()).map_err(CanonicalError::Internal)?;
    let pep_instance_id =
        PepInstanceId::new(target.pep_instance_id()).map_err(CanonicalError::Internal)?;
    let unsupported = unsupported_policy(policy);
    let relation = if unsupported.is_some() {
        MappingRelation::Unsupported
    } else {
        target.resource_operation_relation(policy)
    };
    let diagnostic = unsupported.map(|(code, message)| Diagnostic {
        code: code.into(),
        path: Some("when.atom".into()),
        message: message.into(),
    });
    let dsl = if relation == MappingRelation::Unsupported {
        None
    } else {
        Some(compile_resource_operation_dsl(policy)?)
    };
    let mapping_digest = digest_serializable(&(
        ready.binding_id.as_str(),
        policy.policy_id.as_str(),
        policy.revision.get(),
        target.target_id(),
        relation,
        ready.scope_digest.as_str(),
        dsl.as_deref(),
    ))?;
    let target_digest = dsl
        .as_ref()
        .map(|value| digest_bytes(value.as_bytes()))
        .transpose()?;
    let rules = policy
        .payload
        .rules
        .iter()
        .map(|rule| RuleMapping {
            rule_id: rule.id.clone(),
            relation,
            atoms: vec![AtomMapping {
                expression_path: "when.atom".into(),
                relation,
                diagnostics: diagnostic.clone().into_iter().collect(),
            }],
            diagnostics: Vec::new(),
        })
        .collect();
    let mapping = MappingReport {
        binding_id: ready.binding_id.clone(),
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.revision,
        target_id,
        policy_relation: relation,
        mapping_digest: mapping_digest.clone(),
        capability_snapshot_digest: ready.precondition.capability_snapshot_digest.clone(),
        rules,
        guarantees: GuaranteeMapping {
            relation: MappingRelation::Exact,
            diagnostics: Vec::new(),
        },
    };
    Ok(CompiledBinding {
        dsl,
        mapping,
        mapping_digest,
        target_digest,
        pep_instance_id,
    })
}

fn unsupported_policy(policy: &PolicyEnvelope) -> Option<(&'static str, &'static str)> {
    if policy.payload.activation != ActivationRequirement::PostAttachAllowed {
        return Some((
            "UNSUPPORTED_ACTIVATION",
            "the current AgentSight integration only supports post-attach activation",
        ));
    }
    for rule in &policy.payload.rules {
        match &rule.when {
            Expression::Atom {
                atom:
                    SemanticAtom::ResourceOperation {
                        operation: ResourceOperation::Read | ResourceOperation::NamespaceMutation,
                        target: ResourceTarget::In { resource_set },
                    },
            } if policy.payload.resources.iter().any(|resource| {
                &resource.id == resource_set
                    && matches!(resource.selector, ResourceSelector::File { .. })
            }) => {}
            Expression::Atom {
                atom: SemanticAtom::InformationFlow { .. },
            } => {
                return Some((
                    "UNSUPPORTED_DIRECT_FLOW",
                    "target cannot reliably establish direct information flow",
                ));
            }
            _ => {
                return Some((
                    "UNSUPPORTED_CANONICAL_RULE",
                    "the selected target cannot translate this Canonical rule shape",
                ));
            }
        }
    }
    None
}

fn compile_resource_operation_dsl(policy: &PolicyEnvelope) -> Result<String, CanonicalError> {
    let mut dsl = String::from("source AGENT = exec \"**\"\n");
    for (rule_index, rule) in policy.payload.rules.iter().enumerate() {
        let Expression::Atom {
            atom:
                SemanticAtom::ResourceOperation {
                    operation,
                    target: ResourceTarget::In { resource_set },
                },
        } = &rule.when
        else {
            return Err(CanonicalError::Internal(
                "supported resource-operation policy changed before DSL generation".into(),
            ));
        };
        let resource = policy
            .payload
            .resources
            .iter()
            .find(|resource| &resource.id == resource_set)
            .ok_or_else(|| {
                CanonicalError::Internal("validated resource reference is missing".into())
            })?;
        let ResourceSelector::File { matchers } = &resource.selector else {
            return Err(CanonicalError::Internal(
                "supported resource-operation policy changed resource kind".into(),
            ));
        };
        let (rule_kind, dsl_operation, reason) = match operation {
            ResourceOperation::Read => ("read", "open", "Canonical high-sensitivity read policy"),
            ResourceOperation::NamespaceMutation => (
                "namespace-mutation",
                "unlink",
                "Canonical namespace-mutation policy",
            ),
            _ => {
                return Err(CanonicalError::Internal(
                    "unsupported resource operation reached DSL generation".into(),
                ));
            }
        };
        for (matcher_index, matcher) in matchers.iter().enumerate() {
            let path = match &matcher.path {
                PathMatcher::Exact { path } | PathMatcher::Glob { pattern: path } => path.clone(),
                PathMatcher::Prefix { path } if path == "/" => "/**".into(),
                PathMatcher::Prefix { path } => format!("{path}/**"),
            };
            validate_dsl_literal(&path)?;
            dsl.push_str(&format!(
                "rule canonical-{rule_kind}-{rule_index}-{matcher_index}:\n  block {dsl_operation} file \"{path}\" if AGENT\n  because \"{reason}\"\n"
            ));
        }
    }
    Ok(dsl)
}

fn validate_dsl_literal(value: &str) -> Result<(), CanonicalError> {
    if value.is_empty()
        || value.len() >= 127
        || value
            .chars()
            .any(|character| character == '"' || character == '\\' || character.is_control())
    {
        return Err(CanonicalError::Invalid {
            path: "policy.payload.resources.matchers.path".into(),
            message: "path contains characters or length unsupported by the pinned DSL".into(),
        });
    }
    Ok(())
}

fn digest_serializable(value: &impl Serialize) -> Result<Digest, CanonicalError> {
    let bytes = serde_json::to_vec(value).map_err(EnforcementStoreError::from)?;
    digest_bytes(&bytes)
}

fn digest_bytes(bytes: &[u8]) -> Result<Digest, CanonicalError> {
    let hash = Sha256::digest(bytes);
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in hash {
        value.push_str(&format!("{byte:02x}"));
    }
    Digest::new(value).map_err(CanonicalError::Internal)
}
