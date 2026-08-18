//! Stable lifecycle and semantic mapping states.

use serde::{Deserialize, Serialize};

use crate::identifiers::{BindingId, Digest, PolicyId, Revision, RuleId, TargetId};
use crate::protocol::Diagnostic;

/// Relationship between requested semantics and the effective target policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingRelation {
    /// Effective semantics are equivalent to the request.
    Exact,
    /// Effective authority is narrower than requested.
    Narrower,
    /// Effective authority is wider than requested.
    Wider,
    /// Effective and requested semantics both add and omit authority.
    Incomparable,
    /// The target cannot implement or prove the semantics.
    Unsupported,
    /// The input is structurally or semantically invalid.
    Invalid,
}

/// Desired state of a reconciled policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDesiredState {
    /// Policy must be available for binding references.
    Present,
    /// Policy must not exist.
    Absent,
}

/// Current state of a reconciled policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyState {
    /// Policy is validated and available for bindings.
    Available,
    /// Desired and current state already match.
    NoChange,
    /// Validation rejected the policy.
    Rejected,
    /// Current state cannot be confirmed.
    Unknown,
    /// Policy is absent.
    Absent,
}

/// Desired state of a reconciled binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingDesiredState {
    /// The Effective Policy Snapshot must protect the execution domain.
    Ready,
    /// The binding must be removed after draining.
    Absent,
}

/// Current state of a reconciled binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingState {
    /// Installation is in progress.
    Installing,
    /// All required enforcement points are ready.
    BindingReady,
    /// Desired and current state already match.
    NoChange,
    /// A narrower mapping requires explicit approval.
    ApprovalRequired,
    /// A wider mapping requires a new authorization decision.
    ReauthorizationRequired,
    /// The requested binding cannot be activated.
    Rejected,
    /// Current state cannot be confirmed.
    Unknown,
    /// The execution domain or receipt stream is still draining.
    Draining,
    /// Binding is absent.
    Absent,
}

/// Mapping result for one semantic Atom in an expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomMapping {
    /// Stable JSON-style path from the Rule to the Atom.
    pub expression_path: String,
    /// Requested-to-effective semantic relation.
    pub relation: MappingRelation,
    /// Atom-specific diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Mapping result for one Canonical IR Rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleMapping {
    /// Policy-local Rule identity.
    pub rule_id: RuleId,
    /// Relation after composing the Rule expression and outcome.
    pub relation: MappingRelation,
    /// Per-Atom mapping evidence.
    pub atoms: Vec<AtomMapping>,
    /// Rule-level diagnostics, including outcome mismatches.
    pub diagnostics: Vec<Diagnostic>,
}

/// Independent mapping result for timing, evidence, and failure guarantees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeMapping {
    /// Requested-to-effective semantic relation.
    pub relation: MappingRelation,
    /// Guarantee-specific diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Complete binding-time semantic mapping report for one policy and target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MappingReport {
    /// Binding whose target compilation produced this report.
    pub binding_id: BindingId,
    /// Canonical policy identity.
    pub policy_id: PolicyId,
    /// Canonical policy revision.
    pub policy_revision: Revision,
    /// Target adapter/backend identity.
    pub target_id: TargetId,
    /// Relation after composing Rule and guarantee mappings.
    pub policy_relation: MappingRelation,
    /// Digest over the canonical mapping report.
    pub mapping_digest: Digest,
    /// Immutable capability snapshot used during compilation.
    pub capability_snapshot_digest: Digest,
    /// Per-Rule mapping results.
    pub rules: Vec<RuleMapping>,
    /// Timing, evidence, obligation, remediation, and failure mapping.
    pub guarantees: GuaranteeMapping,
}
