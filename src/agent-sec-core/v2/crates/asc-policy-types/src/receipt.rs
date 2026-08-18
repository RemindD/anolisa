//! Cursor-based deployment, enforcement, and effect receipt contracts.

use serde::{Deserialize, Serialize};

use crate::error::{Validate, ValidationError};
use crate::identifiers::{
    BindingId, Digest, ExecutionDomainId, OperationId, PepInstanceId, PolicyId, ReceiptId,
    ResourceSetId, Revision, RuleId, TargetId,
};

/// Evidence category. These categories must not be collapsed into one success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    /// Evidence that a target artifact was installed or removed.
    Deployment,
    /// Evidence that a synchronous enforcement point made a decision.
    Enforcement,
    /// Independent evidence about the resulting system effect.
    Effect,
}

/// Versioned receipt envelope returned by `AgentSight`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    /// Stable receipt identity used for deduplication.
    pub receipt_id: ReceiptId,
    /// Evidence category.
    #[serde(rename = "type")]
    pub receipt_type: ReceiptType,
    /// Monotonic per-PEP sequence used to detect gaps.
    pub sequence: u64,
    /// `AgentSight` operation that caused the deployment, when applicable.
    pub operation_id: Option<OperationId>,
    /// Canonical policy identity.
    pub policy_id: Option<PolicyId>,
    /// Canonical policy revision.
    pub policy_revision: Option<Revision>,
    /// Concrete binding identity.
    pub binding_id: Option<BindingId>,
    /// Concrete scope digest.
    pub scope_digest: Option<Digest>,
    /// Stable reference to a Canonical IR Rule.
    pub rule_id: Option<RuleId>,
    /// Stable path to the matched Atom inside the Rule expression.
    pub expression_path: Option<String>,
    /// Referenced resource set, without retaining resource content.
    pub resource_set_id: Option<ResourceSetId>,
    /// Binding-time mapping digest.
    pub mapping_digest: Option<Digest>,
    /// Target adapter/backend identity.
    pub target_id: Option<TargetId>,
    /// `AgentSight`-generated target artifact digest.
    pub target_digest: Option<Digest>,
    /// Enforcement-point instance that produced the evidence.
    pub pep_instance_id: PepInstanceId,
    /// Protected execution domain.
    pub execution_domain_id: Option<ExecutionDomainId>,
    /// Normalized operation such as `read` or `namespace_mutation`.
    pub operation: String,
    /// Synchronous block point, when applicable.
    pub block_point: Option<String>,
    /// Actual observed result such as `blocked`.
    pub actual_result: String,
    /// Digest of the original lower-level receipt, if retained separately.
    pub raw_receipt_digest: Option<Digest>,
    /// RFC 3339 event time.
    pub occurred_at: String,
}

impl Validate for Receipt {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.sequence == 0 {
            return Err(ValidationError::new(
                "sequence",
                "must be greater than zero",
            ));
        }
        if self.operation.trim().is_empty()
            || self.actual_result.trim().is_empty()
            || self.occurred_at.trim().is_empty()
        {
            return Err(ValidationError::new(
                "receipt",
                "operation, actualResult, and occurredAt must not be empty",
            ));
        }
        if self.receipt_type == ReceiptType::Enforcement
            && (self.policy_id.is_none()
                || self.policy_revision.is_none()
                || self.binding_id.is_none()
                || self.scope_digest.is_none()
                || self.rule_id.is_none()
                || self.expression_path.is_none()
                || self.mapping_digest.is_none()
                || self.target_id.is_none()
                || self.target_digest.is_none()
                || self.execution_domain_id.is_none())
        {
            return Err(ValidationError::new(
                "receipt",
                "enforcement receipts require policy, Rule/Atom, binding, scope, mapping, target, and execution-domain correlation",
            ));
        }
        Ok(())
    }
}

/// Query for one page of the persistent receipt stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullReceiptsRequest {
    /// Cursor returned by the preceding page, absent for the first page.
    pub cursor: Option<String>,
    /// Maximum receipts requested in the page.
    pub limit: u16,
}

impl Validate for PullReceiptsRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.limit == 0 || self.limit > 1_000 {
            return Err(ValidationError::new("limit", "must be between 1 and 1000"));
        }
        if self.cursor.as_ref().is_some_and(String::is_empty) {
            return Err(ValidationError::new(
                "cursor",
                "must be non-empty when present",
            ));
        }
        Ok(())
    }
}

/// One page from the persistent receipt stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullReceiptsResponse {
    /// Cursor for the next request.
    pub next_cursor: String,
    /// Ordered receipts in this page.
    pub receipts: Vec<Receipt>,
}
