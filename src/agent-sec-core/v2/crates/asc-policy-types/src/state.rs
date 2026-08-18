//! Health, capability, operation, policy, and binding current-state contracts.

use serde::{Deserialize, Serialize};

use crate::identifiers::{
    AgentSightInstanceId, BindingId, Digest, OperationId, PolicyId, ProfileId, TargetId,
};
use crate::ir::{
    ActivationRequirement, DecisionTiming, EvidenceRequirement, FlowPropagation, Obligation,
    ResourceOperation, RuntimeFailurePolicy, SubjectRemediation, UpdateFailurePolicy,
};
use crate::mapping::{BindingState, MappingRelation, PolicyState};
use crate::profile::{AtomKind, ExpressionKind};
use crate::protocol::ProtocolError;
use crate::reconcile::{ReconcileBindingResponse, ReconcilePolicyResponse};
use crate::resource::{FileResolution, ResourceKind};

/// `AgentSight` service identity and readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceState {
    /// Whether the service can accept reconciliation requests.
    pub ready: bool,
    /// API contract version, currently `agentsight.enforcement/v1`.
    pub api_version: String,
    /// Stable server instance identity.
    pub agent_sight_instance_id: AgentSightInstanceId,
}

/// One immutable capability-matrix entry for a target and IR profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityEntry {
    /// Target adapter/backend identity.
    pub target_id: TargetId,
    /// Immutable Canonical IR profile.
    pub profile_id: ProfileId,
    /// Atom categories understood by the adapter.
    pub atom_kinds: Vec<AtomKind>,
    /// Resource domains understood by the adapter.
    pub resource_kinds: Vec<ResourceKind>,
    /// Resource operations implemented by the adapter.
    pub resource_operations: Vec<ResourceOperation>,
    /// Information-flow propagation levels implemented by the adapter.
    pub flow_propagations: Vec<FlowPropagation>,
    /// Expression shapes implemented by the adapter.
    pub expression_kinds: Vec<ExpressionKind>,
    /// File object-resolution semantics implemented by the adapter.
    pub file_resolutions: Vec<FileResolution>,
    /// Decision timing guarantees implemented by the adapter.
    pub decision_timings: Vec<DecisionTiming>,
    /// Evidence guarantees implemented by the adapter.
    pub evidence: Vec<EvidenceRequirement>,
    /// Obligations implemented independently from allow/deny behavior.
    pub obligations: Vec<Obligation>,
    /// Subject remediations implemented by the adapter.
    pub remediations: Vec<SubjectRemediation>,
    /// Binding activation barriers implemented by the adapter.
    pub activation: Vec<ActivationRequirement>,
    /// Runtime failure guarantees implemented by the adapter.
    pub runtime_failure_policies: Vec<RuntimeFailurePolicy>,
    /// Update failure guarantees implemented by the adapter.
    pub update_failure_policies: Vec<UpdateFailurePolicy>,
    /// Best semantic relation this capability entry can prove.
    pub support_level: MappingRelation,
    /// Explicit constraints and uncovered cases.
    pub limitations: Vec<String>,
}

/// Immutable snapshot used for binding-time target mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilitySnapshot {
    /// Capability schema version independent of API version.
    pub schema_version: String,
    /// Digest over the canonical matrix.
    pub snapshot_digest: Digest,
    /// Structured capability entries.
    pub matrix: Vec<CapabilityEntry>,
}

/// Resource category affected by an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResource {
    /// Policy reconciliation.
    Policy,
    /// Binding reconciliation.
    Binding,
}

/// Queryable operation state retained for UNKNOWN reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationState {
    /// Stable idempotency key.
    pub operation_id: OperationId,
    /// Resource category.
    pub resource: OperationResource,
    /// Current policy state, only for policy operations.
    pub policy_state: Option<PolicyState>,
    /// Current binding state, only for binding operations.
    pub binding_state: Option<BindingState>,
    /// Last known error.
    pub error: Option<ProtocolError>,
}

/// Optional filters for `GET /api/enforcement/v1/state`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetStateRequest {
    /// Select one operation record.
    pub operation_id: Option<OperationId>,
    /// Select one policy identity.
    pub policy_id: Option<PolicyId>,
    /// Select one binding identity.
    pub binding_id: Option<BindingId>,
}

/// Complete response to `GET /api/enforcement/v1/state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetStateResponse {
    /// Service identity and health.
    pub service: ServiceState,
    /// Immutable compiler/enforcer capability snapshot.
    pub capability_snapshot: CapabilitySnapshot,
    /// Operations selected by the query.
    pub operations: Vec<OperationState>,
    /// Current policy records selected by the query.
    pub policies: Vec<ReconcilePolicyResponse>,
    /// Current binding records selected by the query.
    pub bindings: Vec<ReconcileBindingResponse>,
}
