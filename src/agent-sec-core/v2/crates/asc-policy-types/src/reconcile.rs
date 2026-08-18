//! Minimal PCP-to-AgentSight reconciliation wire contracts.

use serde::{Deserialize, Serialize};

use crate::binding::{ExecutionIdentity, RuntimeContext};
use crate::error::{Validate, ValidationError};
use crate::identifiers::{
    BindingId, Digest, ExecutionDomainId, OperationId, PepInstanceId, PolicyId, Revision, RunId,
};
use crate::mapping::{BindingState, MappingReport, PolicyDesiredState, PolicyState};
use crate::policy::{EffectivePolicyRef, PolicyEnvelope};
use crate::protocol::{Diagnostic, ProtocolError};
use crate::scope::BindingScope;

/// Compare-and-swap precondition for policy reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyPrecondition {
    /// Revision expected to be current, if one exists.
    pub expected_current_revision: Option<Revision>,
    /// Canonical payload digest expected to be current, if one exists.
    pub expected_payload_digest: Option<Digest>,
}

/// Policy reconciliation request.
///
/// The tagged union makes PRESENT and ABSENT payloads mutually exclusive on
/// both the Rust and JSON boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "desiredState", deny_unknown_fields)]
pub enum ReconcilePolicyRequest {
    /// Create or idempotently confirm an immutable policy revision.
    #[serde(rename = "PRESENT")]
    Present {
        /// Globally unique idempotency key.
        #[serde(rename = "operationId")]
        operation_id: OperationId,
        /// Complete resolved policy.
        policy: PolicyEnvelope,
        /// Optional compare-and-swap guard.
        precondition: PolicyPrecondition,
    },
    /// Remove a policy that is no longer referenced.
    #[serde(rename = "ABSENT")]
    Absent {
        /// Globally unique idempotency key.
        #[serde(rename = "operationId")]
        operation_id: OperationId,
        /// Stable identity to remove.
        #[serde(rename = "policyId")]
        policy_id: PolicyId,
        /// Optional compare-and-swap guard.
        precondition: PolicyPrecondition,
    },
}

impl ReconcilePolicyRequest {
    /// Returns the desired state without inspecting variant fields.
    pub const fn desired_state(&self) -> PolicyDesiredState {
        match self {
            Self::Present { .. } => PolicyDesiredState::Present,
            Self::Absent { .. } => PolicyDesiredState::Absent,
        }
    }
}

impl Validate for ReconcilePolicyRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Present { policy, .. } => policy.validate(),
            Self::Absent { .. } => Ok(()),
        }
    }
}

/// Validation outcome stored with an available or rejected policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationStatus {
    /// Schema and semantic validation succeeded.
    Valid,
    /// Schema or semantic validation failed.
    Invalid,
    /// Schema and Profile are valid, but no static adapter capability can support the policy.
    Unsupported,
}

/// Policy validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationReport {
    /// Validation result.
    pub status: ValidationStatus,
    /// Stable, non-sensitive diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Policy-side compilation stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StaticCompileStage {
    /// Final target compilation requires binding runtime context.
    DeferredToBinding,
    /// No compilation was attempted because validation failed.
    NotAttempted,
}

/// Static compilation report returned by policy reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaticCompileReport {
    /// Current compilation stage.
    pub stage: StaticCompileStage,
    /// `AgentSight` compiler implementation version.
    pub compiler_version: String,
    /// Stable, non-sensitive diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Result of one policy reconciliation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcilePolicyResponse {
    /// Idempotency key copied from the request.
    pub operation_id: OperationId,
    /// Authoritative current state.
    pub state: PolicyState,
    /// Policy identity when known.
    pub policy_id: PolicyId,
    /// Current immutable revision, absent after successful removal.
    pub revision: Option<Revision>,
    /// Current canonical payload digest, absent after successful removal.
    pub payload_digest: Option<Digest>,
    /// Validation report when validation ran.
    pub validation: Option<ValidationReport>,
    /// Static compilation report when applicable.
    pub static_compile: Option<StaticCompileReport>,
    /// Error details for rejected or unknown results.
    pub error: Option<ProtocolError>,
}

/// Explicit approval for a non-exact but non-widening mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingApproval {
    /// Whether a narrower mapping may be installed.
    pub allow_narrower: bool,
    /// External approval evidence, when required.
    pub approval_ref: Option<String>,
    /// Digest of the exact mapping that was approved.
    pub expected_mapping_digest: Option<Digest>,
}

/// Compare-and-swap and capability guard for a binding operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingPrecondition {
    /// Current binding revision expected by the caller.
    pub expected_binding_revision: Option<Revision>,
    /// Capability snapshot against which PCP authorized this request.
    pub capability_snapshot_digest: Digest,
}

/// Minimal trusted identity needed to remove a binding safely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingRemovalIdentity {
    /// Trusted logical execution-domain identity.
    pub execution_domain_id: ExecutionDomainId,
    /// Epoch preventing removal of a reused identity.
    pub identity_epoch: u64,
}

/// Drain behavior before removing a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DrainOptions {
    /// Maximum drain time in milliseconds.
    pub timeout_ms: u64,
    /// Whether persisted receipts are part of the removal barrier.
    pub require_receipt_flush: bool,
}

/// Complete READY payload for binding reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadyBindingRequest {
    /// Globally unique idempotency key.
    pub operation_id: OperationId,
    /// Stable binding identity.
    pub binding_id: BindingId,
    /// Trusted run-registry correlation identity.
    pub run_id: RunId,
    /// Single immutable Effective Policy Snapshot to activate.
    pub effective_policy: EffectivePolicyRef,
    /// Trusted kernel-backed subject identity.
    pub identity: ExecutionIdentity,
    /// Concrete process, namespace, and lifetime boundary.
    pub scope: BindingScope,
    /// Digest of the canonical scope object.
    pub scope_digest: Digest,
    /// Baseline used for target mapping.
    pub runtime_context: RuntimeContext,
    /// Non-exact mapping approval.
    pub approval: BindingApproval,
    /// Current-state and capability preconditions.
    pub precondition: BindingPrecondition,
}

/// Binding reconciliation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "desiredState", deny_unknown_fields)]
pub enum ReconcileBindingRequest {
    /// Atomically install one Effective Policy Snapshot for an execution domain.
    #[serde(rename = "READY")]
    Ready(Box<ReadyBindingRequest>),
    /// Drain and remove an existing binding.
    #[serde(rename = "ABSENT")]
    Absent {
        /// Globally unique idempotency key.
        #[serde(rename = "operationId")]
        operation_id: OperationId,
        /// Stable binding identity.
        #[serde(rename = "bindingId")]
        binding_id: BindingId,
        /// Identity guard against execution-domain reuse.
        identity: BindingRemovalIdentity,
        /// Drain and receipt-flush behavior.
        drain: DrainOptions,
    },
}

impl Validate for ReconcileBindingRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Ready(request) => {
                let ReadyBindingRequest {
                    identity,
                    scope,
                    approval,
                    ..
                } = request.as_ref();
                if identity.identity_epoch == 0 || identity.cgroup_id == 0 {
                    return Err(ValidationError::new(
                        "identity",
                        "identityEpoch and cgroupId must be greater than zero",
                    ));
                }
                if identity.root_process.pid == 0 || identity.root_process.start_time_ticks == 0 {
                    return Err(ValidationError::new(
                        "identity.rootProcess",
                        "pid and startTimeTicks must be greater than zero",
                    ));
                }
                scope.validate().map_err(|error| {
                    ValidationError::new(format!("scope.{}", error.path), error.message)
                })?;
                if approval.allow_narrower && approval.expected_mapping_digest.is_none() {
                    return Err(ValidationError::new(
                        "approval.expectedMappingDigest",
                        "a narrower mapping approval must bind the approved mapping digest",
                    ));
                }
                Ok(())
            }
            Self::Absent {
                identity, drain, ..
            } => {
                if identity.identity_epoch == 0 {
                    return Err(ValidationError::new(
                        "identity.identityEpoch",
                        "must be greater than zero",
                    ));
                }
                if drain.timeout_ms == 0 {
                    return Err(ValidationError::new(
                        "drain.timeoutMs",
                        "must be greater than zero",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Verification state of the concrete binding scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeState {
    /// Kernel-backed scope matches the request.
    Verified,
    /// Scope verification is still in progress.
    Pending,
    /// Scope cannot be verified.
    Unverified,
}

/// Result of one binding reconciliation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcileBindingResponse {
    /// Idempotency key copied from the request.
    pub operation_id: OperationId,
    /// Authoritative current state.
    pub state: BindingState,
    /// Stable binding identity.
    pub binding_id: BindingId,
    /// Current binding revision, absent after successful removal.
    pub binding_revision: Option<Revision>,
    /// Bound execution domain when known.
    pub execution_domain_id: Option<ExecutionDomainId>,
    /// Bound identity epoch when known.
    pub identity_epoch: Option<u64>,
    /// Effective Policy Snapshot installed for this binding.
    pub effective_policy: Option<EffectivePolicyRef>,
    /// Canonical scope digest when installed.
    pub scope_digest: Option<Digest>,
    /// Verification state of the concrete scope.
    pub scope_state: Option<ScopeState>,
    /// Digest over all binding-time policy/target mapping reports.
    pub mapping_digest: Option<Digest>,
    /// Binding-time semantic mapping reports for each policy and target.
    pub mappings: Vec<MappingReport>,
    /// Digests of AgentSight-generated target artifacts.
    pub target_digests: Vec<Digest>,
    /// Enforcement points that acknowledged installation.
    pub pep_instances: Vec<PepInstanceId>,
    /// RFC 3339 activation time.
    pub effective_at: Option<String>,
    /// Error details for rejected or unknown results.
    pub error: Option<ProtocolError>,
}
