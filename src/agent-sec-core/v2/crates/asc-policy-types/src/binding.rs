//! Concrete execution-domain binding.

use serde::{Deserialize, Serialize};

use crate::error::{Validate, ValidationError};
use crate::identifiers::{BaselineId, BindingId, Digest, ExecutionDomainId};
use crate::policy::EffectivePolicyRef;
use crate::scope::BindingScope;

/// Kernel process identity resistant to PID reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessIdentity {
    /// Process ID in the trusted host PID namespace.
    pub pid: u32,
    /// `/proc/<pid>/stat` start time in kernel clock ticks.
    pub start_time_ticks: u64,
}

/// Kernel-backed execution-domain identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionIdentity {
    /// Trusted logical execution-domain identity.
    pub execution_domain_id: ExecutionDomainId,
    /// Monotonic epoch preventing identity reuse.
    pub identity_epoch: u64,
    /// Root process identity used to reject stale or reused PIDs.
    pub root_process: ProcessIdentity,
    /// Kernel cgroup identity used for membership enforcement.
    pub cgroup_id: u64,
}

/// Runtime baseline used for target mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeContext {
    /// Immutable image or host baseline identity.
    pub baseline_id: BaselineId,
    /// Digest of the trusted runtime profile.
    pub runtime_profile_digest: Digest,
}

/// Concrete binding of one Effective Policy Snapshot to one execution domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    /// Stable binding identity.
    pub binding_id: BindingId,
    /// Immutable Effective Policy Snapshot applied atomically.
    pub effective_policy_ref: EffectivePolicyRef,
    /// Trusted subject identity.
    pub identity: ExecutionIdentity,
    /// Concrete enforcement boundary.
    pub scope: BindingScope,
    /// Digest of the canonical scope object.
    pub scope_digest: Digest,
    /// Baseline and runtime profile used for target mapping.
    pub runtime_context: RuntimeContext,
}

impl Validate for Binding {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.identity.identity_epoch == 0 {
            return Err(ValidationError::new(
                "identity.identityEpoch",
                "must be greater than zero",
            ));
        }
        if self.identity.cgroup_id == 0 {
            return Err(ValidationError::new(
                "identity.cgroupId",
                "must be greater than zero",
            ));
        }
        if self.identity.root_process.pid == 0 || self.identity.root_process.start_time_ticks == 0 {
            return Err(ValidationError::new(
                "identity.rootProcess",
                "pid and startTimeTicks must be greater than zero",
            ));
        }

        self.scope
            .validate()
            .map_err(|error| ValidationError::new(format!("scope.{}", error.path), error.message))
    }
}
