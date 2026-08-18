//! Concrete process, namespace, and lifetime scope for a binding.

use serde::{Deserialize, Serialize};

use crate::error::{Validate, ValidationError};

/// Source of process membership for a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMembership {
    /// Membership comes from the trusted execution-domain registry.
    ExecutionDomain,
}

/// Treatment of a nested trusted execution domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedExecutionDomainAction {
    /// Parent constraints remain effective; the child may only add constraints.
    Inherit,
}

/// Processes covered by the binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // The booleans are independent wire-level scope claims.
pub struct ProcessScope {
    /// Trusted source of process membership.
    pub membership: ProcessMembership,
    /// Include the execution-domain root process.
    pub include_root: bool,
    /// Include members already present at activation.
    pub include_existing_members: bool,
    /// Include processes joining after activation.
    pub include_future_members: bool,
    /// Preserve constraints when a member calls exec.
    pub preserve_across_exec: bool,
    /// Parent-policy behavior for nested trusted domains.
    pub nested_execution_domains: NestedExecutionDomainAction,
}

/// Behavior when a protected process attempts to change namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceChangeAction {
    /// Reject an unapproved namespace transition.
    Deny,
}

/// Namespace identities that define resource interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamespaceScope {
    /// PID namespace identity.
    pub pid_namespace_id: u64,
    /// Mount namespace identity for filesystem selectors.
    pub mount_namespace_id: u64,
    /// Network namespace identity for network resources.
    pub network_namespace_id: u64,
    /// Unapproved namespace transition behavior.
    pub on_change: NamespaceChangeAction,
}

/// Event that activates the binding lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingActivation {
    /// Activation begins only after all enforcement points are ready.
    BindingReady,
}

/// Event that terminates the binding lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingEndCondition {
    /// Terminate after the execution domain drains and receipts are flushed.
    ExecutionDomainDrained,
}

/// Temporal binding scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingLifetime {
    /// Activation boundary.
    pub activate_at: BindingActivation,
    /// Optional RFC 3339 expiry controlled by PCP.
    pub expires_at: Option<String>,
    /// Normal termination boundary.
    pub end_condition: BindingEndCondition,
}

/// Complete concrete enforcement scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingScope {
    /// Covered process membership and inheritance.
    pub processes: ProcessScope,
    /// Resource-interpretation namespaces.
    pub namespaces: NamespaceScope,
    /// Activation and termination lifetime.
    pub lifetime: BindingLifetime,
}

impl Validate for BindingScope {
    fn validate(&self) -> Result<(), ValidationError> {
        let processes = &self.processes;
        if !processes.include_root
            || processes.include_existing_members
            || !processes.include_future_members
            || !processes.preserve_across_exec
        {
            return Err(ValidationError::new(
                "processes",
                "v1 post-attach bindings must cover the root and future members across exec, but cannot claim existing-member coverage",
            ));
        }

        let namespaces = &self.namespaces;
        if namespaces.pid_namespace_id == 0
            || namespaces.mount_namespace_id == 0
            || namespaces.network_namespace_id == 0
        {
            return Err(ValidationError::new(
                "namespaces",
                "namespace identities must be greater than zero",
            ));
        }

        if self
            .lifetime
            .expires_at
            .as_ref()
            .is_some_and(|expires_at| expires_at.trim().is_empty())
        {
            return Err(ValidationError::new(
                "lifetime.expiresAt",
                "must be a non-empty RFC 3339 timestamp when present",
            ));
        }
        Ok(())
    }
}
