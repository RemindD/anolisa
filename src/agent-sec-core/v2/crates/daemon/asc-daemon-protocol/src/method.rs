//! Closed PAP method inventory and wire access metadata.

// TODO(daemon-process-health): add the canonical `daemon.health` method only
// with its complete V1-compatible payload and DPV1/DPROC conformance fixtures.
/// Create one authored Policy with a server-generated identity.
pub const POLICY_TEMPLATES_CREATE: &str = "policy.templates.create";
/// Update one existing authored Policy identity.
pub const POLICY_TEMPLATES_UPDATE: &str = "policy.templates.update";
/// Read one exact Policy revision.
pub const POLICY_TEMPLATES_GET: &str = "policy.templates.get";
/// List Policy revisions.
pub const POLICY_TEMPLATES_LIST: &str = "policy.templates.list";
/// Delete one exact Policy revision.
pub const POLICY_TEMPLATES_DELETE: &str = "policy.templates.delete";
/// Create one authored Scope with a server-generated identity.
pub const POLICY_SCOPES_CREATE: &str = "policy.scopes.create";
/// Update one existing authored Scope identity.
pub const POLICY_SCOPES_UPDATE: &str = "policy.scopes.update";
/// Read one exact Scope revision.
pub const POLICY_SCOPES_GET: &str = "policy.scopes.get";
/// List Scope revisions.
pub const POLICY_SCOPES_LIST: &str = "policy.scopes.list";
/// Delete one exact Scope revision.
pub const POLICY_SCOPES_DELETE: &str = "policy.scopes.delete";
/// Create one Binding Apply request with a server-generated identity.
pub const POLICY_BINDINGS_CREATE: &str = "policy.bindings.create";
/// Update one existing Binding identity and request Apply.
pub const POLICY_BINDINGS_UPDATE: &str = "policy.bindings.update";
/// Read one current Binding spec and lifecycle status.
pub const POLICY_BINDINGS_GET: &str = "policy.bindings.get";
/// List current Binding specs and lifecycle statuses.
pub const POLICY_BINDINGS_LIST: &str = "policy.bindings.list";
/// Request deletion of one current Binding.
pub const POLICY_BINDINGS_DELETE: &str = "policy.bindings.delete";

/// Complete PAP-facing method inventory for this protocol revision.
pub const PAP_METHODS: [&str; 15] = [
    POLICY_TEMPLATES_CREATE,
    POLICY_TEMPLATES_UPDATE,
    POLICY_TEMPLATES_GET,
    POLICY_TEMPLATES_LIST,
    POLICY_TEMPLATES_DELETE,
    POLICY_SCOPES_CREATE,
    POLICY_SCOPES_UPDATE,
    POLICY_SCOPES_GET,
    POLICY_SCOPES_LIST,
    POLICY_SCOPES_DELETE,
    POLICY_BINDINGS_CREATE,
    POLICY_BINDINGS_UPDATE,
    POLICY_BINDINGS_GET,
    POLICY_BINDINGS_LIST,
    POLICY_BINDINGS_DELETE,
];

/// One exact Policy operation resolved from the wire method name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMethod {
    /// Create one authored Policy with a server-generated identity.
    Create,
    /// Update one existing authored Policy identity.
    Update,
    /// Read one exact Policy revision.
    Get,
    /// List Policy revisions.
    List,
    /// Delete one exact Policy revision.
    Delete,
}

/// One exact Scope operation resolved from the wire method name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMethod {
    /// Create one authored Scope with a server-generated identity.
    Create,
    /// Update one existing authored Scope identity.
    Update,
    /// Read one exact Scope revision.
    Get,
    /// List Scope revisions.
    List,
    /// Delete one exact Scope revision.
    Delete,
}

/// One exact Binding operation resolved from the wire method name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMethod {
    /// Create one Binding Apply request with a server-generated identity.
    Create,
    /// Update one existing Binding identity and request Apply.
    Update,
    /// Read the current Binding spec and lifecycle status.
    Get,
    /// List current Binding specs and lifecycle statuses.
    List,
    /// Request deletion of the current Binding.
    Delete,
}

/// One exact PAP operation resolved from the wire method name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PapMethod {
    /// Authored Policy operation.
    Policy(PolicyMethod),
    /// Authored Scope operation.
    Scope(ScopeMethod),
    /// Binding spec/lifecycle operation.
    Binding(BindingMethod),
}

/// Closed, type-safe daemon method resolved before parameter decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodId {
    /// Policy Administration Point request.
    Pap(PapMethod),
}

/// Daemon capability owning a registered method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Policy Administration Point operations.
    Pap,
}

/// Access policy declared by a registered method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPolicy {
    /// Admission currently relies on the trusted local transport peer.
    ///
    /// TODO(daemon-auth): replace this temporary bring-up policy with the
    /// reviewed server-side authentication binding before production use.
    LocalPeer,
}

/// Static metadata attached to one registered method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// Owning daemon capability.
    pub capability: Capability,
    /// Required wire-level access policy.
    pub access: AccessPolicy,
}

impl MethodId {
    /// Returns the static routing and admission metadata for this exact method.
    pub const fn metadata(self) -> Metadata {
        match self {
            Self::Pap(_) => Metadata {
                capability: Capability::Pap,
                access: AccessPolicy::LocalPeer,
            },
        }
    }
}

/// Resolves one exact wire method before its parameters are inspected.
pub fn resolve(method: &str) -> Option<MethodId> {
    match method {
        POLICY_TEMPLATES_CREATE => Some(MethodId::Pap(PapMethod::Policy(PolicyMethod::Create))),
        POLICY_TEMPLATES_UPDATE => Some(MethodId::Pap(PapMethod::Policy(PolicyMethod::Update))),
        POLICY_TEMPLATES_GET => Some(MethodId::Pap(PapMethod::Policy(PolicyMethod::Get))),
        POLICY_TEMPLATES_LIST => Some(MethodId::Pap(PapMethod::Policy(PolicyMethod::List))),
        POLICY_TEMPLATES_DELETE => Some(MethodId::Pap(PapMethod::Policy(PolicyMethod::Delete))),
        POLICY_SCOPES_CREATE => Some(MethodId::Pap(PapMethod::Scope(ScopeMethod::Create))),
        POLICY_SCOPES_UPDATE => Some(MethodId::Pap(PapMethod::Scope(ScopeMethod::Update))),
        POLICY_SCOPES_GET => Some(MethodId::Pap(PapMethod::Scope(ScopeMethod::Get))),
        POLICY_SCOPES_LIST => Some(MethodId::Pap(PapMethod::Scope(ScopeMethod::List))),
        POLICY_SCOPES_DELETE => Some(MethodId::Pap(PapMethod::Scope(ScopeMethod::Delete))),
        POLICY_BINDINGS_CREATE => Some(MethodId::Pap(PapMethod::Binding(BindingMethod::Create))),
        POLICY_BINDINGS_UPDATE => Some(MethodId::Pap(PapMethod::Binding(BindingMethod::Update))),
        POLICY_BINDINGS_GET => Some(MethodId::Pap(PapMethod::Binding(BindingMethod::Get))),
        POLICY_BINDINGS_LIST => Some(MethodId::Pap(PapMethod::Binding(BindingMethod::List))),
        POLICY_BINDINGS_DELETE => Some(MethodId::Pap(PapMethod::Binding(BindingMethod::Delete))),
        _ => None,
    }
}

/// Looks up one method in the closed registry.
pub fn metadata(method: &str) -> Option<Metadata> {
    resolve(method).map(MethodId::metadata)
}

/// Returns whether a method belongs to the PAP-facing surface.
pub fn is_pap(method: &str) -> bool {
    matches!(resolve(method), Some(MethodId::Pap(_)))
}
