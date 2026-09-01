use asc_foundation_types::{ResourceId, Revision};
use asc_policy_types::Validate;
use asc_policy_types::authoring::PolicyTemplate;
use asc_policy_types::binding::BindingView;
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::scope::{PreparedScope, ScopeSelector};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ListResult;

/// Create one authored Policy with a server-generated identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatePolicyParams {
    /// Human-readable name; PAP validates its domain constraints.
    pub policy_name: String,
    /// Complete authored Policy intent.
    pub template: PolicyTemplate,
}

/// Update one existing authored Policy identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePolicyParams {
    /// Existing Policy identity to update.
    pub policy_id: ResourceId,
    /// Human-readable name; PAP validates its domain constraints.
    pub policy_name: String,
    /// Complete authored Policy intent.
    pub template: PolicyTemplate,
}

/// Create one authored Scope with a server-generated identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateScopeParams {
    /// Unresolved caller selector. Compatibility-only stored selectors are rejected.
    #[serde(
        deserialize_with = "deserialize_authored_selector",
        serialize_with = "serialize_authored_selector"
    )]
    pub selector: ScopeSelector,
}

/// Update one existing authored Scope identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateScopeParams {
    /// Existing Scope identity to update.
    pub scope_id: ResourceId,
    /// Unresolved caller selector. Compatibility-only stored selectors are rejected.
    #[serde(
        deserialize_with = "deserialize_authored_selector",
        serialize_with = "serialize_authored_selector"
    )]
    pub selector: ScopeSelector,
}

/// Create one Binding Apply request with a server-generated identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateBindingParams {
    /// Exact prepared Policy identity referenced by the Binding.
    pub policy_id: ResourceId,
    /// Exact prepared Policy revision referenced by the Binding.
    pub policy_revision: Revision,
    /// Exact prepared Scope identity referenced by the Binding.
    pub scope_id: ResourceId,
    /// Exact prepared Scope revision referenced by the Binding.
    pub scope_revision: Revision,
}

/// Update one existing Binding identity and request Apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateBindingParams {
    /// Existing Binding identity to update.
    pub binding_id: ResourceId,
    /// Exact prepared Policy identity referenced by the Binding.
    pub policy_id: ResourceId,
    /// Exact prepared Policy revision referenced by the Binding.
    pub policy_revision: Revision,
    /// Exact prepared Scope identity referenced by the Binding.
    pub scope_id: ResourceId,
    /// Exact prepared Scope revision referenced by the Binding.
    pub scope_revision: Revision,
}

fn deserialize_authored_selector<'de, D>(deserializer: D) -> Result<ScopeSelector, D::Error>
where
    D: Deserializer<'de>,
{
    let selector = ScopeSelector::deserialize(deserializer)?;
    validate_authored_selector(&selector).map_err(serde::de::Error::custom)?;
    Ok(selector)
}

fn serialize_authored_selector<S>(
    selector: &ScopeSelector,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    validate_authored_selector(selector).map_err(serde::ser::Error::custom)?;
    selector.serialize(serializer)
}

fn validate_authored_selector(selector: &ScopeSelector) -> Result<(), String> {
    if matches!(selector, ScopeSelector::LegacyExecutionDomain { .. }) {
        return Err("legacy execution-domain selectors cannot be authored".to_owned());
    }
    selector
        .validate()
        .map_err(|error| format!("invalid selector at {}: {}", error.path, error.message))
}

/// Result of creating one Policy identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatePolicyResult {
    /// Durable prepared Policy returned by PAP.
    pub policy: PreparedPolicy,
}

/// Result of updating one Policy identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePolicyResult {
    /// Durable prepared Policy returned by PAP.
    pub policy: PreparedPolicy,
}

/// Result of reading one exact Policy revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetPolicyResult {
    /// Selected prepared Policy.
    pub policy: PreparedPolicy,
}

/// Result of listing Policy revisions.
pub type ListPoliciesResult = ListResult<PreparedPolicy>;

/// Result of deleting one exact Policy revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeletePolicyResult {
    /// Deleted immutable Policy revision.
    pub policy: PreparedPolicy,
}

/// Result of creating one Scope identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateScopeResult {
    /// Durable prepared Scope returned by PAP.
    pub scope: PreparedScope,
}

/// Result of updating one Scope identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateScopeResult {
    /// Durable prepared Scope returned by PAP.
    pub scope: PreparedScope,
}

/// Result of reading one exact Scope revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetScopeResult {
    /// Selected prepared Scope.
    pub scope: PreparedScope,
}

/// Result of listing Scope revisions.
pub type ListScopesResult = ListResult<PreparedScope>;

/// Result of deleting one exact Scope revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteScopeResult {
    /// Deleted immutable Scope revision.
    pub scope: PreparedScope,
}

/// Result of creating one Binding Apply request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateBindingResult {
    /// Current immutable Binding spec and lifecycle status.
    pub binding: BindingView,
}

/// Result of updating one Binding identity and requesting Apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateBindingResult {
    /// Current immutable Binding spec and lifecycle status.
    pub binding: BindingView,
}

/// Result of reading one current Binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetBindingResult {
    /// Current immutable Binding spec and lifecycle status.
    pub binding: BindingView,
}

/// Result of listing current Bindings.
pub type ListBindingsResult = ListResult<BindingView>;

/// Result of accepting a Binding Delete request.
///
/// The returned status is authoritative: the immutable spec is retained for
/// reconciliation and is not projected as synchronously deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteBindingResult {
    /// Current immutable Binding spec and lifecycle status.
    pub binding: BindingView,
}
