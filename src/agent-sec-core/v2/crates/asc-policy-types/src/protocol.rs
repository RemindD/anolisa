//! Common API diagnostics and error contracts.

use serde::{Deserialize, Serialize};

/// Machine-readable diagnostic emitted during validation or mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Diagnostic {
    /// Stable diagnostic code.
    pub code: String,
    /// Optional JSON-style path to the affected field.
    pub path: Option<String>,
    /// Human-readable detail that must not contain protected content.
    pub message: String,
}

/// Stable error envelope used by every enforcement API response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolError {
    /// Stable error code such as `REVISION_CONFLICT`.
    pub code: String,
    /// Human-readable, non-sensitive detail.
    pub message: String,
    /// Whether retrying after the stated reconcile action is meaningful.
    pub retryable: bool,
    /// Whether the operation may have changed enforcement state.
    pub state_changed: bool,
    /// Required query or compensating action, if any.
    pub reconcile_action: Option<String>,
}
