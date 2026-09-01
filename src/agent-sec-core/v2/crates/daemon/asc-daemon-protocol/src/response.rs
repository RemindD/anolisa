use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Stable daemon-generated identity for correlating a response with diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    /// Creates a non-empty opaque daemon request identity.
    ///
    /// # Errors
    /// Returns an error when the identity is empty or whitespace-only.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.trim().is_empty() {
            Err("request ID must be a non-empty string")
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the opaque wire identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Open, machine-readable daemon error code.
///
/// This is intentionally not a closed enum: an older client must still be able
/// to decode a syntactically valid code introduced by a newer daemon.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ErrorCode(String);

impl ErrorCode {
    /// Creates a bounded snake-case wire code.
    ///
    /// # Errors
    /// Returns an error unless the value begins with a lowercase ASCII letter,
    /// contains only lowercase ASCII letters, digits, or underscores, and is at
    /// most 64 bytes long.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let mut bytes = value.bytes();
        if value.len() > 64
            || !matches!(bytes.next(), Some(b'a'..=b'z'))
            || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            Err("error code must be a bounded lower_snake_case identifier")
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the stable wire code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Stable daemon error safe to return across the service boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonError {
    /// Stable machine-readable code. Clients must not parse `message`.
    pub code: ErrorCode,
    /// Bounded, sanitized, operator-facing explanation.
    pub message: String,
}

impl DaemonError {
    /// Creates a daemon error from a registered wire code and safe message.
    ///
    /// # Panics
    /// Panics when a programmer supplies a syntactically invalid error code.
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: ErrorCode::new(code).expect("daemon error codes must be valid constants"),
            message: message.to_owned(),
        }
    }
}

/// Successful daemon response carrying one method-specific result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuccessResponse<T> {
    /// Daemon-generated correlation identity.
    pub request_id: RequestId,
    /// Method-specific successful result.
    pub result: T,
}

/// Failed daemon response carrying one structured service error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorResponse {
    /// Daemon-generated correlation identity.
    pub request_id: RequestId,
    /// Structured RPC or application error.
    pub error: DaemonError,
}

/// One daemon response with mutually exclusive `result` and `error` shapes.
///
/// Transport failures do not produce this value. CLI output and process exit
/// codes are projected by clients.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DaemonResponse<T = Value> {
    /// The requested method completed successfully.
    Success(SuccessResponse<T>),
    /// The request or method failed with a structured service error.
    Error(ErrorResponse),
}

impl<T> DaemonResponse<T> {
    /// Creates a successful method response.
    pub fn success(request_id: RequestId, result: T) -> Self {
        Self::Success(SuccessResponse { request_id, result })
    }

    /// Creates a structured request or method failure.
    pub fn error(request_id: RequestId, code: &str, message: &str) -> Self {
        Self::Error(ErrorResponse {
            request_id,
            error: DaemonError::new(code, message),
        })
    }

    /// Returns the daemon-generated correlation identity for either outcome.
    pub fn request_id(&self) -> &RequestId {
        match self {
            Self::Success(response) => &response.request_id,
            Self::Error(response) => &response.request_id,
        }
    }
}

/// Stable daemon error-code registry.
pub mod error_code {
    /// The request envelope or method parameters are malformed.
    pub const INVALID_REQUEST: &str = "invalid_request";
    /// A validated wire value violates a method's domain constraints.
    pub const INVALID_ARGUMENT: &str = "invalid_argument";
    /// The requested method is not registered by this daemon.
    pub const UNKNOWN_METHOD: &str = "unknown_method";
    /// The authenticated principal lacks authority for the operation.
    pub const PERMISSION_DENIED: &str = "permission_denied";
    /// The requested resource does not exist.
    pub const NOT_FOUND: &str = "not_found";
    /// The requested write conflicts with current state.
    pub const CONFLICT: &str = "conflict";
    /// A bounded server-side resource cannot allocate more capacity.
    pub const RESOURCE_EXHAUSTED: &str = "resource_exhausted";
    /// The request deadline expired before completion.
    pub const DEADLINE_EXCEEDED: &str = "deadline_exceeded";
    /// The service is temporarily unavailable.
    pub const UNAVAILABLE: &str = "unavailable";
    /// An internal invariant or dependency failed without exposing details.
    pub const INTERNAL: &str = "internal";
}
