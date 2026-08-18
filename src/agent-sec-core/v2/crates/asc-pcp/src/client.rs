//! `AgentSight` transport boundary and HTTP implementation.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use asc_policy_types::protocol::ProtocolError;
use asc_policy_types::receipt::{PullReceiptsRequest, PullReceiptsResponse};
use asc_policy_types::reconcile::{
    ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse,
};
use asc_policy_types::state::{GetStateRequest, GetStateResponse};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Canonical V1 policy reconcile endpoint.
pub const POLICIES_PATH: &str = "/api/enforcement/v1/policies";
/// Canonical V1 binding reconcile endpoint.
pub const BINDINGS_PATH: &str = "/api/enforcement/v1/bindings";
/// Canonical V1 current-state endpoint.
pub const STATE_PATH: &str = "/api/enforcement/v1/state";
/// Canonical V1 cursor-based receipt endpoint.
pub const RECEIPTS_PATH: &str = "/api/enforcement/v1/receipts";

/// Transport-independent `AgentSight` enforcement API.
pub trait AgentSightClient {
    /// Reconciles one immutable Canonical IR policy revision.
    ///
    /// # Errors
    /// Returns a transport, protocol, or response-decoding failure.
    fn reconcile_policy(
        &self,
        request: &ReconcilePolicyRequest,
    ) -> Result<ReconcilePolicyResponse, ClientError>;

    /// Reconciles one complete execution-domain binding.
    ///
    /// # Errors
    /// Returns a transport, protocol, or response-decoding failure.
    fn reconcile_binding(
        &self,
        request: &ReconcileBindingRequest,
    ) -> Result<ReconcileBindingResponse, ClientError>;

    /// Queries authoritative state for uncertain or recovery paths.
    ///
    /// # Errors
    /// Returns a transport, protocol, or response-decoding failure.
    fn get_state(&self, request: &GetStateRequest) -> Result<GetStateResponse, ClientError>;

    /// Pulls one page from the persistent receipt stream.
    ///
    /// # Errors
    /// Returns a transport, protocol, or response-decoding failure.
    fn pull_receipts(
        &self,
        request: &PullReceiptsRequest,
    ) -> Result<PullReceiptsResponse, ClientError>;
}

/// Failure at the PCP-to-AgentSight boundary.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The request may have reached `AgentSight` and must be reconciled by state query.
    #[error("ambiguous transport failure: {0}")]
    AmbiguousTransport(String),
    /// `AgentSight` returned a stable protocol error.
    #[error("AgentSight protocol error: {0:?}")]
    Protocol(ProtocolError),
    /// `AgentSight` returned a response outside the shared contract.
    #[error("invalid AgentSight response: {0}")]
    InvalidResponse(String),
    /// The client base URL is invalid.
    #[error("invalid AgentSight base URL: {0}")]
    InvalidBaseUrl(String),
    /// The configured Bearer token file could not be read.
    #[error("failed to read AgentSight token file {path}: {source}")]
    TokenFile {
        /// Configured credential path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// The configured Bearer token cannot be represented safely in an HTTP header.
    #[error("AgentSight token file {0} is empty or contains invalid header characters")]
    InvalidTokenFile(PathBuf),
}

/// Blocking HTTP client for the four minimal enforcement V1 endpoints.
#[derive(Clone)]
pub struct HttpAgentSightClient {
    base_url: String,
    bearer_token: Option<String>,
}

impl fmt::Debug for HttpAgentSightClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpAgentSightClient")
            .field("base_url", &self.base_url)
            .field("bearer_token_configured", &self.bearer_token.is_some())
            .finish()
    }
}

impl HttpAgentSightClient {
    /// Creates a client for an `http://` or `https://` `AgentSight` origin.
    ///
    /// # Errors
    /// Returns an error for an empty or non-HTTP base URL.
    pub fn new(base_url: impl Into<String>) -> Result<Self, ClientError> {
        let base_url = base_url.into();
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            return Err(ClientError::InvalidBaseUrl(base_url));
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            bearer_token: None,
        })
    }

    /// Creates a client that authenticates every request with a Bearer token loaded from a file.
    ///
    /// The token is read once during construction and is never included in `Debug` output. Restart
    /// the client after rotating the credential file.
    ///
    /// # Errors
    /// Returns an error for an invalid base URL, an unreadable file, or a token that cannot be used
    /// safely as an HTTP header value.
    pub fn new_with_token_file(
        base_url: impl Into<String>,
        token_file: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        let mut client = Self::new(base_url)?;
        let token_file = token_file.as_ref();
        client.bearer_token = Some(read_bearer_token(token_file)?);
        Ok(client)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    fn authenticate(&self, request: ureq::Request) -> ureq::Request {
        match &self.bearer_token {
            Some(token) => request.set("Authorization", &format!("Bearer {token}")),
            None => request,
        }
    }

    fn put_json<Request, Response>(
        &self,
        path: &str,
        request: &Request,
    ) -> Result<Response, ClientError>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        let value = serde_json::to_value(request)
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        let http_request = self.authenticate(ureq::put(&self.url(path)));
        decode_response(http_request.send_json(value))
    }
}

impl AgentSightClient for HttpAgentSightClient {
    fn reconcile_policy(
        &self,
        request: &ReconcilePolicyRequest,
    ) -> Result<ReconcilePolicyResponse, ClientError> {
        self.put_json(POLICIES_PATH, request)
    }

    fn reconcile_binding(
        &self,
        request: &ReconcileBindingRequest,
    ) -> Result<ReconcileBindingResponse, ClientError> {
        self.put_json(BINDINGS_PATH, request)
    }

    fn get_state(&self, request: &GetStateRequest) -> Result<GetStateResponse, ClientError> {
        let url = self.url(STATE_PATH);
        let mut http_request = ureq::get(&url);
        if let Some(operation_id) = &request.operation_id {
            http_request = http_request.query("operationId", operation_id.as_str());
        }
        if let Some(policy_id) = &request.policy_id {
            http_request = http_request.query("policyId", policy_id.as_str());
        }
        if let Some(binding_id) = &request.binding_id {
            http_request = http_request.query("bindingId", binding_id.as_str());
        }
        decode_response(self.authenticate(http_request).call())
    }

    fn pull_receipts(
        &self,
        request: &PullReceiptsRequest,
    ) -> Result<PullReceiptsResponse, ClientError> {
        let url = self.url(RECEIPTS_PATH);
        let limit = request.limit.to_string();
        let mut http_request = ureq::get(&url).query("limit", &limit);
        if let Some(cursor) = &request.cursor {
            http_request = http_request.query("cursor", cursor);
        }
        decode_response(self.authenticate(http_request).call())
    }
}

fn read_bearer_token(path: &Path) -> Result<String, ClientError> {
    let token = fs::read_to_string(path).map_err(|source| ClientError::TokenFile {
        path: path.to_path_buf(),
        source,
    })?;
    let token = token.trim();
    if token.is_empty()
        || !token.is_ascii()
        || token
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte.is_ascii_control())
    {
        return Err(ClientError::InvalidTokenFile(path.to_path_buf()));
    }
    Ok(token.to_owned())
}

fn decode_response<Response>(
    response: Result<ureq::Response, ureq::Error>,
) -> Result<Response, ClientError>
where
    Response: DeserializeOwned,
{
    match response {
        Ok(response) => response
            .into_json::<Response>()
            .map_err(|error| ClientError::InvalidResponse(error.to_string())),
        Err(ureq::Error::Status(_, response)) => {
            let protocol_error = response.into_json::<ProtocolError>().map_err(|error| {
                ClientError::InvalidResponse(format!(
                    "non-success response did not contain ProtocolError: {error}"
                ))
            })?;
            Err(ClientError::Protocol(protocol_error))
        }
        Err(ureq::Error::Transport(error)) => {
            Err(ClientError::AmbiguousTransport(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_token_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "asc-pcp-{name}-{}-{}.token",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ))
    }

    #[test]
    fn token_file_configures_a_redacted_authorization_header() {
        let path = temporary_token_path("authorization");
        fs::write(&path, "test-agent-sight-token-0123456789abcdef\n").unwrap();
        let client =
            HttpAgentSightClient::new_with_token_file("http://127.0.0.1:7396", &path).unwrap();
        fs::remove_file(path).unwrap();

        let request = client.authenticate(ureq::get("http://127.0.0.1:7396/test"));
        assert_eq!(
            request.header("Authorization"),
            Some("Bearer test-agent-sight-token-0123456789abcdef")
        );
        let debug = format!("{client:?}");
        assert!(debug.contains("bearer_token_configured: true"));
        assert!(!debug.contains("test-agent-sight-token"));
    }

    #[test]
    fn token_file_rejects_empty_or_header_injection_values() {
        let path = temporary_token_path("invalid");
        for value in [" \n", "token-value\nInjected: true"] {
            fs::write(&path, value).unwrap();
            assert!(matches!(
                HttpAgentSightClient::new_with_token_file("http://127.0.0.1:7396", &path),
                Err(ClientError::InvalidTokenFile(error_path)) if error_path == path
            ));
        }
        fs::remove_file(path).unwrap();
    }
}
