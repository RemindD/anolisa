//! Test and demo HTTP host for the `AgentSecCore` V2 policy control plane.
//!
//! This crate deliberately keeps the HTTP surface small. It is not a production
//! multi-tenant PAP, but it owns one durable PCP controller for its complete
//! lifetime so tests can exercise restart recovery and background reconciliation.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use asc_pcp::{AgentSightClient, Controller, ControllerError, ControllerState, StateStore};
use asc_policy_engine::{PolicyTemplate, TemplateEnvelope};
use asc_policy_types::identifiers::{OperationId, PolicyId, Revision};
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::protocol::ProtocolError;
use asc_policy_types::receipt::Receipt;
use asc_policy_types::reconcile::{
    PolicyPrecondition, ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);

/// Successful response from the product-template policy endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePolicyResponse {
    /// Deterministically lowered Canonical Policy IR.
    pub policy: PolicyEnvelope,
    /// Authoritative result returned by `AgentSight`.
    pub observed: ReconcilePolicyResponse,
}

/// Result of one background maintenance pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceReport {
    /// Pending policy operations examined in this pass.
    pub attempted_policy_operations: usize,
    /// Pending binding operations examined in this pass.
    pub attempted_binding_operations: usize,
    /// Newly persisted receipts.
    pub new_receipts: usize,
    /// Individual failures. Other pending work is still attempted.
    pub errors: Vec<String>,
}

/// Product-service failure before an HTTP response is produced.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// A path or header supplied an invalid strong identifier.
    #[error("invalid identifier: {0}")]
    Identifier(String),
    /// Revision zero is not valid.
    #[error("invalid revision: {0}")]
    Revision(&'static str),
    /// PCP processing failed.
    #[error(transparent)]
    Controller(#[from] ControllerError),
}

/// One process-owned policy application service.
pub struct PolicyService<C, S> {
    controller: Controller<C, S>,
    operation_lock: Mutex<()>,
}

impl<C, S> PolicyService<C, S>
where
    C: AgentSightClient,
    S: StateStore,
{
    /// Creates a service around one restored PCP controller.
    ///
    /// # Errors
    /// Returns an error when durable state cannot be loaded.
    pub fn new(client: C, store: S) -> Result<Self, ServiceError> {
        Ok(Self {
            controller: Controller::new(client, store)?,
            operation_lock: Mutex::new(()),
        })
    }

    /// Lowers a product template, persists it, and reconciles it with `AgentSight`.
    ///
    /// `operation_id` comes from the HTTP `Idempotency-Key` header so the frozen
    /// product template JSON remains free of control-plane metadata.
    ///
    /// # Errors
    /// Returns an identifier, lowering, persistence, or `AgentSight` failure.
    pub fn create_policy(
        &self,
        policy_id: &str,
        revision: u64,
        operation_id: &str,
        template: PolicyTemplate,
    ) -> Result<CreatePolicyResponse, ServiceError> {
        let _guard = self.lock_operations()?;
        let template = TemplateEnvelope {
            policy_id: PolicyId::new(policy_id).map_err(ServiceError::Identifier)?,
            revision: Revision::new(revision).map_err(ServiceError::Revision)?,
            template,
        };
        let policy = self.controller.prepare_policy(template)?;
        let request = ReconcilePolicyRequest::Present {
            operation_id: OperationId::new(operation_id).map_err(ServiceError::Identifier)?,
            policy: policy.clone(),
            precondition: PolicyPrecondition {
                expected_current_revision: None,
                expected_payload_digest: None,
            },
        };
        let observed = self.controller.reconcile_policy(&request)?;
        Ok(CreatePolicyResponse { policy, observed })
    }

    /// Reconciles a complete binding request with `AgentSight`.
    ///
    /// # Errors
    /// Returns validation, persistence, mapping, or `AgentSight` failures.
    pub fn reconcile_binding(
        &self,
        request: &ReconcileBindingRequest,
    ) -> Result<ReconcileBindingResponse, ServiceError> {
        let _guard = self.lock_operations()?;
        Ok(self.controller.reconcile_binding(request)?)
    }

    /// Returns a point-in-time view of locally durable PCP state.
    ///
    /// # Errors
    /// Returns an error if the controller state lock was poisoned.
    pub fn state_snapshot(&self) -> Result<ControllerState, ServiceError> {
        Ok(self.controller.state_snapshot()?)
    }

    /// Pulls and durably deduplicates one receipt page.
    ///
    /// # Errors
    /// Returns validation, persistence, or `AgentSight` failures.
    pub fn pull_receipts(&self, limit: u16) -> Result<Vec<Receipt>, ServiceError> {
        let _guard = self.lock_operations()?;
        Ok(self.controller.pull_receipts(limit)?)
    }

    /// Recovers every pending operation and advances the receipt cursor once.
    ///
    /// Operation failures are reported independently so one bad binding does
    /// not prevent recovery of unrelated desired state.
    ///
    /// # Errors
    /// Returns only when the local controller state cannot be read.
    pub fn maintain_once(&self, receipt_limit: u16) -> Result<MaintenanceReport, ServiceError> {
        let _guard = self.lock_operations()?;
        let state = self.controller.state_snapshot()?;
        let pending_policies: Vec<_> = state
            .policy_operations
            .values()
            .filter(|record| record.observed.is_none())
            .map(|record| record.request.clone())
            .collect();
        let pending_bindings: Vec<_> = state
            .binding_operations
            .values()
            .filter(|record| record.observed.is_none())
            .map(|record| record.request.clone())
            .collect();

        let mut report = MaintenanceReport {
            attempted_policy_operations: pending_policies.len(),
            attempted_binding_operations: pending_bindings.len(),
            ..MaintenanceReport::default()
        };
        for request in pending_policies {
            if let Err(error) = self.controller.reconcile_policy(&request) {
                report.errors.push(error.to_string());
            }
        }
        for request in pending_bindings {
            if let Err(error) = self.controller.reconcile_binding(&request) {
                report.errors.push(error.to_string());
            }
        }
        match self.controller.pull_receipts(receipt_limit) {
            Ok(receipts) => report.new_receipts = receipts.len(),
            Err(error) => report.errors.push(error.to_string()),
        }
        Ok(report)
    }

    fn lock_operations(&self) -> Result<std::sync::MutexGuard<'_, ()>, ServiceError> {
        self.operation_lock
            .lock()
            .map_err(|_| ControllerError::Poisoned.into())
    }
}

/// Serves the local test API until the process is terminated.
///
/// # Errors
/// Returns a listener or connection I/O failure.
pub fn serve<C, S>(listener: &TcpListener, service: &PolicyService<C, S>) -> Result<(), io::Error>
where
    C: AgentSightClient + Send + Sync + 'static,
    S: StateStore + Send + Sync + 'static,
{
    serve_requests(listener, service, None)
}

fn serve_requests<C, S>(
    listener: &TcpListener,
    service: &PolicyService<C, S>,
    maximum_requests: Option<usize>,
) -> Result<(), io::Error>
where
    C: AgentSightClient + Send + Sync + 'static,
    S: StateStore + Send + Sync + 'static,
{
    let mut served = 0_usize;
    loop {
        if maximum_requests.is_some_and(|maximum| served >= maximum) {
            return Ok(());
        }
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        handle_connection(&mut stream, service)?;
        served += 1;
    }
}

fn handle_connection<C, S>(
    stream: &mut TcpStream,
    service: &PolicyService<C, S>,
) -> Result<(), io::Error>
where
    C: AgentSightClient,
    S: StateStore,
{
    let response = match read_request(stream) {
        Ok(request) => route_request(&request, service),
        Err(error) => error_response(400, "INVALID_HTTP_REQUEST", error.to_string(), false, false),
    };
    write_response(stream, &response)
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, io::Error> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = find_header_end(&bytes) {
            break position + 4;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP headers exceed 32 KiB"));
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP headers completed",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    };

    let header_text = std::str::from_utf8(&bytes[..header_end - 4])
        .map_err(|_| invalid_data("HTTP headers must be UTF-8"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP method"))?
        .to_owned();
    let target = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP target"))?
        .to_owned();
    let version = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP version"))?;
    if request_parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(invalid_data("invalid HTTP request line"));
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid_data("invalid HTTP header"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(invalid_data("chunked request bodies are not supported"));
    }
    let content_length = headers.get("content-length").map_or(Ok(0), |value| {
        value
            .parse::<usize>()
            .map_err(|_| invalid_data("invalid Content-Length"))
    })?;
    if content_length > MAX_BODY_BYTES {
        return Err(invalid_data("HTTP body exceeds 1 MiB"));
    }
    let required = header_end + content_length;
    while bytes.len() < required {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP body completed",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }

    Ok(HttpRequest {
        method,
        target,
        headers,
        body: bytes[header_end..required].to_vec(),
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn route_request<C, S>(request: &HttpRequest, service: &PolicyService<C, S>) -> HttpResponse
where
    C: AgentSightClient,
    S: StateStore,
{
    let (path, query) = request
        .target
        .split_once('?')
        .map_or((request.target.as_str(), ""), |parts| parts);

    if request.method == "GET" && path == "/healthz" {
        return json_response(200, &serde_json::json!({ "status": "ok" }));
    }
    if request.method == "GET" && path == "/api/v1/state" {
        return result_response(service.state_snapshot());
    }
    if request.method == "PUT" && path == "/api/v1/bindings" {
        return decode_json::<ReconcileBindingRequest>(&request.body)
            .and_then(|body| service.reconcile_binding(&body).map_err(HttpFailure::from))
            .map_or_else(HttpFailure::response, |response| {
                json_response(200, &response)
            });
    }
    if request.method == "POST" && path == "/api/v1/receipts/pull" {
        let Ok(limit) = query_parameter(query, "limit")
            .unwrap_or("100")
            .parse::<u16>()
        else {
            return error_response(
                400,
                "INVALID_LIMIT",
                "limit must be an integer between 1 and 1000".to_owned(),
                false,
                false,
            );
        };
        return result_response(service.pull_receipts(limit));
    }
    if request.method == "PUT"
        && let Some((policy_id, revision)) = parse_policy_path(path)
    {
        let Some(operation_id) = request.headers.get("idempotency-key") else {
            return error_response(
                400,
                "MISSING_IDEMPOTENCY_KEY",
                "Idempotency-Key header is required".to_owned(),
                false,
                false,
            );
        };
        let Ok(revision) = revision.parse::<u64>() else {
            return error_response(
                400,
                "INVALID_REVISION",
                "revision must be a positive integer".to_owned(),
                false,
                false,
            );
        };
        return decode_json::<PolicyTemplate>(&request.body)
            .and_then(|template| {
                service
                    .create_policy(policy_id, revision, operation_id, template)
                    .map_err(HttpFailure::from)
            })
            .map_or_else(HttpFailure::response, |response| {
                json_response(200, &response)
            });
    }

    error_response(
        404,
        "ROUTE_NOT_FOUND",
        format!("no route for {} {path}", request.method),
        false,
        false,
    )
}

fn parse_policy_path(path: &str) -> Option<(&str, &str)> {
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["api", "v1", "policies", policy_id, "revisions", revision] => Some((policy_id, revision)),
        _ => None,
    }
}

fn query_parameter<'a>(query: &'a str, wanted: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == wanted).then_some(value)
    })
}

fn decode_json<T>(body: &[u8]) -> Result<T, HttpFailure>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(body).map_err(|error| HttpFailure {
        status: 400,
        code: "INVALID_JSON",
        message: error.to_string(),
        retryable: false,
        state_changed: false,
    })
}

fn result_response<T>(result: Result<T, ServiceError>) -> HttpResponse
where
    T: Serialize,
{
    result.map_or_else(
        |error| HttpFailure::from(error).response(),
        |value| json_response(200, &value),
    )
}

#[derive(Debug)]
struct HttpFailure {
    status: u16,
    code: &'static str,
    message: String,
    retryable: bool,
    state_changed: bool,
}

impl HttpFailure {
    fn response(self) -> HttpResponse {
        error_response(
            self.status,
            self.code,
            self.message,
            self.retryable,
            self.state_changed,
        )
    }
}

impl From<ServiceError> for HttpFailure {
    fn from(error: ServiceError) -> Self {
        let (status, code, retryable, state_changed) = match &error {
            ServiceError::Identifier(_)
            | ServiceError::Revision(_)
            | ServiceError::Controller(
                ControllerError::Validation(_) | ControllerError::Engine(_),
            ) => (400, "INVALID_ARGUMENT", false, false),
            ServiceError::Controller(
                ControllerError::IdempotencyConflict(_)
                | ControllerError::ImmutablePolicyConflict(_),
            ) => (409, "CONFLICT", false, false),
            ServiceError::Controller(ControllerError::UnsafeMapping(_)) => {
                (422, "UNSAFE_MAPPING", false, false)
            }
            ServiceError::Controller(ControllerError::Client(_)) => {
                (502, "AGENTSIGHT_ERROR", true, true)
            }
            ServiceError::Controller(_) => (500, "INTERNAL_ERROR", true, false),
        };
        Self {
            status,
            code,
            message: error.to_string(),
            retryable,
            state_changed,
        }
    }
}

fn json_response<T>(status: u16, value: &T) -> HttpResponse
where
    T: Serialize,
{
    match serde_json::to_vec(value) {
        Ok(body) => HttpResponse { status, body },
        Err(error) => error_response(
            500,
            "RESPONSE_ENCODING_FAILED",
            error.to_string(),
            false,
            false,
        ),
    }
}

fn error_response(
    status: u16,
    code: &'static str,
    message: String,
    retryable: bool,
    state_changed: bool,
) -> HttpResponse {
    let error = ProtocolError {
        code: code.to_owned(),
        message,
        retryable,
        state_changed,
        reconcile_action: None,
    };
    let body = serde_json::to_vec(&error).unwrap_or_else(|_| b"{}".to_vec());
    HttpResponse { status, body }
}

fn write_response(stream: &mut TcpStream, response: &HttpResponse) -> Result<(), io::Error> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    use asc_pcp::{ClientError, MemoryStateStore};
    use asc_policy_types::identifiers::PolicyId;
    use asc_policy_types::mapping::PolicyState;
    use asc_policy_types::receipt::{PullReceiptsRequest, PullReceiptsResponse};
    use asc_policy_types::reconcile::ValidationStatus;
    use asc_policy_types::state::{GetStateRequest, GetStateResponse};

    use super::*;

    struct FakeAgentSight {
        policy_calls: Mutex<usize>,
    }

    impl AgentSightClient for FakeAgentSight {
        fn reconcile_policy(
            &self,
            request: &ReconcilePolicyRequest,
        ) -> Result<ReconcilePolicyResponse, ClientError> {
            *self.policy_calls.lock().unwrap() += 1;
            let ReconcilePolicyRequest::Present {
                operation_id,
                policy,
                ..
            } = request
            else {
                panic!("test only sends PRESENT policies");
            };
            Ok(ReconcilePolicyResponse {
                operation_id: operation_id.clone(),
                state: PolicyState::Available,
                policy_id: policy.policy_id.clone(),
                revision: Some(policy.revision),
                payload_digest: policy.payload_digest.clone(),
                validation: Some(asc_policy_types::reconcile::ValidationReport {
                    status: ValidationStatus::Valid,
                    diagnostics: vec![],
                }),
                static_compile: None,
                error: None,
            })
        }

        fn reconcile_binding(
            &self,
            _request: &ReconcileBindingRequest,
        ) -> Result<ReconcileBindingResponse, ClientError> {
            panic!("binding is not used by this test");
        }

        fn get_state(&self, _request: &GetStateRequest) -> Result<GetStateResponse, ClientError> {
            panic!("state recovery is not used by this test");
        }

        fn pull_receipts(
            &self,
            _request: &PullReceiptsRequest,
        ) -> Result<PullReceiptsResponse, ClientError> {
            panic!("receipt polling is not used by this test");
        }
    }

    #[test]
    fn http_service_accepts_frozen_product_template_and_exposes_durable_state() {
        let service = Arc::new(
            PolicyService::new(
                FakeAgentSight {
                    policy_calls: Mutex::new(0),
                },
                MemoryStateStore::default(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_service = Arc::clone(&service);
        let server = thread::spawn(move || {
            serve_requests(&listener, &server_service, Some(2)).unwrap();
        });

        let template: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/pap/high-sensitivity-read.json"
        ))
        .unwrap();
        let response: CreatePolicyResponse = ureq::put(&format!(
            "http://{address}/api/v1/policies/high-sensitive-read/revisions/1"
        ))
        .set("Idempotency-Key", "test-policy-create-1")
        .send_json(template)
        .unwrap()
        .into_json()
        .unwrap();
        assert_eq!(response.policy.policy_id.as_str(), "high-sensitive-read");
        assert_eq!(response.observed.state, PolicyState::Available);

        let state: ControllerState = ureq::get(&format!("http://{address}/api/v1/state"))
            .call()
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(state.prepared_policies.len(), 1);
        assert_eq!(state.policy_operations.len(), 1);
        assert_eq!(
            state
                .prepared_policies
                .values()
                .next()
                .map(|record| &record.canonical_policy.policy_id),
            Some(&PolicyId::new("high-sensitive-read").unwrap())
        );

        server.join().unwrap();
    }
}
