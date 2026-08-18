//! End-to-end contract test across the service HTTP boundary and a mock `AgentSight` server.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asc_pcp::ControllerState;
use asc_policy_types::mapping::BindingState;
use asc_policy_types::reconcile::ReconcileBindingResponse;

const POLICY_HIGH_REQUEST: &str =
    include_str!("../../../fixtures/pcp-agentsight/policy-present-high.request.json");
const POLICY_HIGH_RESPONSE: &str =
    include_str!("../../../fixtures/pcp-agentsight/policy-present-high.response.json");
const POLICY_LOW_REQUEST: &str =
    include_str!("../../../fixtures/pcp-agentsight/policy-present-low-egress.request.json");
const POLICY_LOW_RESPONSE: &str =
    include_str!("../../../fixtures/pcp-agentsight/policy-present-low-egress.response.json");
const BINDING_EXACT_REQUEST: &str =
    include_str!("../../../fixtures/pcp-agentsight/binding-exact.request.json");
const BINDING_EXACT_RESPONSE: &str =
    include_str!("../../../fixtures/pcp-agentsight/binding-exact.response.json");
const BINDING_UNSUPPORTED_REQUEST: &str =
    include_str!("../../../fixtures/pcp-agentsight/binding-direct-flow-unsupported.request.json");
const BINDING_UNSUPPORTED_RESPONSE: &str =
    include_str!("../../../fixtures/pcp-agentsight/binding-direct-flow-unsupported.response.json");
const PAP_HIGH: &str = include_str!("../../../fixtures/pap/high-sensitivity-read.json");
const PAP_LOW: &str = include_str!("../../../fixtures/pap/low-sensitivity-egress.json");
const AGENTSIGHT_TOKEN: &str = "e2e-agentsight-token-0123456789abcdef";

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: serde_json::Value,
}

struct ServiceProcess {
    child: Child,
    state_file: PathBuf,
    token_file: PathBuf,
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.state_file);
        let _ = fs::remove_file(&self.token_file);
    }
}

#[test]
fn frozen_inputs_produce_the_frozen_agentsight_requests() {
    let responses = [
        POLICY_HIGH_RESPONSE,
        POLICY_LOW_RESPONSE,
        BINDING_EXACT_RESPONSE,
        BINDING_UNSUPPORTED_RESPONSE,
    ];
    let agentsight_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let agentsight_address = agentsight_listener.local_addr().unwrap();
    let agentsight = thread::spawn(move || mock_agentsight(&agentsight_listener, &responses));

    let service_address = unused_address();
    let mut service = start_service(service_address, agentsight_address);
    wait_until_ready(service_address, &mut service.child);

    put_policy(
        service_address,
        "high-sensitive-read",
        "policy-high-op-1",
        PAP_HIGH,
    );
    put_policy(
        service_address,
        "low-sensitivity-egress",
        "policy-low-op-1",
        PAP_LOW,
    );
    put_binding(service_address, BINDING_EXACT_REQUEST);
    let rejected: ReconcileBindingResponse =
        put_binding(service_address, BINDING_UNSUPPORTED_REQUEST)
            .into_json()
            .unwrap();
    assert_eq!(rejected.state, BindingState::Rejected);

    let state: ControllerState = ureq::get(&format!("http://{service_address}/api/v1/state"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(state.prepared_policies.len(), 2);
    assert_eq!(state.policy_operations.len(), 2);
    assert_eq!(state.binding_operations.len(), 2);

    let captured = agentsight.join().unwrap();
    let expected = [
        ("/api/enforcement/v1/policies", POLICY_HIGH_REQUEST),
        ("/api/enforcement/v1/policies", POLICY_LOW_REQUEST),
        ("/api/enforcement/v1/bindings", BINDING_EXACT_REQUEST),
        ("/api/enforcement/v1/bindings", BINDING_UNSUPPORTED_REQUEST),
    ];
    assert_eq!(captured.len(), expected.len());
    for (actual, (expected_path, expected_json)) in captured.iter().zip(expected) {
        assert_eq!(actual.method, "PUT");
        assert_eq!(actual.path, expected_path);
        assert_eq!(
            actual.authorization.as_deref(),
            Some("Bearer e2e-agentsight-token-0123456789abcdef")
        );
        assert_eq!(
            actual.body,
            serde_json::from_str::<serde_json::Value>(expected_json).unwrap()
        );
    }
}

fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn start_service(service_address: SocketAddr, agentsight_address: SocketAddr) -> ServiceProcess {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let state_file = std::env::temp_dir().join(format!(
        "asc-policy-service-e2e-{}-{unique}.json",
        std::process::id()
    ));
    let token_file = std::env::temp_dir().join(format!(
        "asc-policy-service-e2e-{}-{unique}.token",
        std::process::id()
    ));
    fs::write(&token_file, format!("{AGENTSIGHT_TOKEN}\n")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_asc-policy-service"))
        .args([
            "--listen",
            &service_address.to_string(),
            "--agentsight-url",
            &format!("http://{agentsight_address}"),
            "--agentsight-token-file",
            token_file.to_str().unwrap(),
            "--state-file",
        ])
        .arg(&state_file)
        .args(["--reconcile-interval-seconds", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ServiceProcess {
        child,
        state_file,
        token_file,
    }
}

fn wait_until_ready(address: SocketAddr, child: &mut Child) {
    let health_url = format!("http://{address}/healthz");
    for _ in 0..100 {
        if child.try_wait().unwrap().is_some() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                pipe.read_to_string(&mut stderr).unwrap();
            }
            panic!("asc-policy-service exited before readiness: {stderr}");
        }
        if ureq::get(&health_url).call().is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("asc-policy-service did not become ready at {health_url}");
}

fn put_policy(address: SocketAddr, policy_id: &str, operation_id: &str, template: &str) {
    let body: serde_json::Value = serde_json::from_str(template).unwrap();
    ureq::put(&format!(
        "http://{address}/api/v1/policies/{policy_id}/revisions/1"
    ))
    .set("Idempotency-Key", operation_id)
    .send_json(body)
    .unwrap();
}

fn put_binding(address: SocketAddr, request: &str) -> ureq::Response {
    let body: serde_json::Value = serde_json::from_str(request).unwrap();
    ureq::put(&format!("http://{address}/api/v1/bindings"))
        .send_json(body)
        .unwrap()
}

fn mock_agentsight(listener: &TcpListener, responses: &[&str]) -> Vec<CapturedRequest> {
    responses
        .iter()
        .map(|response| {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            write_json_response(&mut stream, response);
            request
        })
        .collect()
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "connection closed before request headers");
        bytes.extend_from_slice(&chunk[..read]);
    };
    let headers = std::str::from_utf8(&bytes[..header_end - 4]).unwrap();
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().unwrap();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap().to_owned();
    let path = request_parts.next().unwrap().to_owned();
    let mut content_length = None;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse::<usize>().unwrap());
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim().to_owned());
        }
    }
    let content_length = content_length.unwrap();
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "connection closed before request body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    let body = serde_json::from_slice(&bytes[header_end..header_end + content_length]).unwrap();
    CapturedRequest {
        method,
        path,
        authorization,
        body,
    }
}

fn write_json_response(stream: &mut TcpStream, body: &str) {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    stream.flush().unwrap();
}
