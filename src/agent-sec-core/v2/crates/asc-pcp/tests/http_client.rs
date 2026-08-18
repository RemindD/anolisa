use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use asc_pcp::{AgentSightClient, HttpAgentSightClient, POLICIES_PATH};
use asc_policy_engine::{PolicyTemplate, TemplateEnvelope, lower_template};
use asc_policy_types::identifiers::{OperationId, PolicyId, Revision};
use asc_policy_types::mapping::PolicyState;
use asc_policy_types::reconcile::{
    PolicyPrecondition, ReconcilePolicyRequest, ReconcilePolicyResponse, StaticCompileReport,
    StaticCompileStage, ValidationReport, ValidationStatus,
};

fn request() -> ReconcilePolicyRequest {
    let policy = lower_template(TemplateEnvelope {
        policy_id: PolicyId::new("high-sensitive").unwrap(),
        revision: Revision::new(1).unwrap(),
        template: PolicyTemplate::HighSensitivityReadDeny {
            files: vec!["/secrets/**".to_owned()],
        },
    })
    .unwrap();
    ReconcilePolicyRequest::Present {
        operation_id: OperationId::new("policy-op").unwrap(),
        policy,
        precondition: PolicyPrecondition {
            expected_current_revision: None,
            expected_payload_digest: None,
        },
    }
}

fn response() -> ReconcilePolicyResponse {
    ReconcilePolicyResponse {
        operation_id: OperationId::new("policy-op").unwrap(),
        state: PolicyState::Available,
        policy_id: PolicyId::new("high-sensitive").unwrap(),
        revision: Some(Revision::new(1).unwrap()),
        payload_digest: None,
        validation: Some(ValidationReport {
            status: ValidationStatus::Valid,
            diagnostics: vec![],
        }),
        static_compile: Some(StaticCompileReport {
            stage: StaticCompileStage::DeferredToBinding,
            compiler_version: "fake-v1".to_owned(),
            diagnostics: vec![],
        }),
        error: None,
    }
}

#[test]
#[ignore = "requires permission to bind a local TCP socket"]
fn http_client_uses_the_canonical_policy_url_and_json_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let expected_response = response();
    let response_bytes = serde_json::to_vec(&expected_response).unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_bytes = read_http_request(&mut stream);
        let header_end = find_header_end(&request_bytes).unwrap();
        let headers = String::from_utf8(request_bytes[..header_end].to_vec()).unwrap();
        assert!(
            headers.starts_with(&format!("PUT {POLICIES_PATH} HTTP/1.1\r\n")),
            "unexpected request line: {headers}"
        );
        let body: serde_json::Value =
            serde_json::from_slice(&request_bytes[header_end + 4..]).unwrap();

        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_bytes.len()
        )
        .unwrap();
        stream.write_all(&response_bytes).unwrap();
        body
    });

    let desired = request();
    let client = HttpAgentSightClient::new(format!("http://{address}")).unwrap();
    let observed = client.reconcile_policy(&desired).unwrap();
    assert_eq!(observed, expected_response);
    assert_eq!(
        server.join().unwrap(),
        serde_json::to_value(desired).unwrap()
    );
}

fn read_http_request(stream: &mut impl Read) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4_096];
    loop {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "connection closed before request completed");
        request.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if request.len() >= header_end + 4 + content_length {
                return request;
            }
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}
