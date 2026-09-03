use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asc_agentsight_client::{
    AgentSightClient, AgentSightHttpMethod, AgentSightHttpRequest, AgentSightHttpResponse,
    AgentSightTransport, AgentSightTransportError, ProcessIdentityError, ProcessIdentityResolver,
};
use asc_cli::{Cli, ParseOutcome};
use asc_daemon::{BootstrapConfig, serve_policy_poc};
use asc_daemon_service::ShutdownToken;
use asc_policy_types::binding::{BindingStatus, BindingView};
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::scope::PreparedScope;

#[derive(Clone, Default)]
struct FakeAgentSightTransport {
    requests: Arc<Mutex<Vec<AgentSightHttpRequest>>>,
}

impl AgentSightTransport for FakeAgentSightTransport {
    fn send(
        &self,
        request: &AgentSightHttpRequest,
    ) -> Result<AgentSightHttpResponse, AgentSightTransportError> {
        self.requests.lock().unwrap().push(request.clone());
        let body = match request.method {
            AgentSightHttpMethod::Get => serde_json::to_vec(&serde_json::json!({
                "ready": true,
                "backend": "actplane",
                "capabilities": {"file_delete_guard": true}
            }))
            .unwrap(),
            AgentSightHttpMethod::Post => {
                let applied: serde_json::Value =
                    serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
                serde_json::to_vec(&serde_json::json!({
                    "request": applied,
                    "state": "enforced",
                    "domain_id": 41
                }))
                .unwrap()
            }
            AgentSightHttpMethod::Delete => unreachable!("the Apply-only POC never deletes"),
        };
        Ok(AgentSightHttpResponse { status: 200, body })
    }
}

#[derive(Debug, Clone, Copy)]
struct FixedProcessIdentity;

impl ProcessIdentityResolver for FixedProcessIdentity {
    fn process_start_time(&self, _pid: i32) -> Result<u64, ProcessIdentityError> {
        Ok(987_654)
    }
}

async fn wait_for_socket(path: &Path) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("daemon should bind its socket");
}

async fn run_cli(arguments: Vec<String>) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let ParseOutcome::Run(cli) = Cli::parse_from(arguments).unwrap() else {
            panic!("expected executable CLI")
        };
        cli.execute().unwrap()
    })
    .await
    .unwrap()
}

fn base_args(socket: &Path) -> Vec<String> {
    vec![
        "asc-cli".to_owned(),
        "--socket".to_owned(),
        socket.to_string_lossy().into_owned(),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_to_daemon_to_adapter_worker_reaches_ready() {
    let directory = std::env::temp_dir().join(format!("asc-policy-poc-e2e-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let socket = directory.join("daemon.sock");
    let template = directory.join("policy.json");
    std::fs::write(
        &template,
        include_str!("../../../fixtures/pap/prevent-file-deletion.json"),
    )
    .unwrap();

    let transport = FakeAgentSightTransport::default();
    let requests = Arc::clone(&transport.requests);
    let client = Arc::new(AgentSightClient::with_dependencies(
        transport,
        FixedProcessIdentity,
    ));
    let shutdown = ShutdownToken::new();
    let service = tokio::spawn(serve_policy_poc(
        BootstrapConfig::new(&socket),
        Arc::clone(&client),
        shutdown.clone(),
    ));
    wait_for_socket(&socket).await;

    let mut policy_args = base_args(&socket);
    policy_args.extend([
        "policy".to_owned(),
        "create".to_owned(),
        "--name".to_owned(),
        "protect files".to_owned(),
        "--file".to_owned(),
        template.to_string_lossy().into_owned(),
    ]);
    let policy: PreparedPolicy = serde_json::from_value(run_cli(policy_args).await).unwrap();

    let mut scope_args = base_args(&socket);
    scope_args.extend([
        "scope".to_owned(),
        "create".to_owned(),
        "--pid".to_owned(),
        std::process::id().to_string(),
    ]);
    let scope: PreparedScope = serde_json::from_value(run_cli(scope_args).await).unwrap();

    let mut binding_args = base_args(&socket);
    binding_args.extend([
        "binding".to_owned(),
        "create".to_owned(),
        "--policy-id".to_owned(),
        policy.policy_id.to_string(),
        "--policy-revision".to_owned(),
        policy.revision.get().to_string(),
        "--scope-id".to_owned(),
        scope.scope_id.to_string(),
        "--scope-revision".to_owned(),
        scope.revision.get().to_string(),
    ]);
    let binding: BindingView = serde_json::from_value(run_cli(binding_args).await).unwrap();
    assert_eq!(binding.status, BindingStatus::PendingApply);

    let ready = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut get_args = base_args(&socket);
            get_args.extend([
                "binding".to_owned(),
                "get".to_owned(),
                "--binding-id".to_owned(),
                binding.spec.binding_id.to_string(),
            ]);
            let current: BindingView = serde_json::from_value(run_cli(get_args).await).unwrap();
            if current.status == BindingStatus::Ready {
                break current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("binding should reach READY");
    assert_eq!(ready.spec, binding.spec);

    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, AgentSightHttpMethod::Get);
        assert_eq!(requests[1].method, AgentSightHttpMethod::Post);
        let apply: serde_json::Value =
            serde_json::from_slice(requests[1].body.as_deref().unwrap()).unwrap();
        assert_eq!(apply["root_pid"], std::process::id());
        assert_eq!(apply["process_start_time"], 987_654);
        assert!(
            apply["policy_dsl"]
                .as_str()
                .unwrap()
                .contains("block unlink")
        );
    }

    shutdown.request();
    service.await.unwrap().unwrap();
    std::fs::remove_file(template).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
