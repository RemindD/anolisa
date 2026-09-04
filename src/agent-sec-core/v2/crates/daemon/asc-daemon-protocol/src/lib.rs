//! POC-only JSON protocol adapter for Policy authoring and Binding apply.
//!
//! The service framework remains protocol-neutral. This crate owns one strict
//! JSON request envelope, an explicit four-method allowlist, PAP error mapping,
//! and transport-rejection projection. Its `poc.*` method names are not a
//! product compatibility commitment.

#![forbid(unsafe_code)]

use std::io::Write;
use std::sync::Arc;

use asc_daemon_service::{
    DispatchError, DispatchRequest, RejectedRequest, RejectionEncoder, RejectionReason,
    RequestDispatcher, ResponseDisposition,
};
use asc_foundation_types::{ResourceId, Revision};
use asc_pap::{PapError, PapRepository, PapService, PolicyCompiler};
use asc_policy_runtime::{EnqueueError, ReconcileEnqueuer};
use asc_policy_types::authoring::PolicyTemplate;
use asc_policy_types::binding::{BindingStatus, BindingView};
use asc_policy_types::scope::ScopeSelector;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// POC method for creating a Policy from a product template.
pub const POLICY_CREATE_METHOD: &str = "poc.policy.create";
/// POC method for creating a Scope selector.
pub const SCOPE_CREATE_METHOD: &str = "poc.scope.create";
/// POC method for creating and asynchronously applying a Binding.
pub const BINDING_CREATE_METHOD: &str = "poc.binding.create";
/// POC method for reading current Binding status.
pub const BINDING_GET_METHOD: &str = "poc.binding.get";

/// Strict request envelope used only by the capability-validation POC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Explicit allowlisted method name.
    pub method: String,
    /// Method-specific object.
    pub params: Value,
}

impl RequestEnvelope {
    /// Encodes one typed method request.
    ///
    /// # Errors
    /// Returns a JSON serialization failure.
    pub fn from_params<T>(method: &str, params: &T) -> Result<Self, serde_json::Error>
    where
        T: Serialize,
    {
        Ok(Self {
            method: method.to_owned(),
            params: serde_json::to_value(params)?,
        })
    }
}

/// Parameters for [`POLICY_CREATE_METHOD`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatePolicyParams {
    /// Human-readable Policy name.
    pub policy_name: String,
    /// Product-authored input read unchanged by the CLI.
    pub template: PolicyTemplate,
}

/// Parameters for [`SCOPE_CREATE_METHOD`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateScopeParams {
    /// Target-independent authored selector.
    pub selector: ScopeSelector,
}

/// Parameters for [`BINDING_CREATE_METHOD`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateBindingParams {
    /// Optional caller-provided Binding identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<ResourceId>,
    /// Exact Policy identity.
    pub policy_id: ResourceId,
    /// Exact Policy revision.
    pub policy_revision: Revision,
    /// Exact Scope identity.
    pub scope_id: ResourceId,
    /// Exact Scope revision.
    pub scope_revision: Revision,
}

/// Parameters for [`BINDING_GET_METHOD`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetBindingParams {
    /// Binding identity to query.
    pub binding_id: ResourceId,
}

/// Stable daemon error returned inside a POC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// Machine-readable category.
    pub code: String,
    /// Sanitized diagnostic.
    pub message: String,
}

/// V1-shaped response envelope retained by the Rust POC client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    /// Daemon-generated correlation identity.
    pub request_id: String,
    /// Whether method dispatch succeeded.
    pub ok: bool,
    /// Method-specific response value, or `{}` on failure.
    pub data: Value,
    /// Reserved compatibility output.
    pub stdout: String,
    /// Empty on success and equal to the error message on failure.
    pub stderr: String,
    /// Zero on success, one on failure.
    pub exit_code: i32,
    /// Structured failure, absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl ResponseEnvelope {
    fn success(data: Value) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            ok: true,
            data,
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            error: None,
        }
    }

    fn failure(code: &str, message: &str) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            ok: false,
            data: serde_json::json!({}),
            stdout: String::new(),
            stderr: message.to_owned(),
            exit_code: 1,
            error: Some(ErrorBody {
                code: code.to_owned(),
                message: message.to_owned(),
            }),
        }
    }
}

/// PAP-backed implementation of the POC Policy method family.
pub struct PapDispatcher<R, C> {
    pap: PapService<R, C>,
    repository: Arc<R>,
    queue: ReconcileEnqueuer,
}

impl<R, C> PapDispatcher<R, C> {
    /// Creates a protocol adapter around explicit application dependencies.
    pub const fn new(pap: PapService<R, C>, repository: Arc<R>, queue: ReconcileEnqueuer) -> Self {
        Self {
            pap,
            repository,
            queue,
        }
    }
}

impl<R, C> PapDispatcher<R, C>
where
    R: PapRepository,
    C: PolicyCompiler,
{
    fn handle(&self, payload: &[u8]) -> ResponseEnvelope {
        let request: RequestEnvelope = match serde_json::from_slice(payload) {
            Ok(request) => request,
            Err(_) => return ResponseEnvelope::failure("bad_request", "invalid request JSON"),
        };
        match request.method.as_str() {
            POLICY_CREATE_METHOD => {
                Self::decode_and(&request.params, |params: CreatePolicyParams| {
                    self.pap
                        .create_policy(&params.policy_name, &params.template)
                        .map(to_value)
                })
            }
            SCOPE_CREATE_METHOD => {
                Self::decode_and(&request.params, |params: CreateScopeParams| {
                    self.pap.create_scope(&params.selector).map(to_value)
                })
            }
            BINDING_CREATE_METHOD => {
                Self::decode_and(&request.params, |params: CreateBindingParams| {
                    let binding = self.pap.create_binding_with_id(
                        params.binding_id.as_ref(),
                        &params.policy_id,
                        params.policy_revision,
                        &params.scope_id,
                        params.scope_revision,
                    )?;
                    match self.queue.enqueue(&binding) {
                        Ok(()) => Ok(to_value(binding)),
                        Err(error) => {
                            self.mark_enqueue_failure(&binding, error);
                            self.repository
                                .get_binding(&binding.spec.binding_id)
                                .map(to_value)
                        }
                    }
                })
            }
            BINDING_GET_METHOD => Self::decode_and(&request.params, |params: GetBindingParams| {
                self.pap.get_binding(&params.binding_id).map(to_value)
            }),
            _ => ResponseEnvelope::failure("unknown_method", "unknown daemon method"),
        }
    }

    fn decode_and<T, F>(params: &Value, operation: F) -> ResponseEnvelope
    where
        T: DeserializeOwned,
        F: FnOnce(T) -> Result<Result<Value, serde_json::Error>, PapError>,
    {
        let Ok(params) = serde_json::from_value(params.clone()) else {
            return ResponseEnvelope::failure("bad_request", "invalid method params");
        };
        match operation(params) {
            Ok(Ok(data)) => ResponseEnvelope::success(data),
            Ok(Err(_)) => ResponseEnvelope::failure("internal_error", "daemon internal error"),
            Err(error) => pap_failure(&error),
        }
    }

    fn mark_enqueue_failure(&self, binding: &BindingView, _error: EnqueueError) {
        let id = &binding.spec.binding_id;
        let revision = binding.spec.binding_revision;
        if self
            .repository
            .update_binding_status(
                id,
                revision,
                BindingStatus::PendingApply,
                BindingStatus::Applying,
            )
            .is_ok()
        {
            let _ = self.repository.update_binding_status(
                id,
                revision,
                BindingStatus::Applying,
                BindingStatus::ApplyFailed,
            );
        }
    }
}

impl<R, C> RequestDispatcher for PapDispatcher<R, C>
where
    R: PapRepository + 'static,
    C: PolicyCompiler + 'static,
{
    fn dispatch(
        &self,
        request: DispatchRequest,
        response: &mut dyn Write,
    ) -> Result<ResponseDisposition, DispatchError> {
        if request.control.is_cancelled() {
            return Ok(ResponseDisposition::Close);
        }
        write_response(response, &self.handle(&request.payload))?;
        Ok(ResponseDisposition::Send)
    }
}

/// Protocol-only projection of failures owned by the service framework.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonRejectionEncoder;

impl RejectionEncoder for JsonRejectionEncoder {
    fn encode_rejection(
        &self,
        request: RejectedRequest,
        response: &mut dyn Write,
    ) -> Result<ResponseDisposition, DispatchError> {
        let (code, message) = match request.reason {
            RejectionReason::Busy => ("busy", "daemon is busy"),
            RejectionReason::ShuttingDown => ("shutdown", "daemon is shutting down"),
            RejectionReason::RequestReadTimeout | RejectionReason::DispatchTimedOut => {
                ("timeout", "daemon request timed out")
            }
            RejectionReason::RequestFrameTooLarge | RejectionReason::ResponseFrameTooLarge => (
                "payload_too_large",
                "daemon payload exceeds the configured limit",
            ),
            RejectionReason::EmptyRequest => ("bad_request", "empty daemon request"),
            RejectionReason::DispatchFailed | RejectionReason::InvalidResponseFrame => {
                ("internal_error", "daemon internal error")
            }
        };
        write_response(response, &ResponseEnvelope::failure(code, message))?;
        Ok(ResponseDisposition::Send)
    }
}

fn to_value<T>(value: T) -> Result<Value, serde_json::Error>
where
    T: Serialize,
{
    serde_json::to_value(value)
}

fn pap_failure(error: &PapError) -> ResponseEnvelope {
    let (code, message) = match error {
        PapError::InvalidIdentifier(_)
        | PapError::InvalidPolicyName(_)
        | PapError::InvalidPolicy(_)
        | PapError::InvalidScope(_)
        | PapError::InvalidBinding(_)
        | PapError::InvalidPagination => ("bad_request", "invalid Policy request"),
        PapError::NotFound => ("not_found", "Policy record not found"),
        PapError::Conflict | PapError::OperationInProgress => {
            ("conflict", "Policy request conflicts with current state")
        }
        PapError::RevisionExhausted | PapError::Serialization | PapError::Persistence => {
            ("internal_error", "daemon internal error")
        }
    };
    ResponseEnvelope::failure(code, message)
}

fn write_response(
    writer: &mut dyn Write,
    response: &ResponseEnvelope,
) -> Result<(), DispatchError> {
    serde_json::to_writer(writer, response).map_err(|_| DispatchError)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use asc_agentsight_client::{AgentSightClientError, AgentSightDeploymentState};
    use asc_policy_runtime::{
        BindingDeploymentClient, InMemoryPapRepository, PocPolicyCompiler, reconciliation_queue,
    };
    use asc_policy_types::target::TargetBindingPlan;

    use super::*;

    #[derive(Default)]
    struct FakeClient {
        calls: AtomicUsize,
    }

    impl BindingDeploymentClient for FakeClient {
        fn apply(
            &self,
            _plan: &TargetBindingPlan,
        ) -> Result<AgentSightDeploymentState, AgentSightClientError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(AgentSightDeploymentState::Present)
        }
    }

    fn request<T: Serialize>(method: &str, params: &T) -> Vec<u8> {
        serde_json::to_vec(&RequestEnvelope::from_params(method, params).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn four_method_flow_reaches_ready_through_the_async_worker() {
        let repository = Arc::new(InMemoryPapRepository::default());
        let client = Arc::new(FakeClient::default());
        let pap = PapService::new(Arc::clone(&repository), Arc::new(PocPolicyCompiler));
        let (queue, worker) = reconciliation_queue(
            NonZeroUsize::new(4).unwrap(),
            Arc::clone(&repository),
            Arc::clone(&client),
        );
        let dispatcher = PapDispatcher::new(pap, Arc::clone(&repository), queue);
        let worker = tokio::spawn(worker.run());

        let template: PolicyTemplate = serde_json::from_str(include_str!(
            "../../../../fixtures/pap/prevent-file-deletion.json"
        ))
        .unwrap();
        let policy_response = dispatcher.handle(&request(
            POLICY_CREATE_METHOD,
            &CreatePolicyParams {
                policy_name: "protect files".to_owned(),
                template,
            },
        ));
        let policy: asc_policy_types::policy::PreparedPolicy =
            serde_json::from_value(policy_response.data).unwrap();
        let scope_response = dispatcher.handle(&request(
            SCOPE_CREATE_METHOD,
            &CreateScopeParams {
                selector: ScopeSelector::Pid { pid: 4242 },
            },
        ));
        let scope: asc_policy_types::scope::PreparedScope =
            serde_json::from_value(scope_response.data).unwrap();
        let binding_response = dispatcher.handle(&request(
            BINDING_CREATE_METHOD,
            &CreateBindingParams {
                binding_id: None,
                policy_id: policy.policy_id,
                policy_revision: policy.revision,
                scope_id: scope.scope_id,
                scope_revision: scope.revision,
            },
        ));
        let binding: BindingView = serde_json::from_value(binding_response.data).unwrap();
        assert_eq!(binding.status, BindingStatus::PendingApply);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let response = dispatcher.handle(&request(
                    BINDING_GET_METHOD,
                    &GetBindingParams {
                        binding_id: binding.spec.binding_id.clone(),
                    },
                ));
                let current: BindingView = serde_json::from_value(response.data).unwrap();
                if current.status == BindingStatus::Ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(client.calls.load(Ordering::Relaxed), 1);

        drop(dispatcher);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn binding_create_accepts_a_caller_provided_identity() {
        let repository = Arc::new(InMemoryPapRepository::default());
        let client = Arc::new(FakeClient::default());
        let pap = PapService::new(Arc::clone(&repository), Arc::new(PocPolicyCompiler));
        let (queue, _worker) = reconciliation_queue(
            NonZeroUsize::new(4).unwrap(),
            Arc::clone(&repository),
            client,
        );
        let dispatcher = PapDispatcher::new(pap, repository, queue);

        let template: PolicyTemplate = serde_json::from_str(include_str!(
            "../../../../fixtures/pap/prevent-file-deletion.json"
        ))
        .unwrap();
        let policy_response = dispatcher.handle(&request(
            POLICY_CREATE_METHOD,
            &CreatePolicyParams {
                policy_name: "protect files".to_owned(),
                template,
            },
        ));
        let policy: asc_policy_types::policy::PreparedPolicy =
            serde_json::from_value(policy_response.data).unwrap();
        let scope_response = dispatcher.handle(&request(
            SCOPE_CREATE_METHOD,
            &CreateScopeParams {
                selector: ScopeSelector::Pid { pid: 4242 },
            },
        ));
        let scope: asc_policy_types::scope::PreparedScope =
            serde_json::from_value(scope_response.data).unwrap();
        let binding_id = ResourceId::new("30000000-0000-4000-8000-000000000001").unwrap();
        let params = CreateBindingParams {
            binding_id: Some(binding_id.clone()),
            policy_id: policy.policy_id,
            policy_revision: policy.revision,
            scope_id: scope.scope_id,
            scope_revision: scope.revision,
        };

        let binding_response = dispatcher.handle(&request(BINDING_CREATE_METHOD, &params));
        let binding: BindingView = serde_json::from_value(binding_response.data).unwrap();
        assert_eq!(binding.spec.binding_id, binding_id);
        assert_eq!(binding.spec.binding_revision.get(), 1);
        assert_eq!(binding.status, BindingStatus::PendingApply);

        let duplicate = dispatcher.handle(&request(BINDING_CREATE_METHOD, &params));
        assert_eq!(duplicate.error.unwrap().code, "conflict");
    }

    #[test]
    fn malformed_and_unknown_requests_are_stable_daemon_failures() {
        let repository = Arc::new(InMemoryPapRepository::default());
        let client = Arc::new(FakeClient::default());
        let pap = PapService::new(Arc::clone(&repository), Arc::new(PocPolicyCompiler));
        let (queue, _worker) = reconciliation_queue(
            NonZeroUsize::new(1).unwrap(),
            Arc::clone(&repository),
            client,
        );
        let dispatcher = PapDispatcher::new(pap, repository, queue);

        let malformed = dispatcher.handle(b"not-json");
        assert_eq!(malformed.error.unwrap().code, "bad_request");
        let unknown = dispatcher.handle(&request("poc.missing", &serde_json::json!({})));
        assert_eq!(unknown.error.unwrap().code, "unknown_method");
    }

    #[test]
    fn frozen_request_fixtures_cover_the_complete_poc_allowlist() {
        let fixtures = [
            (
                include_str!("../../../../fixtures/daemon/poc-policy-create.request.json"),
                POLICY_CREATE_METHOD,
            ),
            (
                include_str!("../../../../fixtures/daemon/poc-scope-create.request.json"),
                SCOPE_CREATE_METHOD,
            ),
            (
                include_str!("../../../../fixtures/daemon/poc-binding-create.request.json"),
                BINDING_CREATE_METHOD,
            ),
            (
                include_str!("../../../../fixtures/daemon/poc-binding-create-with-id.request.json"),
                BINDING_CREATE_METHOD,
            ),
            (
                include_str!("../../../../fixtures/daemon/poc-binding-get.request.json"),
                BINDING_GET_METHOD,
            ),
        ];
        for (fixture, expected_method) in fixtures {
            let request: RequestEnvelope = serde_json::from_str(fixture).unwrap();
            assert_eq!(request.method, expected_method);
            match expected_method {
                POLICY_CREATE_METHOD => {
                    serde_json::from_value::<CreatePolicyParams>(request.params).unwrap();
                }
                SCOPE_CREATE_METHOD => {
                    serde_json::from_value::<CreateScopeParams>(request.params).unwrap();
                }
                BINDING_CREATE_METHOD => {
                    serde_json::from_value::<CreateBindingParams>(request.params).unwrap();
                }
                BINDING_GET_METHOD => {
                    serde_json::from_value::<GetBindingParams>(request.params).unwrap();
                }
                _ => unreachable!("fixture list contains only allowlisted methods"),
            }
        }
    }
}
