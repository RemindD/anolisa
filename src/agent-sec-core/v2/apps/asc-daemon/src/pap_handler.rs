use std::sync::Arc;

use asc_daemon_core::{
    PeerCredentials, PolicyAdministration, PolicyAdministrationError, Principal, PrincipalRole,
};
use asc_daemon_protocol::method::{BindingMethod, PapMethod, PolicyMethod, ScopeMethod};
use asc_daemon_protocol::{
    CreateBindingParams, CreateBindingResult, CreatePolicyParams, CreatePolicyResult,
    CreateScopeParams, CreateScopeResult, DaemonResponse, DeleteBindingResult, DeletePolicyResult,
    DeleteScopeResult, GetBindingResult, GetPolicyResult, GetScopeResult, ListBindingsResult,
    ListParams, ListPoliciesResult, ListScopesResult, RequestId, ResourceParams, RevisionParams,
    UpdateBindingParams, UpdateBindingResult, UpdatePolicyParams, UpdatePolicyResult,
    UpdateScopeParams, UpdateScopeResult, error_code,
};

/// PAP-specific protocol adapter with its infrastructure types erased.
pub(super) struct PapHandler {
    application: Arc<dyn PolicyAdministration>,
}

impl PapHandler {
    pub(super) fn new(application: impl PolicyAdministration + 'static) -> Self {
        Self {
            application: Arc::new(application),
        }
    }

    pub(super) fn handle(
        &self,
        request_id: RequestId,
        peer: PeerCredentials,
        method: PapMethod,
        params: serde_json::Value,
    ) -> DaemonResponse {
        // TODO(daemon-auth): local socket admission is sufficient only for
        // transport bring-up. Before production use, bind the kernel-authenticated
        // peer to reviewed server-side authorization policy instead of granting
        // every admitted peer Policy administration authority.
        let principal =
            Principal::from_authenticated_peer(peer, PrincipalRole::PolicyAdministrator);

        match dispatch(method, params, self.application.as_ref(), &principal) {
            Ok(result) => DaemonResponse::success(request_id, result),
            Err(DispatchError::BadRequest) => DaemonResponse::error(
                request_id,
                error_code::INVALID_REQUEST,
                "method parameters are invalid",
            ),
            Err(DispatchError::Application(PolicyAdministrationError::Forbidden)) => {
                DaemonResponse::error(
                    request_id,
                    error_code::PERMISSION_DENIED,
                    "principal is not authorized to administer policy",
                )
            }
            Err(
                DispatchError::Application(PolicyAdministrationError::Internal)
                | DispatchError::Projection,
            ) => DaemonResponse::error(
                request_id,
                error_code::INTERNAL,
                "policy state could not be processed",
            ),
            Err(DispatchError::Application(error)) => {
                let (code, message) = project_application_error(&error);
                DaemonResponse::error(request_id, code, message)
            }
        }
    }
}

fn dispatch(
    method: PapMethod,
    params: serde_json::Value,
    application: &dyn PolicyAdministration,
    principal: &Principal,
) -> Result<serde_json::Value, DispatchError> {
    match method {
        PapMethod::Policy(method) => dispatch_policy(method, params, application, principal),
        PapMethod::Scope(method) => dispatch_scope(method, params, application, principal),
        PapMethod::Binding(method) => dispatch_binding(method, params, application, principal),
    }
}

fn dispatch_policy(
    method: PolicyMethod,
    params: serde_json::Value,
    application: &dyn PolicyAdministration,
    principal: &Principal,
) -> Result<serde_json::Value, DispatchError> {
    match method {
        PolicyMethod::Create => {
            let input: CreatePolicyParams = decode(params)?;
            let policy =
                application.create_policy(principal, &input.policy_name, &input.template)?;
            encode(&CreatePolicyResult { policy })
        }
        PolicyMethod::Update => {
            let input: UpdatePolicyParams = decode(params)?;
            let policy = application.update_policy(
                principal,
                &input.policy_id,
                &input.policy_name,
                &input.template,
            )?;
            encode(&UpdatePolicyResult { policy })
        }
        PolicyMethod::Get => {
            let input: RevisionParams = decode(params)?;
            let policy = application.get_policy(principal, &input.id, input.revision)?;
            encode(&GetPolicyResult { policy })
        }
        PolicyMethod::List => {
            let input: ListParams = decode(params)?;
            let page = application.list_policies(principal, input.limit, input.offset)?;
            encode(&ListPoliciesResult {
                items: page.items,
                total: page.total,
            })
        }
        PolicyMethod::Delete => {
            let input: RevisionParams = decode(params)?;
            let policy =
                application.delete_policy_revision(principal, &input.id, input.revision)?;
            encode(&DeletePolicyResult { policy })
        }
    }
}

fn dispatch_scope(
    method: ScopeMethod,
    params: serde_json::Value,
    application: &dyn PolicyAdministration,
    principal: &Principal,
) -> Result<serde_json::Value, DispatchError> {
    match method {
        ScopeMethod::Create => {
            let input: CreateScopeParams = decode(params)?;
            let scope = application.create_scope(principal, &input.selector)?;
            encode(&CreateScopeResult { scope })
        }
        ScopeMethod::Update => {
            let input: UpdateScopeParams = decode(params)?;
            let scope = application.update_scope(principal, &input.scope_id, &input.selector)?;
            encode(&UpdateScopeResult { scope })
        }
        ScopeMethod::Get => {
            let input: RevisionParams = decode(params)?;
            let scope = application.get_scope(principal, &input.id, input.revision)?;
            encode(&GetScopeResult { scope })
        }
        ScopeMethod::List => {
            let input: ListParams = decode(params)?;
            let page = application.list_scopes(principal, input.limit, input.offset)?;
            encode(&ListScopesResult {
                items: page.items,
                total: page.total,
            })
        }
        ScopeMethod::Delete => {
            let input: RevisionParams = decode(params)?;
            let scope = application.delete_scope_revision(principal, &input.id, input.revision)?;
            encode(&DeleteScopeResult { scope })
        }
    }
}

fn dispatch_binding(
    method: BindingMethod,
    params: serde_json::Value,
    application: &dyn PolicyAdministration,
    principal: &Principal,
) -> Result<serde_json::Value, DispatchError> {
    match method {
        BindingMethod::Create => {
            let input: CreateBindingParams = decode(params)?;
            let binding = application.create_binding(
                principal,
                &input.policy_id,
                input.policy_revision,
                &input.scope_id,
                input.scope_revision,
            )?;
            encode(&CreateBindingResult { binding })
        }
        BindingMethod::Update => {
            let input: UpdateBindingParams = decode(params)?;
            let binding = application.update_binding(
                principal,
                &input.binding_id,
                &input.policy_id,
                input.policy_revision,
                &input.scope_id,
                input.scope_revision,
            )?;
            encode(&UpdateBindingResult { binding })
        }
        BindingMethod::Get => {
            let input: ResourceParams = decode(params)?;
            let binding = application.get_binding(principal, &input.id)?;
            encode(&GetBindingResult { binding })
        }
        BindingMethod::List => {
            let input: ListParams = decode(params)?;
            let page = application.list_bindings(principal, input.limit, input.offset)?;
            encode(&ListBindingsResult {
                items: page.items,
                total: page.total,
            })
        }
        BindingMethod::Delete => {
            let input: ResourceParams = decode(params)?;
            let binding = application.delete_binding(principal, &input.id)?;
            encode(&DeleteBindingResult { binding })
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(params: serde_json::Value) -> Result<T, DispatchError> {
    serde_json::from_value(params).map_err(|_| DispatchError::BadRequest)
}

fn encode<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, DispatchError> {
    serde_json::to_value(value).map_err(|_| DispatchError::Projection)
}

enum DispatchError {
    BadRequest,
    Application(PolicyAdministrationError),
    Projection,
}

impl From<PolicyAdministrationError> for DispatchError {
    fn from(value: PolicyAdministrationError) -> Self {
        Self::Application(value)
    }
}

fn project_application_error(error: &PolicyAdministrationError) -> (&'static str, &'static str) {
    match error {
        PolicyAdministrationError::InvalidArgument => (
            error_code::INVALID_ARGUMENT,
            "policy input failed domain validation",
        ),
        PolicyAdministrationError::Conflict => {
            (error_code::CONFLICT, "immutable revision conflict")
        }
        PolicyAdministrationError::NotFound => (
            error_code::NOT_FOUND,
            "requested policy resource was not found",
        ),
        PolicyAdministrationError::ResourceExhausted => (
            error_code::RESOURCE_EXHAUSTED,
            "revision space is exhausted",
        ),
        PolicyAdministrationError::Forbidden | PolicyAdministrationError::Internal => {
            (error_code::INTERNAL, "policy state could not be processed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_error_projection_does_not_expose_internal_failures() {
        assert_eq!(
            project_application_error(&PolicyAdministrationError::NotFound),
            ("not_found", "requested policy resource was not found")
        );
        assert_eq!(
            project_application_error(&PolicyAdministrationError::Internal),
            (error_code::INTERNAL, "policy state could not be processed")
        );
    }
}
