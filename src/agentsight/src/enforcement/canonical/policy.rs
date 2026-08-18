//! Canonical policy revision reconciliation.

use asc_policy_types::Validate;
use asc_policy_types::identifiers::PolicyId;
use asc_policy_types::ir::{Expression, SemanticAtom};
use asc_policy_types::mapping::PolicyState;
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::protocol::Diagnostic;
use asc_policy_types::reconcile::{
    PolicyPrecondition, ReconcilePolicyRequest, ReconcilePolicyResponse, StaticCompileReport,
    StaticCompileStage, ValidationReport, ValidationStatus,
};

use super::{
    CanonicalError, CanonicalPolicyController, CanonicalState, PolicyOperationRecord, policy_key,
    validation_error,
};

const COMPILER_VERSION: &str = "agentsight-ir-v1";

pub(super) fn reconcile(
    controller: &CanonicalPolicyController,
    request: ReconcilePolicyRequest,
) -> Result<ReconcilePolicyResponse, CanonicalError> {
    let _guard = controller.lock()?;
    let mut state = controller.load_state()?;
    let operation_id = operation_id(&request).to_owned();
    if let Some(existing) = state.policy_operations.get(&operation_id) {
        return if existing.request == request {
            Ok(existing.response.clone())
        } else {
            Err(CanonicalError::OperationConflict(operation_id))
        };
    }
    request.validate().map_err(validation_error)?;
    let response = match &request {
        ReconcilePolicyRequest::Present {
            operation_id,
            policy,
            precondition,
        } => {
            verify_precondition(&state, &policy.policy_id, precondition)?;
            let key = policy_key(&policy.policy_id, policy.revision);
            let current_state = match state.policies.get(&key) {
                Some(existing) if existing != policy => {
                    return Err(CanonicalError::RevisionConflict(key));
                }
                Some(_) => PolicyState::NoChange,
                None => {
                    state.policies.insert(key, policy.clone());
                    PolicyState::Available
                }
            };
            ReconcilePolicyResponse {
                operation_id: operation_id.clone(),
                state: current_state,
                policy_id: policy.policy_id.clone(),
                revision: Some(policy.revision),
                payload_digest: policy.payload_digest.clone(),
                validation: Some(ValidationReport {
                    status: ValidationStatus::Valid,
                    diagnostics: Vec::new(),
                }),
                static_compile: Some(StaticCompileReport {
                    stage: StaticCompileStage::DeferredToBinding,
                    compiler_version: COMPILER_VERSION.into(),
                    diagnostics: static_compile_diagnostics(policy),
                }),
                error: None,
            }
        }
        ReconcilePolicyRequest::Absent {
            operation_id,
            policy_id,
            precondition,
        } => {
            verify_precondition(&state, policy_id, precondition)?;
            if state.bindings.values().any(|binding| {
                binding
                    .effective_policy
                    .as_ref()
                    .is_some_and(|policy| &policy.policy_id == policy_id)
            }) {
                return Err(CanonicalError::PolicyInUse(policy_id.to_string()));
            }
            state
                .policies
                .retain(|_, policy| &policy.policy_id != policy_id);
            ReconcilePolicyResponse {
                operation_id: operation_id.clone(),
                state: PolicyState::Absent,
                policy_id: policy_id.clone(),
                revision: None,
                payload_digest: None,
                validation: None,
                static_compile: None,
                error: None,
            }
        }
    };
    state.policy_operations.insert(
        operation_id,
        PolicyOperationRecord {
            request,
            response: response.clone(),
        },
    );
    controller.save_state(&state)?;
    Ok(response)
}

fn verify_precondition(
    state: &CanonicalState,
    policy_id: &PolicyId,
    precondition: &PolicyPrecondition,
) -> Result<(), CanonicalError> {
    let current = state
        .policies
        .values()
        .filter(|policy| &policy.policy_id == policy_id)
        .max_by_key(|policy| policy.revision);
    if precondition.expected_current_revision != current.map(|policy| policy.revision)
        && precondition.expected_current_revision.is_some()
    {
        return Err(CanonicalError::PreconditionFailed(
            "expected policy revision does not match current state".into(),
        ));
    }
    if let Some(expected) = &precondition.expected_payload_digest
        && current.and_then(|policy| policy.payload_digest.as_ref()) != Some(expected)
    {
        return Err(CanonicalError::PreconditionFailed(
            "expected payload digest does not match current state".into(),
        ));
    }
    Ok(())
}

fn static_compile_diagnostics(policy: &PolicyEnvelope) -> Vec<Diagnostic> {
    policy
        .payload
        .rules
        .iter()
        .enumerate()
        .find(|(_, rule)| {
            matches!(
                rule.when,
                Expression::Atom {
                    atom: SemanticAtom::InformationFlow { .. }
                }
            )
        })
        .map(|(index, _)| Diagnostic {
            code: "TARGET_MAPPING_DEFERRED".into(),
            path: Some(format!("payload.rules[{index}]")),
            message: "direct information flow receives its final target mapping at binding time"
                .into(),
        })
        .into_iter()
        .collect()
}

fn operation_id(request: &ReconcilePolicyRequest) -> &str {
    match request {
        ReconcilePolicyRequest::Present { operation_id, .. }
        | ReconcilePolicyRequest::Absent { operation_id, .. } => operation_id.as_str(),
    }
}
