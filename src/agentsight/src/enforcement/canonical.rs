//! Canonical Policy IR reconciliation and binding-time ActPlane translation.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use agentsight_enforcement_protocol::{
    ApplyPolicy, Binding as RuntimeBinding, BindingState as RuntimeBindingState, PolicyMode,
};
use asc_policy_types::Validate;
use asc_policy_types::identifiers::{BindingId, Digest, PepInstanceId, PolicyId, Revision};
use asc_policy_types::mapping::{BindingState, MappingRelation, MappingReport};
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::protocol::ProtocolError;
use asc_policy_types::reconcile::{
    ReadyBindingRequest, ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse, ScopeState,
};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{EnforcementStore, EnforcementStoreError};

mod policy;
mod translation;

use translation::{CanonicalTarget, CompiledBinding, compile_binding};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyOperationRecord {
    request: ReconcilePolicyRequest,
    response: ReconcilePolicyResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingOperationRecord {
    request: ReconcileBindingRequest,
    response: Option<ReconcileBindingResponse>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalState {
    policies: BTreeMap<String, PolicyEnvelope>,
    policy_operations: BTreeMap<String, PolicyOperationRecord>,
    binding_operations: BTreeMap<String, BindingOperationRecord>,
    bindings: BTreeMap<String, ReconcileBindingResponse>,
}

/// Failures returned before a Canonical operation can produce a state response.
#[derive(Debug, Error)]
pub(crate) enum CanonicalError {
    #[error("invalid Canonical request at {path}: {message}")]
    Invalid { path: String, message: String },
    #[error("operation ID {0} was already used with a different request")]
    OperationConflict(String),
    #[error("operation ID {0} is still being reconciled")]
    OperationInProgress(String),
    #[error("immutable policy revision conflicts with {0}")]
    RevisionConflict(String),
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("effective policy {0} is not available")]
    PolicyNotFound(String),
    #[error("policy {0} is still referenced by an active binding")]
    PolicyInUse(String),
    #[error("binding removal is not implemented by the Canonical V1 creation slice")]
    BindingRemovalUnsupported,
    #[error("runtime acknowledgement does not match the prepared Canonical binding")]
    InvalidAcknowledgement,
    #[error("Canonical controller state lock is poisoned")]
    Poisoned,
    #[error("Canonical controller internal invariant failed: {0}")]
    Internal(String),
    #[error(transparent)]
    Store(#[from] EnforcementStoreError),
}

impl CanonicalError {
    pub(crate) fn protocol_error(&self) -> ProtocolError {
        let (code, retryable) = match self {
            Self::Invalid { .. } => ("INVALID_REQUEST", false),
            Self::OperationConflict(_) => ("OPERATION_ID_CONFLICT", false),
            Self::OperationInProgress(_) => ("OPERATION_IN_PROGRESS", true),
            Self::RevisionConflict(_) => ("REVISION_CONFLICT", false),
            Self::PreconditionFailed(_) => ("PRECONDITION_FAILED", false),
            Self::PolicyNotFound(_) => ("POLICY_NOT_FOUND", false),
            Self::PolicyInUse(_) => ("POLICY_IN_USE", false),
            Self::BindingRemovalUnsupported => ("UNSUPPORTED_OPERATION", false),
            Self::InvalidAcknowledgement => ("INVALID_ENFORCER_ACK", false),
            Self::Poisoned | Self::Internal(_) | Self::Store(_) => {
                ("CANONICAL_STATE_UNAVAILABLE", true)
            }
        };
        ProtocolError {
            code: code.into(),
            message: self.to_string(),
            retryable,
            state_changed: false,
            reconcile_action: None,
        }
    }
}

/// Prepared install or a terminal response that requires no PEP mutation.
pub(crate) enum BindingPlan {
    Complete(ReconcileBindingResponse),
    Install(InstallPlan),
}

/// Canonical metadata retained while the existing enforcement coordinator installs DSL.
pub(crate) struct InstallPlan {
    pub(crate) request: ReconcileBindingRequest,
    pub(crate) apply_policy: ApplyPolicy,
    mapping: MappingReport,
    mapping_digest: Digest,
    target_digest: Digest,
    pep_instance_id: PepInstanceId,
}

/// Durable Canonical policy and binding reconciler layered over the existing store.
pub(crate) struct CanonicalPolicyController {
    store: EnforcementStore,
    target: CanonicalTarget,
    lifecycle: Mutex<()>,
}

impl CanonicalPolicyController {
    pub(crate) fn new(store: EnforcementStore) -> Self {
        Self {
            store,
            target: CanonicalTarget::actplane(),
            lifecycle: Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub(super) fn new_mock(store: EnforcementStore) -> Self {
        Self {
            store,
            target: CanonicalTarget::mock_exact(),
            lifecycle: Mutex::new(()),
        }
    }

    pub(crate) fn reconcile_policy(
        &self,
        request: ReconcilePolicyRequest,
    ) -> Result<ReconcilePolicyResponse, CanonicalError> {
        policy::reconcile(self, request)
    }

    pub(crate) fn plan_binding(
        &self,
        request: ReconcileBindingRequest,
    ) -> Result<BindingPlan, CanonicalError> {
        let _guard = self.lock()?;
        let mut state = self.load_state()?;
        let operation_id = binding_operation_id(&request).to_owned();
        if let Some(existing) = state.binding_operations.get(&operation_id) {
            if existing.request != request {
                return Err(CanonicalError::OperationConflict(operation_id));
            }
            return existing
                .response
                .clone()
                .map(BindingPlan::Complete)
                .ok_or(CanonicalError::OperationInProgress(operation_id));
        }
        request.validate().map_err(validation_error)?;
        let ReconcileBindingRequest::Ready(ready) = &request else {
            return Err(CanonicalError::BindingRemovalUnsupported);
        };
        verify_binding_precondition(&state, ready)?;
        let policy = state
            .policies
            .get(&policy_key(
                &ready.effective_policy.policy_id,
                ready.effective_policy.revision,
            ))
            .filter(|policy| {
                policy.profile_id == ready.effective_policy.profile_id
                    && ready
                        .effective_policy
                        .payload_digest
                        .as_ref()
                        .is_none_or(|digest| policy.payload_digest.as_ref() == Some(digest))
            })
            .cloned()
            .ok_or_else(|| {
                CanonicalError::PolicyNotFound(format!(
                    "{}:{}",
                    ready.effective_policy.policy_id,
                    ready.effective_policy.revision.get()
                ))
            })?;
        let compiled = compile_binding(self.target, ready, &policy)?;

        if compiled.mapping.policy_relation == MappingRelation::Unsupported {
            let response = terminal_binding_response(
                ready,
                BindingState::Rejected,
                &compiled,
                Some(protocol_error(
                    "UNSUPPORTED_SEMANTICS",
                    "the selected target cannot enforce this Canonical policy",
                )),
            );
            record_binding_operation(&mut state, request, response.clone());
            self.save_state(&state)?;
            return Ok(BindingPlan::Complete(response));
        }
        if compiled.mapping.policy_relation == MappingRelation::Narrower {
            if !ready.approval.allow_narrower {
                let response = terminal_binding_response(
                    ready,
                    BindingState::ApprovalRequired,
                    &compiled,
                    Some(protocol_error(
                        "NARROWER_MAPPING_REQUIRES_APPROVAL",
                        "ActPlane blocks a wider open operation than the requested read operation",
                    )),
                );
                record_binding_operation(&mut state, request, response.clone());
                self.save_state(&state)?;
                return Ok(BindingPlan::Complete(response));
            }
            if ready.approval.expected_mapping_digest.as_ref() != Some(&compiled.mapping_digest) {
                return Err(CanonicalError::PreconditionFailed(
                    "approved mapping digest does not match the current target mapping".into(),
                ));
            }
        }
        let dsl = compiled.dsl.clone().ok_or_else(|| {
            CanonicalError::Internal("installable mapping did not produce target DSL".into())
        })?;
        let root_pid = i32::try_from(ready.identity.root_process.pid).map_err(|_| {
            CanonicalError::Invalid {
                path: "identity.rootProcess.pid".into(),
                message: "PID exceeds the AgentSight process identity range".into(),
            }
        })?;
        let apply_policy = ApplyPolicy {
            binding_id: runtime_binding_id(&ready.binding_id),
            agent_id: ready.run_id.to_string(),
            session_id: Some(ready.identity.execution_domain_id.to_string()),
            root_pid,
            process_start_time: ready.identity.root_process.start_time_ticks,
            policy_id: ready.effective_policy.policy_id.to_string(),
            policy_revision: ready.effective_policy.revision.get().to_string(),
            policy_dsl: dsl,
            policy_mode: Some(PolicyMode::Enforce),
        };
        state.binding_operations.insert(
            operation_id,
            BindingOperationRecord {
                request: request.clone(),
                response: None,
            },
        );
        self.save_state(&state)?;
        Ok(BindingPlan::Install(InstallPlan {
            request,
            apply_policy,
            mapping: compiled.mapping,
            mapping_digest: compiled.mapping_digest,
            target_digest: compiled.target_digest.ok_or_else(|| {
                CanonicalError::Internal(
                    "installable mapping did not produce a target digest".into(),
                )
            })?,
            pep_instance_id: compiled.pep_instance_id,
        }))
    }

    pub(crate) fn complete_binding(
        &self,
        plan: InstallPlan,
        acknowledgement: RuntimeBinding,
    ) -> Result<ReconcileBindingResponse, CanonicalError> {
        if acknowledgement.request != plan.apply_policy
            || acknowledgement.state != RuntimeBindingState::Enforced
            || acknowledgement.domain_id.is_none()
        {
            return Err(CanonicalError::InvalidAcknowledgement);
        }
        let ReconcileBindingRequest::Ready(ready) = &plan.request else {
            return Err(CanonicalError::Internal(
                "an install plan must contain a READY request".into(),
            ));
        };
        let response = ReconcileBindingResponse {
            operation_id: ready.operation_id.clone(),
            state: BindingState::BindingReady,
            binding_id: ready.binding_id.clone(),
            binding_revision: Some(
                Revision::new(1).map_err(|message| CanonicalError::Internal(message.into()))?,
            ),
            execution_domain_id: Some(ready.identity.execution_domain_id.clone()),
            identity_epoch: Some(ready.identity.identity_epoch),
            effective_policy: Some(ready.effective_policy.clone()),
            scope_digest: Some(ready.scope_digest.clone()),
            scope_state: Some(ScopeState::Verified),
            mapping_digest: Some(plan.mapping_digest),
            mappings: vec![plan.mapping],
            target_digests: vec![plan.target_digest],
            pep_instances: vec![plan.pep_instance_id],
            effective_at: Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
            error: None,
        };
        let _guard = self.lock()?;
        let mut state = self.load_state()?;
        let operation_id = ready.operation_id.to_string();
        let record = state
            .binding_operations
            .get_mut(&operation_id)
            .ok_or_else(|| CanonicalError::OperationInProgress(operation_id.clone()))?;
        if record.request != plan.request {
            return Err(CanonicalError::OperationConflict(operation_id));
        }
        record.response = Some(response.clone());
        state
            .bindings
            .insert(ready.binding_id.to_string(), response.clone());
        self.save_state(&state)?;
        Ok(response)
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, CanonicalError> {
        self.lifecycle.lock().map_err(|_| CanonicalError::Poisoned)
    }

    fn load_state(&self) -> Result<CanonicalState, CanonicalError> {
        self.store
            .canonical_state_json()?
            .map(|json| serde_json::from_str(&json).map_err(EnforcementStoreError::from))
            .transpose()
            .map(Option::unwrap_or_default)
            .map_err(CanonicalError::from)
    }

    fn save_state(&self, state: &CanonicalState) -> Result<(), CanonicalError> {
        let json = serde_json::to_string(state).map_err(EnforcementStoreError::from)?;
        self.store.replace_canonical_state_json(&json)?;
        Ok(())
    }
}

fn terminal_binding_response(
    ready: &ReadyBindingRequest,
    state: BindingState,
    compiled: &CompiledBinding,
    error: Option<ProtocolError>,
) -> ReconcileBindingResponse {
    ReconcileBindingResponse {
        operation_id: ready.operation_id.clone(),
        state,
        binding_id: ready.binding_id.clone(),
        binding_revision: None,
        execution_domain_id: Some(ready.identity.execution_domain_id.clone()),
        identity_epoch: Some(ready.identity.identity_epoch),
        effective_policy: Some(ready.effective_policy.clone()),
        scope_digest: Some(ready.scope_digest.clone()),
        scope_state: Some(ScopeState::Verified),
        mapping_digest: Some(compiled.mapping_digest.clone()),
        mappings: vec![compiled.mapping.clone()],
        target_digests: Vec::new(),
        pep_instances: Vec::new(),
        effective_at: None,
        error,
    }
}

fn record_binding_operation(
    state: &mut CanonicalState,
    request: ReconcileBindingRequest,
    response: ReconcileBindingResponse,
) {
    state.binding_operations.insert(
        binding_operation_id(&request).to_owned(),
        BindingOperationRecord {
            request,
            response: Some(response),
        },
    );
}

fn verify_binding_precondition(
    state: &CanonicalState,
    ready: &ReadyBindingRequest,
) -> Result<(), CanonicalError> {
    let current = state.bindings.get(ready.binding_id.as_str());
    if let Some(expected) = ready.precondition.expected_binding_revision
        && current.and_then(|binding| binding.binding_revision) != Some(expected)
    {
        return Err(CanonicalError::PreconditionFailed(
            "expected binding revision does not match current state".into(),
        ));
    }
    if let Some(current) = current
        && current.effective_policy.as_ref() != Some(&ready.effective_policy)
    {
        return Err(CanonicalError::PreconditionFailed(
            "binding ID already names a different effective policy".into(),
        ));
    }
    Ok(())
}

fn binding_operation_id(request: &ReconcileBindingRequest) -> &str {
    match request {
        ReconcileBindingRequest::Ready(request) => request.operation_id.as_str(),
        ReconcileBindingRequest::Absent { operation_id, .. } => operation_id.as_str(),
    }
}

fn policy_key(policy_id: &PolicyId, revision: Revision) -> String {
    format!("{policy_id}:{}", revision.get())
}

fn runtime_binding_id(binding_id: &BindingId) -> Uuid {
    let hash = Sha256::digest(binding_id.as_str().as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn validation_error(error: asc_policy_types::ValidationError) -> CanonicalError {
    CanonicalError::Invalid {
        path: error.path,
        message: error.message,
    }
}

fn protocol_error(code: &str, message: &str) -> ProtocolError {
    ProtocolError {
        code: code.into(),
        message: message.into(),
        retryable: false,
        state_changed: false,
        reconcile_action: None,
    }
}
