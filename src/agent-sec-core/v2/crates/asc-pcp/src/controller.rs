//! Idempotent PCP reconciliation controller.

use std::sync::Mutex;
use std::{collections::HashSet, fmt::Debug};

use asc_policy_engine::{EngineError, TemplateEnvelope, lower_template};
use asc_policy_types::Validate;
use asc_policy_types::identifiers::OperationId;
use asc_policy_types::mapping::{BindingState, MappingRelation, PolicyState};
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::receipt::{PullReceiptsRequest, Receipt};
use asc_policy_types::reconcile::{
    ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse,
};
use asc_policy_types::state::{GetStateRequest, GetStateResponse};

use crate::client::{AgentSightClient, ClientError};
use crate::store::{
    BindingOperationRecord, ControllerState, PolicyOperationRecord, PreparedPolicyRecord,
    StateStore, StoreError,
};

/// PCP control-loop failure.
#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    /// Product template lowering failed.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// A shared request or receipt invariant failed.
    #[error("invalid control-plane data: {0}")]
    Validation(#[from] asc_policy_types::ValidationError),
    /// Persistent state failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// `AgentSight` communication or protocol failed.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// One operation ID was reused for another request body.
    #[error("operation ID {0} was reused with different content")]
    IdempotencyConflict(String),
    /// One immutable product policy revision was reused for another template.
    #[error("prepared policy {0} was reused with different content")]
    ImmutablePolicyConflict(String),
    /// `AgentSight` reported a mapping that PCP cannot authorize for activation.
    #[error("binding mapping is not authorized: {0}")]
    UnsafeMapping(String),
    /// A process-local controller lock was poisoned.
    #[error("controller state lock was poisoned")]
    Poisoned,
    /// A repeated receipt ID carried different evidence.
    #[error("receipt ID {0} was reused with different content")]
    ReceiptConflict(String),
    /// An `AgentSight` response does not correlate to the desired operation.
    #[error("AgentSight response correlation failed: {0}")]
    ResponseCorrelation(String),
    /// `AgentSight` returned an unusable receipt cursor.
    #[error("AgentSight returned an empty receipt cursor")]
    EmptyReceiptCursor,
}

/// Serialized, persistent PCP controller.
pub struct Controller<C, S> {
    client: C,
    store: S,
    state: Mutex<ControllerState>,
}

impl<C, S> Controller<C, S>
where
    C: AgentSightClient,
    S: StateStore,
{
    /// Restores the last committed state and creates a controller.
    ///
    /// # Errors
    /// Returns an error when persistent state cannot be loaded.
    pub fn new(client: C, store: S) -> Result<Self, ControllerError> {
        let state = store.load()?;
        Ok(Self {
            client,
            store,
            state: Mutex::new(state),
        })
    }

    /// Lowers and durably records one immutable product policy template.
    ///
    /// # Errors
    /// Returns an error for invalid input, immutable revision conflicts, or
    /// persistence failure.
    pub fn prepare_policy(
        &self,
        template: TemplateEnvelope,
    ) -> Result<PolicyEnvelope, ControllerError> {
        let policy = lower_template(template.clone())?;
        let key = format!("{}:{}", policy.policy_id, policy.revision.get());
        let record = PreparedPolicyRecord {
            template,
            canonical_policy: policy.clone(),
        };
        let mut state = self.lock_state()?;
        if let Some(existing) = state.prepared_policies.get(&key) {
            if existing != &record {
                return Err(ControllerError::ImmutablePolicyConflict(key));
            }
            return Ok(existing.canonical_policy.clone());
        }
        state.prepared_policies.insert(key, record);
        self.store.save(&state)?;
        Ok(policy)
    }

    /// Reconciles one policy with durable operation-id idempotency.
    ///
    /// A pending duplicate is queried through `GetState` before the exact same
    /// operation may be retried. A different body is never sent under the same
    /// operation ID.
    ///
    /// # Errors
    /// Returns an error for invalid input, idempotency conflict, persistence,
    /// or `AgentSight` failure.
    pub fn reconcile_policy(
        &self,
        request: &ReconcilePolicyRequest,
    ) -> Result<ReconcilePolicyResponse, ControllerError> {
        request.validate()?;
        let operation_id = policy_operation_id(request).clone();
        let pending_duplicate = {
            let mut state = self.lock_state()?;
            match state.policy_operations.get(operation_id.as_str()) {
                Some(existing) if &existing.request != request => {
                    return Err(ControllerError::IdempotencyConflict(
                        operation_id.to_string(),
                    ));
                }
                Some(existing) => {
                    if let Some(observed) = &existing.observed {
                        return Ok(observed.clone());
                    }
                    true
                }
                None => {
                    state.policy_operations.insert(
                        operation_id.to_string(),
                        PolicyOperationRecord {
                            request: request.to_owned(),
                            observed: None,
                        },
                    );
                    self.store.save(&state)?;
                    false
                }
            }
        };

        if pending_duplicate && let Some(recovered) = self.recover_policy(&operation_id)? {
            return Ok(recovered);
        }

        match self.client.reconcile_policy(request) {
            Ok(response) => {
                self.record_policy_response(&operation_id, &response)?;
                Ok(response)
            }
            Err(error) => {
                if matches!(&error, ClientError::AmbiguousTransport(_))
                    && let Some(recovered) = self.recover_policy(&operation_id)?
                {
                    return Ok(recovered);
                }
                Err(error.into())
            }
        }
    }

    /// Reconciles one binding and refuses unsafe semantic mappings.
    ///
    /// # Errors
    /// Returns an error for invalid input, idempotency conflict, unsafe mapping,
    /// persistence, or `AgentSight` failure.
    pub fn reconcile_binding(
        &self,
        request: &ReconcileBindingRequest,
    ) -> Result<ReconcileBindingResponse, ControllerError> {
        request.validate()?;
        let operation_id = binding_operation_id(request).clone();
        let pending_duplicate = {
            let mut state = self.lock_state()?;
            match state.binding_operations.get(operation_id.as_str()) {
                Some(existing) if &existing.request != request => {
                    return Err(ControllerError::IdempotencyConflict(
                        operation_id.to_string(),
                    ));
                }
                Some(existing) => {
                    if let Some(observed) = &existing.observed {
                        validate_binding_mapping(request, observed)?;
                        return Ok(observed.clone());
                    }
                    true
                }
                None => {
                    state.binding_operations.insert(
                        operation_id.to_string(),
                        BindingOperationRecord {
                            request: request.to_owned(),
                            observed: None,
                        },
                    );
                    self.store.save(&state)?;
                    false
                }
            }
        };

        if pending_duplicate && let Some(recovered) = self.recover_binding(&operation_id)? {
            validate_binding_mapping(request, &recovered)?;
            return Ok(recovered);
        }

        match self.client.reconcile_binding(request) {
            Ok(response) => {
                self.record_binding_response(&operation_id, &response)?;
                validate_binding_mapping(request, &response)?;
                Ok(response)
            }
            Err(error) => {
                if matches!(&error, ClientError::AmbiguousTransport(_))
                    && let Some(recovered) = self.recover_binding(&operation_id)?
                {
                    validate_binding_mapping(request, &recovered)?;
                    return Ok(recovered);
                }
                Err(error.into())
            }
        }
    }

    /// Queries `AgentSight` state without mutating desired state.
    ///
    /// # Errors
    /// Returns an `AgentSight` client failure.
    pub fn get_state(
        &self,
        request: &GetStateRequest,
    ) -> Result<GetStateResponse, ControllerError> {
        Ok(self.client.get_state(request)?)
    }

    /// Pulls the next durable receipt page and returns only newly observed receipts.
    ///
    /// Cursor advancement and receipt insertion are committed atomically in the
    /// PCP state backend.
    ///
    /// # Errors
    /// Returns an error for invalid receipts, conflicting IDs, empty cursor,
    /// persistence, or `AgentSight` failure.
    pub fn pull_receipts(&self, limit: u16) -> Result<Vec<Receipt>, ControllerError> {
        let cursor = self.lock_state()?.receipt_cursor.clone();
        let request = PullReceiptsRequest { cursor, limit };
        request.validate()?;
        let response = self.client.pull_receipts(&request)?;
        if response.next_cursor.is_empty() {
            return Err(ControllerError::EmptyReceiptCursor);
        }

        for receipt in &response.receipts {
            receipt.validate()?;
        }

        let mut state = self.lock_state()?;
        let mut added = Vec::new();
        for receipt in response.receipts {
            let key = receipt.receipt_id.to_string();
            if let Some(existing) = state.receipts.get(&key) {
                if existing != &receipt {
                    return Err(ControllerError::ReceiptConflict(key));
                }
            } else {
                state.receipts.insert(key, receipt.clone());
                added.push(receipt);
            }
        }
        state.receipt_cursor = Some(response.next_cursor);
        self.store.save(&state)?;
        Ok(added)
    }

    /// Returns a point-in-time copy of durable controller state.
    ///
    /// # Errors
    /// Returns an error if the process-local state lock is poisoned.
    pub fn state_snapshot(&self) -> Result<ControllerState, ControllerError> {
        Ok(self.lock_state()?.clone())
    }

    fn recover_policy(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ReconcilePolicyResponse>, ControllerError> {
        let state = self.client.get_state(&GetStateRequest {
            operation_id: Some(operation_id.clone()),
            policy_id: None,
            binding_id: None,
        })?;
        let response = state
            .policies
            .into_iter()
            .find(|response| response.operation_id == *operation_id);
        if let Some(response) = &response {
            self.record_policy_response(operation_id, response)?;
        }
        Ok(response)
    }

    fn recover_binding(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ReconcileBindingResponse>, ControllerError> {
        let state = self.client.get_state(&GetStateRequest {
            operation_id: Some(operation_id.clone()),
            policy_id: None,
            binding_id: None,
        })?;
        let response = state
            .bindings
            .into_iter()
            .find(|response| response.operation_id == *operation_id);
        if let Some(response) = &response {
            self.record_binding_response(operation_id, response)?;
        }
        Ok(response)
    }

    fn record_policy_response(
        &self,
        operation_id: &OperationId,
        response: &ReconcilePolicyResponse,
    ) -> Result<(), ControllerError> {
        let mut state = self.lock_state()?;
        if let Some(record) = state.policy_operations.get_mut(operation_id.as_str()) {
            validate_policy_response(&record.request, response)?;
            record.observed = Some(response.clone());
        } else {
            return Err(ControllerError::ResponseCorrelation(format!(
                "policy operation {operation_id} is not in desired state"
            )));
        }
        self.store.save(&state)?;
        Ok(())
    }

    fn record_binding_response(
        &self,
        operation_id: &OperationId,
        response: &ReconcileBindingResponse,
    ) -> Result<(), ControllerError> {
        let mut state = self.lock_state()?;
        if let Some(record) = state.binding_operations.get_mut(operation_id.as_str()) {
            validate_binding_response(&record.request, response)?;
            record.observed = Some(response.clone());
        } else {
            return Err(ControllerError::ResponseCorrelation(format!(
                "binding operation {operation_id} is not in desired state"
            )));
        }
        self.store.save(&state)?;
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ControllerState>, ControllerError> {
        self.state.lock().map_err(|_| ControllerError::Poisoned)
    }
}

fn policy_operation_id(request: &ReconcilePolicyRequest) -> &OperationId {
    match request {
        ReconcilePolicyRequest::Present { operation_id, .. }
        | ReconcilePolicyRequest::Absent { operation_id, .. } => operation_id,
    }
}

fn binding_operation_id(request: &ReconcileBindingRequest) -> &OperationId {
    match request {
        ReconcileBindingRequest::Ready(request) => &request.operation_id,
        ReconcileBindingRequest::Absent { operation_id, .. } => operation_id,
    }
}

fn validate_binding_mapping(
    request: &ReconcileBindingRequest,
    response: &ReconcileBindingResponse,
) -> Result<(), ControllerError> {
    let ReconcileBindingRequest::Ready(request) = request else {
        return Ok(());
    };
    if !matches!(
        response.state,
        BindingState::BindingReady | BindingState::NoChange
    ) {
        return Ok(());
    }
    if response.mappings.is_empty() || response.mapping_digest.is_none() {
        return Err(ControllerError::UnsafeMapping(
            "ready response omitted mapping evidence".to_owned(),
        ));
    }

    let mut needs_narrower_approval = false;
    for mapping in &response.mappings {
        authorize_relation(mapping.policy_relation, &mut needs_narrower_approval)?;
        authorize_relation(mapping.guarantees.relation, &mut needs_narrower_approval)?;
        for rule in &mapping.rules {
            authorize_relation(rule.relation, &mut needs_narrower_approval)?;
            for atom in &rule.atoms {
                authorize_relation(atom.relation, &mut needs_narrower_approval)?;
            }
        }
    }

    if needs_narrower_approval {
        if !request.approval.allow_narrower {
            return Err(ControllerError::UnsafeMapping(
                "narrower mapping lacks explicit approval".to_owned(),
            ));
        }
        if request.approval.expected_mapping_digest.as_ref() != response.mapping_digest.as_ref() {
            return Err(ControllerError::UnsafeMapping(
                "narrower approval does not match the aggregate mapping digest".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_policy_response(
    request: &ReconcilePolicyRequest,
    response: &ReconcilePolicyResponse,
) -> Result<(), ControllerError> {
    let (operation_id, policy_id, expected_revision, expected_digest) = match request {
        ReconcilePolicyRequest::Present {
            operation_id,
            policy,
            ..
        } => (
            operation_id,
            &policy.policy_id,
            Some(policy.revision),
            policy.payload_digest.as_ref(),
        ),
        ReconcilePolicyRequest::Absent {
            operation_id,
            policy_id,
            ..
        } => (operation_id, policy_id, None, None),
    };
    require_equal("operationId", operation_id, &response.operation_id)?;
    require_equal("policyId", policy_id, &response.policy_id)?;
    if matches!(
        response.state,
        PolicyState::Available | PolicyState::NoChange
    ) && response.revision != expected_revision
    {
        return Err(ControllerError::ResponseCorrelation(
            "available policy revision differs from desired revision".to_owned(),
        ));
    }
    if let Some(expected_digest) = expected_digest
        && response.payload_digest.as_ref() != Some(expected_digest)
    {
        return Err(ControllerError::ResponseCorrelation(
            "policy payload digest differs from desired digest".to_owned(),
        ));
    }
    Ok(())
}

fn validate_binding_response(
    request: &ReconcileBindingRequest,
    response: &ReconcileBindingResponse,
) -> Result<(), ControllerError> {
    match request {
        ReconcileBindingRequest::Absent {
            operation_id,
            binding_id,
            ..
        } => {
            require_equal("operationId", operation_id, &response.operation_id)?;
            require_equal("bindingId", binding_id, &response.binding_id)
        }
        ReconcileBindingRequest::Ready(request) => {
            require_equal("operationId", &request.operation_id, &response.operation_id)?;
            require_equal("bindingId", &request.binding_id, &response.binding_id)?;
            if !matches!(
                response.state,
                BindingState::BindingReady | BindingState::NoChange
            ) {
                return Ok(());
            }
            require_equal(
                "executionDomainId",
                &Some(request.identity.execution_domain_id.clone()),
                &response.execution_domain_id,
            )?;
            require_equal(
                "identityEpoch",
                &Some(request.identity.identity_epoch),
                &response.identity_epoch,
            )?;
            require_equal(
                "effectivePolicy",
                &Some(request.effective_policy.clone()),
                &response.effective_policy,
            )?;
            require_equal(
                "scopeDigest",
                &Some(request.scope_digest.clone()),
                &response.scope_digest,
            )?;

            let mut mapped_targets = HashSet::new();
            for mapping in &response.mappings {
                if mapping.binding_id != request.binding_id {
                    return Err(ControllerError::ResponseCorrelation(
                        "mapping bindingId differs from desired binding".to_owned(),
                    ));
                }
                if mapping.policy_id != request.effective_policy.policy_id
                    || mapping.policy_revision != request.effective_policy.revision
                {
                    return Err(ControllerError::ResponseCorrelation(format!(
                        "mapping references unexpected policy {} revision {}",
                        mapping.policy_id,
                        mapping.policy_revision.get()
                    )));
                }
                if mapping.capability_snapshot_digest
                    != request.precondition.capability_snapshot_digest
                {
                    return Err(ControllerError::ResponseCorrelation(
                        "mapping capability snapshot differs from the precondition".to_owned(),
                    ));
                }
                if !mapped_targets.insert(&mapping.target_id) {
                    return Err(ControllerError::ResponseCorrelation(
                        "duplicate target mapping report".to_owned(),
                    ));
                }
            }
            Ok(())
        }
    }
}

fn require_equal<T>(field: &str, expected: &T, actual: &T) -> Result<(), ControllerError>
where
    T: PartialEq + Debug,
{
    if expected != actual {
        return Err(ControllerError::ResponseCorrelation(format!(
            "{field} differs: expected {expected:?}, got {actual:?}"
        )));
    }
    Ok(())
}

fn authorize_relation(
    relation: MappingRelation,
    needs_narrower_approval: &mut bool,
) -> Result<(), ControllerError> {
    match relation {
        MappingRelation::Exact => Ok(()),
        MappingRelation::Narrower => {
            *needs_narrower_approval = true;
            Ok(())
        }
        MappingRelation::Wider
        | MappingRelation::Incomparable
        | MappingRelation::Unsupported
        | MappingRelation::Invalid => Err(ControllerError::UnsafeMapping(format!(
            "relation {relation:?} cannot be activated"
        ))),
    }
}
