use std::sync::{Arc, Mutex};

use asc_foundation_types::{ResourceId, Revision};
use asc_policy_types::Validate;
use asc_policy_types::authoring::{PolicyTemplate, TemplateEnvelope};
use asc_policy_types::binding::{BindingStatus, BindingView};
use asc_policy_types::error::ValidationError;
use asc_policy_types::identifiers::PolicyId;
use asc_policy_types::policy::{PreparedPolicy, validate_policy_name};
use asc_policy_types::scope::{PolicyReference, PreparedScope, ScopeDeletion, ScopeSelector};
use uuid::Uuid;

use crate::compiler::PolicyCompiler;
use crate::error::PapError;
use crate::model::Page;
use crate::repository::PapRepository;

const MAX_WRITE_ATTEMPTS: usize = 8;
const MAX_PAGE_SIZE: u32 = 1_000;

#[derive(Clone, Copy)]
enum WriteTarget<'a> {
    Create,
    Update(&'a ResourceId),
}

/// Policy Administration Point for templates, assignments and owned Binding intent.
pub struct PapService<R, C> {
    scope_mutations: Arc<Mutex<()>>,
    repository: Arc<R>,
    compiler: Arc<C>,
    discovery: Option<Arc<dyn crate::ScopeDiscovery>>,
    enqueuer: Option<Arc<dyn crate::BindingReconcileEnqueuer>>,
}

impl<R, C> Clone for PapService<R, C> {
    fn clone(&self) -> Self {
        Self {
            scope_mutations: self.scope_mutations.clone(),
            repository: Arc::clone(&self.repository),
            compiler: Arc::clone(&self.compiler),
            enqueuer: self.enqueuer.clone(),
            discovery: self.discovery.clone(),
        }
    }
}

impl<R, C> PapService<R, C>
where
    R: PapRepository,
    C: PolicyCompiler,
{
    /// Creates PAP from explicit persistence and synchronous compiler ports.
    pub fn new(repository: Arc<R>, compiler: Arc<C>) -> Self {
        Self {
            scope_mutations: Arc::new(Mutex::new(())),
            repository,
            compiler,
            enqueuer: None,
            discovery: None,
        }
    }

    /// Connects committed Binding intent to the existing reconciliation runtime.
    #[must_use]
    pub fn with_reconcile_enqueuer(
        mut self,
        enqueuer: Arc<dyn crate::BindingReconcileEnqueuer>,
    ) -> Self {
        self.enqueuer = Some(enqueuer);
        self
    }
    /// Connects assignment admission and deletion to owned discovery workers.
    #[must_use]
    pub fn with_scope_discovery(mut self, discovery: Arc<dyn crate::ScopeDiscovery>) -> Self {
        self.discovery = Some(discovery);
        self
    }
    fn check_ready(&self) -> Result<(), PapError> {
        self.enqueuer.as_ref().map_or(Ok(()), |e| e.check_ready())
    }
    fn notify(&self, mut binding: BindingView) -> Result<BindingView, PapError> {
        let Some(enqueuer) = &self.enqueuer else {
            return Ok(binding);
        };
        // Terminal/running no-ops need no admission and must never be failed.
        if !matches!(
            binding.status.phase,
            BindingStatus::PendingApply | BindingStatus::PendingDelete
        ) {
            return Ok(binding);
        }
        let Err(reason) = enqueuer.enqueue(&binding.spec.binding_id) else {
            return Ok(binding);
        };
        match self.repository.fail_pending_binding(&binding, reason) {
            Ok(true) => {
                // Return the snapshot confirmed by the conditional write, without
                // a second read that could observe a newer request or fail.
                binding.status.phase = match binding.status.phase {
                    BindingStatus::PendingApply => BindingStatus::ApplyFailed,
                    BindingStatus::PendingDelete => BindingStatus::DeleteFailed,
                    _ => unreachable!("only pending requests notify"),
                };
                binding.status.error = Some(reason.failure());
                return Ok(binding);
            }
            Ok(false) => match self.repository.get_binding(&binding.spec.binding_id) {
                Ok(current)
                    if current.spec.binding_revision != binding.spec.binding_revision
                        || current.status != binding.status =>
                {
                    return Ok(current);
                }
                Err(PapError::NotFound) => return Err(PapError::NotFound),
                // Do not retry an old rejection against a fresh pending request.
                // A failed reread also cannot confirm termination.
                _ => {}
            },
            Err(_) => {}
        }
        Err(PapError::SchedulingRejected {
            id: binding.spec.binding_id,
            revision: binding.spec.binding_revision,
            reason,
        })
    }

    /// Creates one Policy identity from an authored template.
    ///
    /// PAP generates the identity and starts at revision 1.
    ///
    /// # Errors
    /// Returns validation, lowering, conflict, revision, or persistence errors.
    #[tracing::instrument(skip_all, name = "pap.create_policy")]
    pub fn create_policy(
        &self,
        policy_name: &str,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        self.write_policy(WriteTarget::Create, policy_name, template)
    }

    /// Updates one existing Policy identity to an authored template.
    ///
    /// Identical latest content is idempotent. Changed content receives the
    /// next never-reused revision and is lowered synchronously before storage.
    ///
    /// # Errors
    /// Returns validation, lowering, conflict, revision, or persistence errors.
    #[tracing::instrument(skip_all, name = "pap.update_policy")]
    pub fn update_policy(
        &self,
        policy_id: &ResourceId,
        policy_name: &str,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        self.write_policy(WriteTarget::Update(policy_id), policy_name, template)
    }

    fn write_policy(
        &self,
        target: WriteTarget<'_>,
        policy_name: &str,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        validate_policy_name(policy_name)
            .map_err(|message| PapError::InvalidPolicyName(message.to_owned()))?;
        let (update_existing, mut selected_id) = match target {
            WriteTarget::Create => (false, generated_resource_id()?),
            WriteTarget::Update(id) => (true, id.clone()),
        };

        for _ in 0..MAX_WRITE_ATTEMPTS {
            let state = self.repository.get_policy_revision_state(&selected_id)?;
            if update_existing && state.is_none() {
                return Err(PapError::NotFound);
            }
            if !update_existing && state.is_some() {
                selected_id = generated_resource_id()?;
                continue;
            }
            if let Some(current) = state.as_ref().and_then(|value| value.current.as_ref())
                && current.policy_name == policy_name
                && &current.template == template
            {
                return Ok(current.clone());
            }

            let revision =
                next_revision(state.as_ref().map(|value| value.last_allocated_revision))?;
            let candidate = self.prepare_policy(&selected_id, policy_name, revision, template)?;
            match self.repository.put_policy(&candidate) {
                Err(PapError::Conflict) => {
                    if !update_existing {
                        selected_id = generated_resource_id()?;
                    }
                }
                result => return result,
            }
        }
        Err(PapError::Conflict)
    }

    /// Gets the current Policy when its revision matches exactly.
    ///
    /// # Errors
    /// Returns not-found or persistence errors.
    #[tracing::instrument(skip_all, name = "pap.get_policy")]
    pub fn get_policy(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        self.repository.get_policy(id, revision)
    }

    /// Lists current Policy records.
    ///
    /// # Errors
    /// Returns invalid-pagination or persistence errors.
    #[tracing::instrument(skip_all, name = "pap.list_policies")]
    pub fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError> {
        validate_limit(limit)?;
        self.repository.list_policies(limit, offset)
    }

    /// Deletes the current Policy content without allowing revision reuse.
    ///
    /// # Errors
    /// Returns not-found, conflict, or persistence errors.
    #[tracing::instrument(skip_all, name = "pap.delete_policy_revision")]
    pub fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        self.repository.delete_policy_revision(id, revision)
    }

    /// Creates an immutable assignment from exact current policy revisions.
    /// # Errors
    /// Rejects stale references, invalid selectors, and unavailable discovery.
    pub fn create_scope_assignment(
        &self,
        selector: &ScopeSelector,
        policies: &[PolicyReference],
    ) -> Result<PreparedScope, PapError> {
        let _guard = self
            .scope_mutations
            .lock()
            .map_err(|_| PapError::Persistence)?;
        selector.validate().map_err(PapError::InvalidScope)?;
        // The current AgentSight adapter has no cgroup instance contract.
        if matches!(selector, ScopeSelector::CgroupId { .. }) {
            return Err(PapError::InvalidScope(ValidationError::new(
                "selector",
                "cgroup assignments are not supported",
            )));
        }
        let discovery = self.discovery.as_ref().ok_or(PapError::Unavailable)?;
        self.check_ready()?;
        let snapshots = policies
            .iter()
            .map(|p| {
                self.repository
                    .get_policy(&p.policy_id, p.policy_revision)
                    .map_err(|e| {
                        if matches!(e, PapError::NotFound) {
                            PapError::ReferencedPolicyRevisionNotFound
                        } else {
                            e
                        }
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let candidate = PreparedScope {
            scope_id: generated_resource_id()?,
            selector: selector.clone(),
            policy_snapshots: snapshots,
            status: asc_policy_types::scope::ScopeStatus::Active,
        };
        candidate.validate().map_err(PapError::InvalidScope)?;
        let scope = self.repository.put_scope(&candidate)?;
        if let Err(error) = discovery.start(&scope) {
            let cleanup = self
                .repository
                .begin_scope_delete(&scope.scope_id)
                .and_then(|_| self.repository.finish_scope_discovery(&scope.scope_id))
                .and_then(|bindings| self.notify_all(bindings));
            if let Err(cleanup_error) = cleanup {
                tracing::error!(
                    target: "asc_process_diagnostic",
                    scope_id = %scope.scope_id,
                    start_error = %error,
                    %cleanup_error,
                    "scope discovery startup compensation failed; inspect and retry Scope deletion"
                );
            }
            return Err(error);
        }
        Ok(scope)
    }

    /// Reads an assignment by identity.
    /// # Errors
    /// Returns not-found or storage failures.
    pub fn get_scope(&self, id: &ResourceId) -> Result<PreparedScope, PapError> {
        self.repository.get_scope(id)
    }

    /// Lists assignments including those awaiting cleanup.
    /// # Errors
    /// Returns pagination or storage failures.
    pub fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError> {
        validate_limit(limit)?;
        self.repository.list_scopes(limit, offset)
    }

    /// Accepts irreversible deletion, stops discovery and schedules owned cleanup.
    /// A successful response acknowledges intent, not remote completion.
    /// # Errors
    /// Returns not-found, discovery or storage failures, retaining admitted intent.
    pub fn delete_scope(&self, id: &ResourceId) -> Result<ScopeDeletion, PapError> {
        let _guard = self
            .scope_mutations
            .lock()
            .map_err(|_| PapError::Persistence)?;
        if self.repository.begin_scope_delete(id)?.is_none() {
            return Ok(ScopeDeletion {
                scope_id: id.clone(),
                completed: true,
            });
        }
        // Close child admission before joining discovery. A stop failure retains
        // deletion intent; retry delete/retry_scope after discovery is available.
        self.discovery
            .as_ref()
            .ok_or(PapError::Unavailable)?
            .stop(id)?;
        self.notify_all(self.repository.finish_scope_discovery(id)?)?;
        let completed = match self.repository.get_scope(id) {
            Ok(_) => false,
            Err(PapError::NotFound) => true,
            Err(error) => return Err(error),
        };
        Ok(ScopeDeletion {
            scope_id: id.clone(),
            completed,
        })
    }

    /// Explicitly retries failed work owned by an assignment.
    /// # Errors
    /// Returns not-found, discovery, scheduling or storage failures.
    pub fn retry_scope(&self, id: &ResourceId) -> Result<PreparedScope, PapError> {
        let _guard = self
            .scope_mutations
            .lock()
            .map_err(|_| PapError::Persistence)?;
        let scope = self.repository.get_scope(id)?;
        if scope.status == asc_policy_types::scope::ScopeStatus::Deleting {
            self.discovery
                .as_ref()
                .ok_or(PapError::Unavailable)?
                .stop(id)?;
            self.notify_all(self.repository.finish_scope_discovery(id)?)?;
        }
        match self.repository.retry_scope(id) {
            Ok(bindings) => self.notify_all(bindings)?,
            Err(PapError::NotFound)
                if scope.status == asc_policy_types::scope::ScopeStatus::Deleting => {}
            Err(error) => return Err(error),
        }
        Ok(scope)
    }

    fn notify_all(&self, bindings: Vec<BindingView>) -> Result<(), PapError> {
        let mut failure = None;
        for binding in bindings {
            if let Err(error) = self.notify(binding) {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Gets the current Binding snapshot and mutable status.
    ///
    /// # Errors
    /// Returns not-found or persistence errors.
    #[tracing::instrument(skip_all, name = "pap.get_binding")]
    pub fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        self.repository.get_binding(id)
    }

    /// Lists current Binding specs and status.
    ///
    /// # Errors
    /// Returns invalid-pagination or persistence errors.
    #[tracing::instrument(skip_all, name = "pap.list_bindings")]
    pub fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError> {
        validate_limit(limit)?;
        self.repository.list_bindings(limit, offset)
    }

    fn prepare_policy(
        &self,
        policy_id: &ResourceId,
        policy_name: &str,
        revision: Revision,
        template: &PolicyTemplate,
    ) -> Result<PreparedPolicy, PapError> {
        let domain_id = PolicyId::new(policy_id.as_str()).map_err(PapError::InvalidIdentifier)?;
        let input = TemplateEnvelope {
            policy_id: domain_id.clone(),
            revision,
            template: template.clone(),
        };
        let canonical_policy = self
            .compiler
            .lower(&input)
            .map_err(PapError::InvalidPolicy)?;
        if canonical_policy.policy_id != domain_id {
            return Err(PapError::InvalidPolicy(ValidationError::new(
                "canonicalPolicy.policyId",
                "compiler output must match the authored Policy identity",
            )));
        }
        if canonical_policy.revision != revision {
            return Err(PapError::InvalidPolicy(ValidationError::new(
                "canonicalPolicy.revision",
                "compiler output must match the authored Policy revision",
            )));
        }
        canonical_policy
            .validate()
            .map_err(PapError::InvalidPolicy)?;
        // Name was checked at admission; the checks above validate every
        // remaining PreparedPolicy invariant with PAP's compiler error paths.
        Ok(PreparedPolicy {
            policy_id: policy_id.clone(),
            policy_name: policy_name.to_owned(),
            revision,
            template: template.clone(),
            canonical_policy,
        })
    }
}

impl<R: PapRepository, C: PolicyCompiler> crate::ScopeBindingSink for PapService<R, C> {
    fn sync_instances(
        &self,
        id: &ResourceId,
        instances: &[asc_policy_types::process_discovery::ProcessIdentity],
    ) -> Result<(), PapError> {
        self.notify_all(self.repository.sync_scope_instances(id, instances)?)
    }
}

fn validate_limit(limit: u32) -> Result<(), PapError> {
    if (1..=MAX_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(PapError::InvalidPagination)
    }
}

fn next_revision(current: Option<Revision>) -> Result<Revision, PapError> {
    match current {
        Some(revision) => revision
            .checked_next()
            .map_err(|_| PapError::RevisionExhausted),
        None => Revision::new(1).map_err(|_| PapError::RevisionExhausted),
    }
}

fn generated_resource_id() -> Result<ResourceId, PapError> {
    ResourceId::new(Uuid::new_v4().to_string())
        .map_err(|error| PapError::InvalidIdentifier(error.to_string()))
}
