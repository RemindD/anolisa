use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use asc_foundation_types::{ResourceId, Revision};
use asc_pap::{Page, PapError, PapRepository, PolicyRevisionState, ScopeRevisionState};
use asc_policy_types::binding::{BindingStatus, BindingView};
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::scope::PreparedScope;

/// Process-local Repository for the capability-validation POC.
///
/// All operations are serialized by one mutex. State is lost on daemon restart;
/// this type is not evidence for a durable or concurrent production backend.
#[derive(Debug, Default)]
pub struct InMemoryPapRepository {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    policy_heads: BTreeMap<String, Revision>,
    policies: BTreeMap<String, PreparedPolicy>,
    scope_heads: BTreeMap<String, Revision>,
    scopes: BTreeMap<String, PreparedScope>,
    bindings: BTreeMap<String, BindingView>,
}

impl InMemoryPapRepository {
    fn lock(&self) -> Result<MutexGuard<'_, MemoryState>, PapError> {
        self.state.lock().map_err(|_| PapError::Persistence)
    }
}

impl PapRepository for InMemoryPapRepository {
    fn put_policy(&self, policy: &PreparedPolicy) -> Result<PreparedPolicy, PapError> {
        let mut state = self.lock()?;
        let id = policy.policy_id.as_str().to_owned();
        if let Some(existing) = state.policies.get(&id)
            && existing.revision == policy.revision
        {
            return if existing == policy {
                Ok(existing.clone())
            } else {
                Err(PapError::Conflict)
            };
        }
        if !is_next_revision(state.policy_heads.get(&id).copied(), policy.revision) {
            return Err(PapError::Conflict);
        }
        state.policies.insert(id.clone(), policy.clone());
        state.policy_heads.insert(id, policy.revision);
        Ok(policy.clone())
    }

    fn get_policy_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<PolicyRevisionState>, PapError> {
        let state = self.lock()?;
        Ok(state
            .policy_heads
            .get(id.as_str())
            .copied()
            .map(|last_allocated_revision| PolicyRevisionState {
                last_allocated_revision,
                current: state.policies.get(id.as_str()).cloned(),
            }))
    }

    fn get_policy(&self, id: &ResourceId, revision: Revision) -> Result<PreparedPolicy, PapError> {
        self.lock()?
            .policies
            .get(id.as_str())
            .filter(|policy| policy.revision == revision)
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError> {
        Ok(page(self.lock()?.policies.values().cloned(), limit, offset))
    }

    fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError> {
        let mut state = self.lock()?;
        if state
            .policies
            .get(id.as_str())
            .is_none_or(|policy| policy.revision != revision)
        {
            return Err(PapError::NotFound);
        }
        state
            .policies
            .remove(id.as_str())
            .ok_or(PapError::Persistence)
    }

    fn put_scope(&self, scope: &PreparedScope) -> Result<PreparedScope, PapError> {
        let mut state = self.lock()?;
        let id = scope.scope_id.as_str().to_owned();
        if let Some(existing) = state.scopes.get(&id)
            && existing.revision == scope.revision
        {
            return if existing == scope {
                Ok(existing.clone())
            } else {
                Err(PapError::Conflict)
            };
        }
        if !is_next_revision(state.scope_heads.get(&id).copied(), scope.revision) {
            return Err(PapError::Conflict);
        }
        state.scopes.insert(id.clone(), scope.clone());
        state.scope_heads.insert(id, scope.revision);
        Ok(scope.clone())
    }

    fn get_scope_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<ScopeRevisionState>, PapError> {
        let state = self.lock()?;
        Ok(state
            .scope_heads
            .get(id.as_str())
            .copied()
            .map(|last_allocated_revision| ScopeRevisionState {
                last_allocated_revision,
                current: state.scopes.get(id.as_str()).cloned(),
            }))
    }

    fn get_scope(&self, id: &ResourceId, revision: Revision) -> Result<PreparedScope, PapError> {
        self.lock()?
            .scopes
            .get(id.as_str())
            .filter(|scope| scope.revision == revision)
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError> {
        Ok(page(self.lock()?.scopes.values().cloned(), limit, offset))
    }

    fn delete_scope_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedScope, PapError> {
        let mut state = self.lock()?;
        if state
            .scopes
            .get(id.as_str())
            .is_none_or(|scope| scope.revision != revision)
        {
            return Err(PapError::NotFound);
        }
        state
            .scopes
            .remove(id.as_str())
            .ok_or(PapError::Persistence)
    }

    fn update_binding(&self, binding: &BindingView) -> Result<BindingView, PapError> {
        if !matches!(
            binding.status,
            BindingStatus::PendingApply | BindingStatus::PendingDelete
        ) {
            return Err(PapError::Conflict);
        }

        let mut state = self.lock()?;
        let id = binding.spec.binding_id.as_str().to_owned();
        if let Some(current) = state.bindings.get(&id) {
            if current == binding {
                return Ok(current.clone());
            }
            if current.status.is_reconciling() {
                return Err(PapError::OperationInProgress);
            }
            if !is_next_revision(
                Some(current.spec.binding_revision),
                binding.spec.binding_revision,
            ) {
                return Err(PapError::Conflict);
            }
        } else if binding.spec.binding_revision.get() != 1
            || binding.status != BindingStatus::PendingApply
        {
            return Err(PapError::Conflict);
        }
        state.bindings.insert(id, binding.clone());
        Ok(binding.clone())
    }

    fn update_binding_status(
        &self,
        id: &ResourceId,
        binding_revision: Revision,
        expected_status: BindingStatus,
        next_status: BindingStatus,
    ) -> Result<BindingStatus, PapError> {
        let mut state = self.lock()?;
        let binding = state
            .bindings
            .get_mut(id.as_str())
            .ok_or(PapError::NotFound)?;
        if binding.spec.binding_revision != binding_revision || binding.status != expected_status {
            return Err(PapError::Conflict);
        }
        expected_status
            .validate_successor(next_status)
            .map_err(|_| PapError::Conflict)?;
        binding.status = next_status;
        Ok(next_status)
    }

    fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError> {
        self.lock()?
            .bindings
            .get(id.as_str())
            .cloned()
            .ok_or(PapError::NotFound)
    }

    fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError> {
        Ok(page(self.lock()?.bindings.values().cloned(), limit, offset))
    }
}

fn is_next_revision(current: Option<Revision>, candidate: Revision) -> bool {
    match current {
        None => candidate.get() == 1,
        Some(current) => current.get().checked_add(1) == Some(candidate.get()),
    }
}

fn page<T>(items: impl Iterator<Item = T>, limit: u32, offset: u32) -> Page<T> {
    let items: Vec<_> = items.collect();
    let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    Page {
        items: items.into_iter().skip(offset).take(limit).collect(),
        total,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use asc_pap::{PapRepository, PapService};
    use asc_policy_types::authoring::PolicyTemplate;
    use asc_policy_types::binding::BindingStatus;
    use asc_policy_types::scope::ScopeSelector;

    use super::*;
    use crate::PocPolicyCompiler;

    fn service() -> (
        PapService<InMemoryPapRepository, PocPolicyCompiler>,
        Arc<InMemoryPapRepository>,
    ) {
        let repository = Arc::new(InMemoryPapRepository::default());
        (
            PapService::new(Arc::clone(&repository), Arc::new(PocPolicyCompiler)),
            repository,
        )
    }

    #[test]
    fn stores_complete_pap_records_and_applies_status_cas() {
        let (pap, repository) = service();
        let policy = pap
            .create_policy(
                "protect files",
                &PolicyTemplate::PreventFileDeletion {
                    files: vec!["/workspace/important/**".to_owned()],
                },
            )
            .unwrap();
        let scope = pap.create_scope(&ScopeSelector::Pid { pid: 4242 }).unwrap();
        let binding = pap
            .create_binding(
                &policy.policy_id,
                policy.revision,
                &scope.scope_id,
                scope.revision,
            )
            .unwrap();

        assert_eq!(binding.status, BindingStatus::PendingApply);
        assert_eq!(
            repository
                .update_binding_status(
                    &binding.spec.binding_id,
                    binding.spec.binding_revision,
                    BindingStatus::PendingApply,
                    BindingStatus::Applying,
                )
                .unwrap(),
            BindingStatus::Applying
        );
        assert_eq!(
            repository
                .update_binding_status(
                    &binding.spec.binding_id,
                    binding.spec.binding_revision,
                    BindingStatus::PendingApply,
                    BindingStatus::Ready,
                )
                .unwrap_err(),
            PapError::Conflict
        );
    }

    #[test]
    fn list_order_and_tombstone_revision_are_concrete_repository_behavior() {
        let (pap, repository) = service();
        let first = pap
            .create_policy(
                "one",
                &PolicyTemplate::PreventFileDeletion {
                    files: vec!["/one".to_owned()],
                },
            )
            .unwrap();
        let second = pap
            .create_policy(
                "two",
                &PolicyTemplate::PreventFileDeletion {
                    files: vec!["/two".to_owned()],
                },
            )
            .unwrap();

        let page = repository.list_policies(10, 0).unwrap();
        assert_eq!(page.total, 2);
        assert!(
            page.items
                .windows(2)
                .all(|pair| { pair[0].policy_id.as_str() < pair[1].policy_id.as_str() })
        );

        pap.delete_policy_revision(&first.policy_id, first.revision)
            .unwrap();
        let recreated = pap
            .update_policy(
                &first.policy_id,
                "one-again",
                &PolicyTemplate::PreventFileDeletion {
                    files: vec!["/one-again".to_owned()],
                },
            )
            .unwrap();
        assert_eq!(recreated.revision.get(), 2);
        assert_ne!(first.policy_id, second.policy_id);
    }
}
