use std::num::NonZeroUsize;
use std::sync::Arc;

use asc_agentsight_client::{
    AgentSightClient, AgentSightClientError, AgentSightDeploymentState, AgentSightTransport,
    ProcessIdentityResolver,
};
use asc_foundation_types::{ResourceId, Revision};
use asc_pap::{PapError, PapRepository};
use asc_policy_adapter_agentsight::AgentSightAdapter;
use asc_policy_types::binding::{BindingStatus, BindingView};
use asc_policy_types::target::{TargetBindingPlan, TranslationOutcome};
use tokio::sync::mpsc;

/// Minimal side-effecting port consumed by the POC reconciliation worker.
pub trait BindingDeploymentClient: Send + Sync + 'static {
    /// Applies one target-specific immutable Binding plan.
    ///
    /// # Errors
    /// Returns the stable `AgentSight` rejection or retryable failure category.
    fn apply(
        &self,
        plan: &TargetBindingPlan,
    ) -> Result<AgentSightDeploymentState, AgentSightClientError>;
}

impl<T, R> BindingDeploymentClient for AgentSightClient<T, R>
where
    T: AgentSightTransport + 'static,
    R: ProcessIdentityResolver + Send + Sync + 'static,
{
    fn apply(
        &self,
        plan: &TargetBindingPlan,
    ) -> Result<AgentSightDeploymentState, AgentSightClientError> {
        self.apply(plan)
    }
}

#[derive(Debug, Clone)]
struct ReconcileWork {
    binding_id: ResourceId,
    binding_revision: Revision,
}

/// Bounded, process-local sender used after a POC Binding write is accepted.
#[derive(Debug, Clone)]
pub struct ReconcileEnqueuer {
    sender: mpsc::Sender<ReconcileWork>,
}

impl ReconcileEnqueuer {
    /// Enqueues the immutable identity of one current `PENDING_APPLY` Binding.
    ///
    /// # Errors
    /// Returns whether the bounded queue is full or its worker has stopped.
    pub fn enqueue(&self, binding: &BindingView) -> Result<(), EnqueueError> {
        let work = ReconcileWork {
            binding_id: binding.spec.binding_id.clone(),
            binding_revision: binding.spec.binding_revision,
        };
        self.sender.try_send(work).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => EnqueueError::Full,
            mpsc::error::TrySendError::Closed(_) => EnqueueError::Closed,
        })
    }
}

/// Stable failure of the deliberately non-durable POC queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnqueueError {
    /// The bounded queue has no remaining capacity.
    #[error("Policy reconciliation queue is full")]
    Full,
    /// The process-local worker has stopped.
    #[error("Policy reconciliation worker is unavailable")]
    Closed,
}

/// Single-consumer POC worker for asynchronous Binding translation and apply.
pub struct ReconcileWorker<R, C> {
    repository: Arc<R>,
    client: Arc<C>,
    receiver: mpsc::Receiver<ReconcileWork>,
}

/// Creates one bounded in-memory work queue and its single consumer.
pub fn reconciliation_queue<R, C>(
    capacity: NonZeroUsize,
    repository: Arc<R>,
    client: Arc<C>,
) -> (ReconcileEnqueuer, ReconcileWorker<R, C>) {
    let (sender, receiver) = mpsc::channel(capacity.get());
    (
        ReconcileEnqueuer { sender },
        ReconcileWorker {
            repository,
            client,
            receiver,
        },
    )
}

impl<R, C> ReconcileWorker<R, C>
where
    R: PapRepository + 'static,
    C: BindingDeploymentClient,
{
    /// Processes queue items until every sender is dropped.
    pub async fn run(mut self) {
        while let Some(work) = self.receiver.recv().await {
            let repository = Arc::clone(&self.repository);
            let client = Arc::clone(&self.client);
            let _ = tokio::task::spawn_blocking(move || {
                reconcile_one(repository.as_ref(), client.as_ref(), &work);
            })
            .await;
        }
    }
}

fn reconcile_one<R, C>(repository: &R, client: &C, work: &ReconcileWork)
where
    R: PapRepository,
    C: BindingDeploymentClient,
{
    let Ok(binding) = repository.get_binding(&work.binding_id) else {
        return;
    };
    if binding.spec.binding_revision != work.binding_revision
        || binding.status != BindingStatus::PendingApply
    {
        return;
    }
    if repository
        .update_binding_status(
            &work.binding_id,
            work.binding_revision,
            BindingStatus::PendingApply,
            BindingStatus::Applying,
        )
        .is_err()
    {
        return;
    }

    let next_status = match AgentSightAdapter.translate(&binding.spec) {
        Ok(TranslationOutcome::Translated(plan)) => match client.apply(&plan) {
            Ok(AgentSightDeploymentState::Present) => BindingStatus::Ready,
            Ok(AgentSightDeploymentState::Absent) | Err(_) => BindingStatus::ApplyFailed,
        },
        Ok(TranslationOutcome::Rejected(_)) | Err(_) => BindingStatus::ApplyFailed,
    };
    let _: Result<BindingStatus, PapError> = repository.update_binding_status(
        &work.binding_id,
        work.binding_revision,
        BindingStatus::Applying,
        next_status,
    );
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use asc_agentsight_client::AgentSightDeploymentState;
    use asc_pap::{PapRepository, PapService};
    use asc_policy_types::authoring::PolicyTemplate;
    use asc_policy_types::binding::{BindingStatus, BindingView};
    use asc_policy_types::scope::ScopeSelector;

    use super::*;
    use crate::{InMemoryPapRepository, PocPolicyCompiler};

    #[derive(Default)]
    struct FakeDeploymentClient {
        apply_calls: AtomicUsize,
    }

    impl BindingDeploymentClient for FakeDeploymentClient {
        fn apply(
            &self,
            _plan: &TargetBindingPlan,
        ) -> Result<AgentSightDeploymentState, AgentSightClientError> {
            self.apply_calls.fetch_add(1, Ordering::Relaxed);
            Ok(AgentSightDeploymentState::Present)
        }
    }

    fn create_binding(
        repository: &Arc<InMemoryPapRepository>,
        selector: &ScopeSelector,
    ) -> BindingView {
        let pap = PapService::new(Arc::clone(repository), Arc::new(PocPolicyCompiler));
        let policy = pap
            .create_policy(
                "protect files",
                &PolicyTemplate::PreventFileDeletion {
                    files: vec!["/workspace/important/**".to_owned()],
                },
            )
            .unwrap();
        let scope = pap.create_scope(selector).unwrap();
        pap.create_binding(
            &policy.policy_id,
            policy.revision,
            &scope.scope_id,
            scope.revision,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn supported_binding_advances_to_ready_and_duplicate_work_is_a_no_op() {
        let repository = Arc::new(InMemoryPapRepository::default());
        let client = Arc::new(FakeDeploymentClient::default());
        let binding = create_binding(&repository, &ScopeSelector::Pid { pid: 4242 });
        let (queue, worker) = reconciliation_queue(
            NonZeroUsize::new(2).unwrap(),
            Arc::clone(&repository),
            Arc::clone(&client),
        );
        queue.enqueue(&binding).unwrap();
        queue.enqueue(&binding).unwrap();
        drop(queue);

        worker.run().await;

        assert_eq!(
            repository
                .get_binding(&binding.spec.binding_id)
                .unwrap()
                .status,
            BindingStatus::Ready
        );
        assert_eq!(client.apply_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn unsupported_scope_fails_asynchronously_without_calling_the_client() {
        let repository = Arc::new(InMemoryPapRepository::default());
        let client = Arc::new(FakeDeploymentClient::default());
        let binding = create_binding(&repository, &ScopeSelector::CgroupId { cgroup_id: 42 });
        let (queue, worker) = reconciliation_queue(
            NonZeroUsize::new(1).unwrap(),
            Arc::clone(&repository),
            Arc::clone(&client),
        );
        queue.enqueue(&binding).unwrap();
        drop(queue);

        worker.run().await;

        assert_eq!(
            repository
                .get_binding(&binding.spec.binding_id)
                .unwrap()
                .status,
            BindingStatus::ApplyFailed
        );
        assert_eq!(client.apply_calls.load(Ordering::Relaxed), 0);
    }
}
