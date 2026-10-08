use asc_foundation_types::{ResourceId, Revision};
use asc_policy_types::binding::BindingView;
use asc_policy_types::policy::PreparedPolicy;
use asc_policy_types::scope::PreparedScope;

use crate::error::PapError;
use crate::model::{Page, PolicyRevisionState};

/// Persistence port owned by PAP.
///
/// Repositories bound serialized records and list pages to the transport budget.
/// A page may contain fewer than `limit` items; advance by its actual item count.
///
/// All list implementations must apply pagination in the repository. They
/// first order the complete matching result as documented by the individual
/// method, then skip `offset` records and return at most `limit` records.
/// Identity ordering is the lexicographic byte order of `ResourceId::as_str()`.
/// `Page::total` is the matching count before `offset` and `limit` are applied.
/// These values are per-query inputs and must not be persisted.
pub trait PapRepository: Send + Sync {
    /// Creates or replaces the current Policy record.
    ///
    /// Implementations must atomically accept a changed record only when its
    /// revision is exactly the next never-reused revision for the Policy identity.
    /// An exact replay of the current record is idempotent; every other stale,
    /// reused, or skipped revision must return [`PapError::Conflict`]. A successful
    /// changed write replaces the previously retained content; only the current
    /// record remains.
    ///
    /// # Errors
    /// Returns conflict or persistence failures.
    fn put_policy(&self, policy: &PreparedPolicy) -> Result<PreparedPolicy, PapError>;

    /// Gets Policy allocation state and its optional current record.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn get_policy_revision_state(
        &self,
        id: &ResourceId,
    ) -> Result<Option<PolicyRevisionState>, PapError>;

    /// Gets the current Policy only when its revision equals `revision`.
    ///
    /// # Errors
    /// Returns not-found or persistence failures.
    fn get_policy(&self, id: &ResourceId, revision: Revision) -> Result<PreparedPolicy, PapError>;

    /// Lists current Policy records ordered by Policy identity ascending.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn list_policies(&self, limit: u32, offset: u32) -> Result<Page<PreparedPolicy>, PapError>;

    /// Deletes the current Policy content when its revision equals `revision`.
    ///
    /// Implementations retain the allocation head as a tombstone so a later
    /// update of the same identity cannot reuse the deleted revision.
    ///
    /// # Errors
    /// Returns not-found, conflict, or persistence failures.
    fn delete_policy_revision(
        &self,
        id: &ResourceId,
        revision: Revision,
    ) -> Result<PreparedPolicy, PapError>;

    /// Atomically validates exact current policy snapshots and inserts an immutable Scope.
    /// # Errors
    /// Rejects reused IDs, stale snapshots, invalid assignments, and storage failures.
    fn put_scope(&self, scope: &PreparedScope) -> Result<PreparedScope, PapError>;

    /// Reads an assignment, including deletion intent.
    /// # Errors
    /// Returns not-found or storage failures.
    fn get_scope(&self, id: &ResourceId) -> Result<PreparedScope, PapError>;

    /// Lists assignments in identity order.
    /// # Errors
    /// Returns storage failures.
    fn list_scopes(&self, limit: u32, offset: u32) -> Result<Page<PreparedScope>, PapError>;

    /// Closes child admission before the discovery worker is joined.
    /// Returns `None` for a previously completed deletion; unknown IDs are errors.
    /// # Errors
    /// Returns not-found or storage failures.
    fn begin_scope_delete(&self, id: &ResourceId) -> Result<Option<PreparedScope>, PapError>;

    /// Records discovery termination and requests all owned Binding deletions.
    /// Removes an empty Scope only after its worker has stopped.
    /// # Errors
    /// Returns storage failures or conflict if deletion was not admitted.
    fn finish_scope_discovery(&self, id: &ResourceId) -> Result<Vec<BindingView>, PapError>;

    /// Admits missing instances and retires absent ones atomically with Scope lifecycle.
    /// Returns only changed Binding intents; terminal failures are not implicitly retried.
    /// # Errors
    /// Rejects inactive Scopes or storage failures.
    fn sync_scope_instances(
        &self,
        id: &ResourceId,
        instances: &[asc_policy_types::process_discovery::ProcessIdentity],
    ) -> Result<Vec<BindingView>, PapError>;

    /// Explicitly retries failed owned Bindings, preserving nonterminal retry budgets.
    /// # Errors
    /// Returns not-found or storage failures.
    fn retry_scope(&self, id: &ResourceId) -> Result<Vec<BindingView>, PapError>;

    /// Retained repository contract for lower-level revision/CAS compatibility tests.
    /// Production admission uses `sync_scope_instances`; reconciliation uses
    /// `BindingStateRepository::compare_exchange_binding_state`. This method is
    /// not a public PAP mutation path.
    ///
    /// Inserts a fresh Binding (`expected: None`) or conditionally replaces an
    /// existing Binding (`Some`). Compare the expected spec and complete status (including error) under
    /// the same transaction as the write. An update of an absent ID is `NotFound`;
    /// it must never insert. Creation uses a fresh server-generated ID at revision 1.
    ///
    /// Only changed specs increment revision. Same-spec Apply retries and Delete
    /// requests keep revision and deployments. Clear the status error for a new
    /// request; scheduling progress belongs to the caller, not this repository.
    /// Delete intent cannot return to Apply. Repeated requests that do not change
    /// the record preserve its status explanation. No dispatch occurs in this operation.
    ///
    /// # Errors
    /// Returns not-found, operation-in-progress, conflict or persistence failures.
    fn update_binding(
        &self,
        expected: Option<&BindingView>,
        binding: &BindingView,
    ) -> Result<BindingView, PapError>;

    /// Atomically fail only the supplied ID, revision and pending status.
    /// Set the failed phase and status error in the same transaction; preserve
    /// spec and deployments. No retry progress is stored. Return false on contention, never retry
    /// against a newer snapshot. No operation identity is implied by revision.
    /// # Errors
    /// Returns persistence failures; a non-pending expectation is a conflict.
    fn fail_pending_binding(
        &self,
        expected: &BindingView,
        reason: crate::EnqueueError,
    ) -> Result<bool, PapError>;

    /// Gets the current Binding spec, status and safe last error as a read-only aggregate.
    ///
    /// # Errors
    /// Returns not-found or persistence failures.
    fn get_binding(&self, id: &ResourceId) -> Result<BindingView, PapError>;

    /// Lists current Binding specs and status ordered by Binding identity
    /// ascending.
    ///
    /// # Errors
    /// Returns a persistence failure when the query cannot complete.
    fn list_bindings(&self, limit: u32, offset: u32) -> Result<Page<BindingView>, PapError>;
}
