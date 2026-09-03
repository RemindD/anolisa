# AgentSecCore V2 Policy foundation and PAP

This workspace slice contains the dependency-light contracts and Policy
Administration Point used by later AgentSecCore V2 Policy and daemon work
packages. It deliberately contains no daemon process, persistence
implementation, concrete Policy compiler, Policy runtime, reconciliation
worker, outbox, or target Adapter.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy and immutable prepared Policy/Scope/Binding
  snapshots, backend-independent IR, and target Adapter contracts.
- `asc-pap`: transport-independent current-record Policy/Scope/Binding CRUD with
  monotonic revisions over explicit compiler and repository ports.

## Current-record revision boundary

Policy, Scope, and Binding each retain one current record per stable identity.
Changed writes advance a positive, never-reused revision and atomically replace
the previous current content. An exact GET for an older revision returns
not-found, and LIST returns at most one current record per identity.

Deleting current Policy or Scope content retains its allocation head as a
tombstone, so a later update of the same identity advances rather than reuses a
revision. A `PreparedBinding` embeds complete Policy and Scope snapshots; an
existing Binding therefore remains deterministic after either source record is
updated or deleted. A new Binding can select only a currently retained source
revision. PAP does not expose historical resource-version CRUD; durable
operation/audit history belongs to later work packages.

## Binding spec and lifecycle boundary

`PreparedBinding` is an immutable snapshot. The pair
`(binding_id, binding_revision)` identifies exactly one complete Policy/Scope
snapshot and must never be reused for a different desired-state operation.
Only the current Binding snapshot is retained. Mutable status is deliberately
outside that spec:

- `BindingStatus` contains only the lifecycle state; it carries no duplicated
  Binding ID or revision.
- `BindingView { spec, status }` joins one immutable spec with its status for
  GET/LIST responses.
- `bindingRevision` advances for every accepted, non-idempotent Apply or Delete
  intent, including reapplying identical content after failure or deletion.
- Reconciler claim, retry, completion, and failure transitions do not advance
  the revision.

All legal lifecycle states are shared in `asc-policy-types::binding`, next to
`PreparedBinding`, so PAP, the future outbox, and the future reconciler use one
contract:

| State | Meaning | Written by | Terminal without a new request? |
|---|---|---|---|
| `PENDING_APPLY` | Apply request accepted but not claimed | PAP | no |
| `APPLYING` | Apply work claimed and running | reconciler | no |
| `READY` | referenced spec applied successfully | reconciler | yes, success |
| `APPLY_FAILED` | Apply permanently failed or exhausted retries | reconciler | yes, failure |
| `PENDING_DELETE` | Delete request accepted but not claimed | PAP | no |
| `DELETING` | detach work claimed and running | reconciler | no |
| `DELETED` | detach completed successfully | reconciler | yes, success |
| `DELETE_FAILED` | detach permanently failed or exhausted retries | reconciler | yes, failure |

“Terminal” means that no automatic transition remains. A later user request can
still move lifecycle from a terminal state to a new pending state.

The successful creation path is:

```text
none --CREATE--> PENDING_APPLY --claim--> APPLYING --success--> READY
```

The successful deletion path is:

```text
apply-side state --DELETE--> PENDING_DELETE --claim--> DELETING --success--> DELETED
```

The complete legal transition set is:

| Current | Event | Next | Revision rule |
|---|---|---|---|
| none | CREATE valid spec | `PENDING_APPLY` | allocate revision 1 |
| `PENDING_APPLY`, `APPLYING`, `READY` | UPDATE identical spec | no-op | unchanged |
| `APPLYING`, `DELETING` | UPDATE changed spec | `OPERATION_IN_PROGRESS` | unchanged |
| `DELETING` | UPDATE identical spec | `OPERATION_IN_PROGRESS` | unchanged |
| any other state | UPDATE accepted Apply intent | `PENDING_APPLY` | allocate next revision and replace current record |
| `APPLYING` | DELETE | `OPERATION_IN_PROGRESS` | unchanged |
| `PENDING_APPLY`, `READY`, `APPLY_FAILED`, `DELETE_FAILED` | DELETE | `PENDING_DELETE` | allocate next revision and replace current record |
| `PENDING_DELETE`, `DELETING`, `DELETED` | DELETE | no-op | unchanged |
| `PENDING_APPLY` | worker claim | `APPLYING` | unchanged |
| `APPLYING` | success | `READY` | unchanged |
| `APPLYING` | retryable failure | `PENDING_APPLY` | unchanged |
| `APPLYING` | permanent/retry-exhausted failure | `APPLY_FAILED` | unchanged |
| `PENDING_DELETE` | worker claim | `DELETING` | unchanged |
| `DELETING` | success | `DELETED` | unchanged |
| `DELETING` | retryable failure | `PENDING_DELETE` | unchanged |
| `DELETING` | permanent/retry-exhausted failure | `DELETE_FAILED` | unchanged |

There are no other legal transitions. In particular, a user request may reverse
`PENDING_APPLY` or `PENDING_DELETE` because target-side work has not been
claimed, but it cannot interrupt `APPLYING` or `DELETING`. There is no
`APPLYING -> PENDING_DELETE` or `DELETING -> PENDING_APPLY` transition within
one revision.

Repositories atomically replace the single current Binding snapshot and status
when PAP accepts a new desired-state revision; no older Binding record remains.
A status-only worker transition does not rewrite spec content. Status CAS APIs
identify the current target by `binding_id` plus the revision contained in the
Binding and require the expected current status. Repository implementations
must repeat the `APPLYING`/`DELETING` admission gate inside the atomic update so
a worker claim cannot race a PAP pre-check.

The shared state machine is defined and tested now, but the PAP-only phase
implements no outbox, dispatcher, or reconciler. Therefore
PAP writes only `PENDING_APPLY` and `PENDING_DELETE`; nothing in this phase
advances them. TODO(policy-reconciliation): persist each accepted current
Binding replacement and its reconcile intent atomically, then let the future
Reconciler consume one complete `BindingView` whose embedded revision fences
claim, retry, completion, failure, restart recovery, and cancellation.

Daemon protocol, client, process, concrete persistence/compiler, and Policy
runtime crates belong to later work packages and are intentionally absent from
this slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
