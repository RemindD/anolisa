# AgentSecCore V2 Policy foundation and PAP

This workspace slice contains the dependency-light contracts and Policy
Administration Point used by later AgentSecCore V2 Policy and daemon work
packages. It deliberately contains no daemon process, persistence
implementation, concrete Policy compiler, Policy runtime, reconciliation
worker, outbox, or target Adapter.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy and immutable prepared Policy/Scope/Binding specs,
  backend-independent IR, and target Adapter contracts.
- `asc-pap`: transport-independent Policy/Scope revision CRUD and Binding
  spec/lifecycle CRUD over explicit compiler and repository ports.

## Binding spec and lifecycle boundary

`PreparedBinding` is immutable content. The pair
`(binding_id, binding_revision)` identifies exactly one complete Policy/Scope
spec and must never be reused for different content. Mutable status is
deliberately outside that spec:

- `BindingStatus` contains only the lifecycle state; it carries no duplicated
  Binding ID or revision.
- `BindingView { spec, status }` joins one immutable spec with its status for
  GET/LIST responses.
- `bindingRevision` changes only for different immutable content. Lifecycle
  transitions do not manufacture a new spec revision.

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

| Current | Event | Next | Spec revision rule |
|---|---|---|---|
| none | CREATE valid spec | `PENDING_APPLY` | allocate revision 1 |
| `PENDING_APPLY`, `APPLYING`, `READY` | UPDATE identical spec | no-op | unchanged |
| `APPLY_FAILED`, `PENDING_DELETE`, `DELETING`, `DELETED`, `DELETE_FAILED` | UPDATE identical spec | `PENDING_APPLY` | unchanged |
| any state | UPDATE changed spec | `PENDING_APPLY` | allocate next revision |
| `PENDING_APPLY`, `APPLYING`, `READY`, `APPLY_FAILED` | DELETE | `PENDING_DELETE` | unchanged |
| `PENDING_DELETE`, `DELETING`, `DELETED` | DELETE | no-op | unchanged |
| `DELETE_FAILED` | DELETE retry | `PENDING_DELETE` | unchanged |
| `PENDING_APPLY` | worker claim | `APPLYING` | unchanged |
| `APPLYING` | success | `READY` | unchanged |
| `APPLYING` | retryable failure | `PENDING_APPLY` | unchanged |
| `APPLYING` | permanent/retry-exhausted failure | `APPLY_FAILED` | unchanged |
| `PENDING_DELETE` | worker claim | `DELETING` | unchanged |
| `DELETING` | success | `DELETED` | unchanged |
| `DELETING` | retryable failure | `PENDING_DELETE` | unchanged |
| `DELETING` | permanent/retry-exhausted failure | `DELETE_FAILED` | unchanged |

There are no other legal transitions. In particular, UPDATE received while an
older Delete is `PENDING_DELETE` or `DELETING` moves lifecycle to
`PENDING_APPLY`. DELETE received while Apply is pending or running follows the
symmetric rule.

Repositories persist immutable specs and mutable status separately. A new spec
revision and its initial status form one transaction; a status-only transition
does not rewrite spec content. Status CAS APIs identify the target explicitly by
`binding_id` and `binding_revision` and require the expected current status, so
the read model does not need to duplicate those fields. The PAP
revision-allocation wrapper carries `last_allocated_revision` plus status, not a
duplicate spec.

The shared state machine is defined and tested now, but the PAP-only phase
implements no outbox, dispatcher, or reconciler. Therefore
PAP writes only `PENDING_APPLY` and `PENDING_DELETE`; nothing in this phase
advances them. TODO(policy-reconciliation): persist each request transition and
its reconcile intent atomically; define the operation ordering/CAS token needed
to reject stale results and ABA; then implement claim, retry, completion,
failure, restart recovery, and cancellation using the transitions above.

Daemon protocol, client, process, concrete persistence/compiler, and Policy
runtime crates belong to later work packages and are intentionally absent from
this slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
