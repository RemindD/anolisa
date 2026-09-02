# AgentSecCore V2 Policy foundation, PAP, and daemon request slice

This workspace slice contains the dependency-light contracts and Policy
Administration Point plus the local-peer request path from daemon protocol
to PAP. It deliberately contains no socket listener, persistence
implementation, concrete production Policy compiler, Policy runtime,
reconciliation worker, outbox, or target Adapter.

This in-process PAP slice is not a drop-in replacement for the supported V1
daemon socket and must not be registered there yet. TODO(daemon-transport-compat):
implement or version the V1 envelope, caller, timeout, request-ID, and unknown
field behavior before socket integration. TODO(daemon-process-health): add
`daemon.health` only with its complete compatible payload and conformance
fixtures. TODO(daemon-otel): add W3C carriers only together with extraction and
context attachment around application dispatch.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy and immutable prepared Policy/Scope/Binding specs,
  backend-independent IR, and target Adapter contracts.
- `asc-pap`: transport-independent Policy/Scope revision CRUD and Binding
  spec/lifecycle CRUD over explicit compiler and repository ports.
- `asc-daemon-protocol`: strict PAP wire envelopes, method inventory, and
  prepared Policy/Scope/Binding result contracts.
- `asc-daemon-core`: trusted Principal authorization through a
  `PolicyAdministration` implementation directly over the concrete `PapService`.
- `asc-daemon`: temporary trusted-peer admission plus type-erased PAP handler
  dispatch, DTO projection, and structured service error projection.

The request-level integration test uses serialized Policy, Scope, and Binding
CRUD protocol envelopes and the real `PapService`. Only its explicit
`PapRepository` and `PolicyCompiler` ports are replaced with in-memory fakes.
Socket framing, authentication binding, SQLite, and a production compiler
remain later composition work.
TODO(daemon-auth): before production use, replace temporary socket-peer
admission with reviewed server-side authentication and role policy.

## Daemon response contract

Every decoded response contains a daemon-generated `requestId` and
exactly one of `result` or `error`. Successful method results and structured
errors are different wire shapes, so invalid combinations cannot be produced
by the Rust type. For example:

```json
{"requestId":"request-policy-list","result":{"items":[],"total":0}}
```

```json
{
  "requestId": "request-policy-get",
  "error": {
    "code": "not_found",
    "message": "requested policy resource was not found"
  }
}
```

The stable error-code registry accepts syntactically valid unregistered codes.
Clients match on `error.code`; `error.message` is bounded, sanitized display
text and is not a machine contract. Transport failures produce no
`DaemonResponse`.

The response has no generic `ok`, `data`, `stdout`, `stderr`, or
`exitCode`. CLI rendering and process exit codes belong to `asc-cli`. Constant
success dispositions such as `STORED` and `DELETED` are also omitted: the
presence of `result` establishes success, while meaningful asynchronous state
such as Binding `PENDING_APPLY` and `PENDING_DELETE` remains in the result.

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

Each resource exposes separate `create` and `update` methods. A create request
omits the server-generated resource identity; an update request requires it.
The protocol does not multiplex those commands through `.put` or infer the
operation from an optional identity. Policy and Scope use the same explicit
`{create,update,get,list,delete}` inventory described here for Binding.

The daemon protocol exposes the Binding desired-state boundary through five
explicit allowlisted methods:

| Method | Parameters | Result semantics |
|---|---|---|
| `policy.bindings.create` | exact Policy and Scope IDs/revisions | creates a server-identified immutable spec and returns its current `BindingView` |
| `policy.bindings.update` | required `bindingId` plus exact Policy and Scope IDs/revisions | updates the existing identity and returns its current `BindingView` |
| `policy.bindings.get` | `id` | returns the current immutable spec and lifecycle status |
| `policy.bindings.list` | bounded `limit`/`offset` | returns current `BindingView` records and the unpaginated total |
| `policy.bindings.delete` | `id` | records Delete intent and returns the resulting `BindingView` |

`policy.bindings.delete` does not synchronously remove the immutable spec and
does not claim target-side detach. Callers must interpret the returned `status`;
without a reconciler, a newly accepted delete remains `PENDING_DELETE`.

Daemon socket transport, client, process bootstrap, concrete
persistence/compiler, and Policy runtime crates belong to later work packages
and are intentionally absent from this slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
