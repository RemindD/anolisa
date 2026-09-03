# AgentSecCore V2 foundation contracts

This workspace slice contains the dependency-light contracts shared by later
AgentSecCore V2 Policy and daemon work packages, plus the first AgentSight
file-deletion Adapter and its independent deployment Client. It deliberately
contains no daemon process, persistence implementation, Policy engine, PAP,
Policy runtime, or Binding reconciliation framework.

The current crates are:

- `asc-foundation-types`: bounded transport-independent identifiers and revisions.
- `asc-policy-types`: authored Policy, prepared Policy/Scope/Binding,
  backend-independent IR, and target Adapter contracts.
- `asc-policy-adapter-agentsight`: deterministic file-deletion and PID-Scope
  translation into a compiler-checked AgentSight/ActPlane plan.
- `asc-agentsight-client`: health-gated AgentSight apply/delete transport for
  one configured endpoint, with process identity resolution and complete HTTP
  fixtures. It does not depend on a reconciliation framework.

Daemon protocol, persistence, reconciliation, and Policy runtime
crates belong to later work packages and are intentionally absent from this
workspace slice.

Run the branch-owned validation from this directory:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
