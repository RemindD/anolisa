# Issue triage and community claiming

ANOLISA separates routing, triage, implementation ownership, and code review.

## Roles

- **Component label** answers where the issue belongs.
- **Triager** gives the first maintainer response and decides the next status.
- **Claimant** is the person actively working on an accepted community task.
- **Code owner** reviews the resulting pull request.

A new issue passes through the ANOLISA Issue Router before a parameterized
GitHub Actions workflow applies the validated result. Assignees represent people
actively implementing the work, not notification targets.

## Status labels

| Label | Meaning |
|---|---|
| `status:needs-triage` | Awaiting the first maintainer decision |
| `status:needs-info` | The reporter needs to add focused information |
| `status:accepted` | In scope and ready for implementation |
| `status:in-progress` | Someone has claimed the work |
| `status:blocked` | Waiting on another decision or dependency |
| `status:duplicate` | Tracked by another issue |
| `status:declined` | Not planned or outside the current scope |

Only one `status:*` label should describe the current workflow state.

## New issue flow

1. The Issue Form may supply a component hint. It is authoritative only for a
   structured report whose author passes the private fast-path policy.
2. The external dispatcher discovers the issue, uses the structured fast path
   when eligible, or requests a component classification with a public summary
   and evidence.
3. The dispatcher invokes `Issue Router` through `workflow_dispatch`.
4. The workflow validates the component against `.github/components.json` and
   preserves any conflicting component label already applied by a maintainer.
5. Decisions below the configured confidence threshold remain non-mutating.
6. An accepted decision adds `component:*`, mentions the component owners,
   posts the public summary, and sends the configured notification.

The workflow does not infer a component from the Issue Form or title, and it
does not rewrite issue titles. It assigns component owners only when the issue
author is authorized by the externally managed `ISSUE_TRIAGE_POLICY` secret;
all other issues remain unassigned until someone claims the work. The secret is
a JSON object whose optional `auto_assign_authors` field is an array of GitHub
logins. An absent secret safely disables automatic assignment.

Only a first-line decision marker authored by `github-actions[bot]` is trusted
for idempotency. Router summary and evidence text is HTML-escaped before
publication so it cannot create workflow markers. Owner notification has a
separate marker on the trusted triage comment: a failed notification remains
pending and is retried by rerunning the workflow. If delivery succeeds but
recording the marker fails, a rerun may deliver a duplicate rather than lose the
notification. HTTP success alone is not treated as delivery: the DingTalk
response must also contain `errcode: 0` before the notification is recorded.
The notification uses a fixed Issue link and displays the GitHub-provided title
separately with Markdown metacharacters escaped.

## Claiming community work

An issue can be claimed when it has at least one of:

- `status:accepted`
- `status:ready` (legacy compatibility)
- `good first issue`
- `help wanted`
- `action:helpwanted` (legacy compatibility)

A fresh claim is rejected when any `status:*` label other than
`status:accepted` or the legacy `status:ready` is present, even if a claimable
label remains on the issue. A maintainer must first move the issue back to a
ready state. Claiming removes the ready-state label before adding
`status:in-progress`.

Commands must be the first and only text on the comment line:

```text
/claim
/unclaim
```

`/assign` and `/unassign` are accepted aliases.

The workflow records ownership in a bot marker and `status:in-progress`, then
tries to make the claimant the formal assignee. GitHub only permits some users
to become formal assignees, so the bot marker remains authoritative when an
external contributor cannot be assigned through the API.

Claim and release markers are accepted only as the first line of a comment from
`github-actions[bot]`. The workflow writes the authoritative marker before
changing labels or assignees. Rerunning an interrupted command reconciles the
remaining mutable state without creating another marker. During reconciliation,
an existing `status:in-progress` is allowed only for the marker owner.

A claimant should release the issue when they can no longer work on it.
Maintainers may release abandoned claims after communicating in the issue. A
release restores `status:accepted` only when no other workflow status remains;
otherwise it preserves that status and reports that the issue is unavailable.

## Automation mode

The repository variable `COMMUNITY_AUTOMATION_MODE` controls the triage and
claim workflows:

- `apply` permits validated triage labels, comments, notifications, allowlisted
  reporter assignments, and claimant assignments.
- `shadow` writes only Action logs and summaries.

Any other value is rejected without changing the issue. This fail-closed
behavior prevents a misspelled incident-response setting from enabling writes.

`Issue Router` also accepts an `apply` input. Set it to `false` for a single
dry run even when the repository mode is `apply`. The default repository mode
is `apply`; set it to `shadow` for incident response or a non-mutating trial.

## SecCore analysis after Issue Router

`AI / SecCore Issue Analysis` analyzes one Issue in the verified
`agentic-os-org/ANOLISA` repository or the `RemindD/anolisa` pilot fork.
It recommends a priority, explains impact, and optionally runs an approved
functional component PoC. Use synthetic or non-sensitive reports; cybersecurity
testing and private vulnerability intake are outside this workflow.

### Configuration and manual runs

1. Put the workflow on the default branch and enable Issues in the fork.
   Ensure `component:sec-core` and `priority:p0` through `priority:p3` exist,
   with the current definitions from `.github/labels.json`.
2. Add `QODER_PERSONAL_ACCESS_TOKEN` as an Actions repository secret using
   [Qoder Integrations](https://qoder.com/account/integrations). No GitHub App
   or developer login-cache copy is required.
3. To enable Router-triggered analysis, set repository variable
   `SECCORE_ISSUE_ANALYSIS_ENABLED=true`. Also set
   `SECCORE_ISSUE_WRITEBACK_ENABLED=true` to authorize automatic publication.

A repository writer can manually analyze an explicit Issue:

```bash
gh workflow run sec-core-issue-analysis.yml --repo RemindD/anolisa \
  --ref main -f issue_number=12 -f target_ref=main -f publish=false
```

`--ref` selects the workflow; `target_ref` selects the source and resolves once
to a full SHA. The default `publish=false` produces artifacts without writing
to the Issue. Explicit `publish=true` authorizes publication for that manual run.

### Router handoff

Router dispatches analysis only after accepting `component:sec-core` with
analysis enabled. Low confidence, dry runs, conflicts, and other components do
not qualify. Accepted routing remains valid if owner notification fails; owner
notifications are disabled in the pilot fork.

The built-in `GITHUB_TOKEN` starts analysis as `github-actions[bot]`. Analysis
and publication verify the same-repository default-branch Router run, its bot
decision comment, and the current open SecCore Issue. External Issue authors
are eligible. Creation, edit, comment, and label events do not start analysis
independently; the external dispatcher still supplies the component decision.

Router checks for a published result matching the source, rules, Issue, and
discussion before dispatch. Analysis checks again before invoking the model.
Notification bookkeeping does not change this fingerprint. Incomplete runs
remain retryable, and manual dispatch permits explicit reanalysis. The workflow
has no persistent queue, complete-query discovery, or automatic reconciliation.

### Results and publication

The comment shows priority and its reason, impact, and actual PoC status.
Source and full-report links are folded into details. The report adds the
supported and unverified effects and up to three key evidence links. A next
step appears only for a review objection, blocked verification, or unresolved
priority. Full snapshots, analysis, review, execution logs, writeback records, and
file hashes remain in the seven-day artifact.

Only captured Issue priority rules define grades. Missing or conflicting rules
leave priority unresolved. Refuted claims receive an explanation without a
priority; inactive or out-of-scope reports are not published. A review objection
keeps the proposal visible but withholds its label. P0/P1 recommends human review.

Publication uses a separate job without the model credential. It rechecks the
Issue, discussion, rules, and authorization, then adds an absent priority and
creates or updates this pipeline's comment. It preserves unrelated labels and
comments, stops on conflicting priorities or changed inputs, skips identical
published summaries, and reads back its writes. Failed publication does not
invalidate the analysis; inspect `writeback-results.json` before retrying.

### PoC and review

The approved `sqlite_maintenance_gate` profile uses the real frozen
`asc-sqlite-kernel` code with synthetic NaN and finite marker inputs. It runs the
component baseline, selected case, and three controls. `poc.json` records actual
execution, observations, logs, and cleanup. Other reports explain why no profile
applies. Build failures remain blocked. Component results do not establish
daemon/CLI integration, production impact, or a fix.

Routine decisions use a self-check in the analysis call. P0/P1, a material
self-check objection, ambiguous priority authority, failed PoC assertions, or a
contradictory PoC result trigger a focused review. This uses the same agent;
it is not independent review. One material revision is allowed. Source hashes,
quotes, ranges, and rule references are checked deterministically for each result.

### Runtime and debugging

The model uses pinned Qoder CLI `1.1.77` with the `auto` model alias, Read/Grep/Glob,
and Write restricted to its JSON result directory. Source and inputs are
read-only; no GitHub credential, shell tool, repository agent configuration,
or MCP server is available. The separate functional executor receives neither
GitHub nor model credentials and disconnects external networking before tests.
Resource limits live in the [analysis controller](scripts/sec-core-issue-analysis.js)
and [PoC executor](scripts/sec-core-issue-poc.js).

Model calls have no separate timeout by default (`AGENT_TIMEOUT_SECONDS=0`);
the analysis job has a 180-minute deadline. Heartbeats appear every 60 seconds.
Sanitized event traces retain tool timing without model text or tool arguments;
execution records retain a redacted diagnostic tail and container cleanup status.
Parsed results rejected by validation may be repaired once with its feedback. Interrupted
or rejected candidates are diagnostic only and cannot be published.

### Checking changes

Run the existing credential-free checks; relevant pushes run them in Actions:

```bash
node --test .github/scripts/sec-core-issue-analysis.test.js .github/scripts/issue-triage.test.js .github/scripts/issue-claim.test.js
```

For a real-model check, freeze the source and rules, then use a synthetic NaN
marker report and a false expired-finite-marker report with `publish=false`.
Check the finding, priority reason, impact boundary, and truthful PoC status;
wording need not match exactly. Verify that another component skips analysis
and replaying the same Router decision does not duplicate analysis or comments.

Unset `SECCORE_ISSUE_ANALYSIS_ENABLED` to stop automatic analysis, or unset
`SECCORE_ISSUE_WRITEBACK_ENABLED` to stop automatic publication. Archive useful
acceptance and failure artifacts before their seven-day retention expires.
