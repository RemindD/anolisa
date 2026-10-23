# Manual SecCore Issue source analysis

Repository writers can analyze one Issue's title and body in
`agentic-os-org/ANOLISA` against a frozen SecCore V2 source snapshot.
Discussion comments are excluded from analysis. The workflow checks source
references and priority rules, performs same-agent review, and produces a report.
It does not execute the component, functional tests, or dynamic reproductions.

## Run the workflow

Configure `QODER_PERSONAL_ACCESS_TOKEN` as a repository Actions secret and ensure
the priority labels have definitions matching [labels.json](../labels.json).
The workflow must be available on the repository's default branch for manual
dispatch.

In Actions, select **AI / SecCore Issue Analysis**, then **Run workflow**:

- `issue_number`: the Issue number, without a URL or `#` prefix.
- `target_ref`: the source branch, tag, or full SHA; defaults to `main`.
- `publish`: defaults to `false`; set to `true` to authorize Issue writeback.

For example, replace `1234` with the Issue number to analyze:

```bash
gh workflow run sec-core-issue-analysis.yml \
  --repo agentic-os-org/ANOLISA --ref main \
  -f issue_number=1234 -f target_ref=main -f publish=false
```

`--ref` selects the workflow version; `target_ref` selects the source and is
resolved once to a full SHA. An Issue with any existing `priority:*` label is
skipped before source collection or model calls, for either value of `publish`.
The skipped run records its reason in `run.json`. Issue Router and Issue events
do not trigger analysis.

## Reports and publication

Reports and comments state that the finding is based on source analysis only;
no dynamic reproduction or functional tests were executed for that Issue.
Claims include a verification plan for checks to be performed separately.
Snapshots, validated results, source references, and bounded failure diagnostics
are retained in Actions artifacts for seven days.

Publication rechecks authorization, Issue content, state, labels, and priority
rules. Adding, editing, or deleting discussion comments does not invalidate the
analysis or block publication. The publisher preserves unrelated comments and
protects its selected previous report against overwriting intervening edits.
It verifies its report write and the Issue fields after publication.
Use **Re-run failed jobs** to retry publication with the existing validated
analysis artifact, including when its planned label was already added.

## Local checks

```bash
node --test .github/scripts/sec-core-issue-analysis.test.js
```

These regression tests validate the automation; they do not verify the behavior
reported in a real Issue. The model runs in an isolated, read-only source
environment with no GitHub credentials or shell tool. The separate publisher
receives no model credential.
