"""CLI entry point for agent-sec-cli package."""

import json
from typing import Optional

import typer
from agent_sec_cli.security_middleware import invoke
from agent_sec_cli.security_middleware.backends.hardening import (
    DEFAULT_HARDEN_CONFIG,
)

app = typer.Typer(
    name="agent-sec-cli",
    help="AgentSecCore unified CLI entry point",
    add_completion=True,
)

# ---------------------------------------------------------------------------
# Command: harden
# ---------------------------------------------------------------------------

_HARDEN_HELP_TEXT = f"""\
Usage: agent-sec-cli harden [SEHARDEN_ARGS]...

Defaults:
  If omitted, the wrapper adds `--scan --config {DEFAULT_HARDEN_CONFIG}`.

Examples:
  agent-sec-cli harden --scan --config {DEFAULT_HARDEN_CONFIG}
  agent-sec-cli harden --reinforce --config {DEFAULT_HARDEN_CONFIG}
  agent-sec-cli harden --reinforce --dry-run --config {DEFAULT_HARDEN_CONFIG}

Common SEHarden flags:
  --scan              Run compliance scan.
  --reinforce         Apply remediation actions.
  --dry-run           Preview reinforce actions without changing the system.
  --config <ruleset>  Select a profile name or YAML file.
  --level <level>     Limit execution to a profile level.
  --verbose           Show detailed rule-level evidence.
  --log-level <lv>    Set log level: trace|debug|info|warn|error.

Help:
  agent-sec-cli harden --help             Show this concise wrapper help.
  agent-sec-cli harden --downstream-help  Show full `loongshield seharden` help.
"""


def _with_default_harden_args(args: list[str]) -> list[str]:
    """Add wrapper defaults when the caller does not provide them explicitly."""
    normalized = list(args)
    if (
        "--scan" not in normalized
        and "--reinforce" not in normalized
        and "--dry-run" not in normalized
    ):
        normalized.insert(0, "--scan")
    if "--config" not in normalized and not any(
        arg.startswith("--config=") for arg in normalized
    ):
        normalized.extend(["--config", DEFAULT_HARDEN_CONFIG])
    return normalized


# ---------------------------------------------------------------------------
# Command: log-sandbox (internal — called by sandbox-guard.py)
# ---------------------------------------------------------------------------


@app.command(name="log-sandbox", hidden=True)
def log_sandbox(
    decision: str = typer.Option(
        "",
        "--decision",
        help="Sandbox decision (allow/block/sandbox)",
    ),
    command: str = typer.Option(
        "",
        "--command",
        help="Command being evaluated",
    ),
    reasons: str = typer.Option(
        "",
        "--reasons",
        help="Reasons for the decision",
    ),
    network_policy: str = typer.Option(
        "",
        "--network-policy",
        help="Network policy applied",
    ),
    cwd: str = typer.Option(
        "",
        "--cwd",
        help="Current working directory",
    ),
):
    """Internal: Record sandbox prehook decision (called by sandbox-guard.py)."""
    result = invoke(
        "sandbox_prehook",
        decision=decision,
        command=command,
        reasons=reasons,
        network_policy=network_policy,
        cwd=cwd,
    )
    # Silent exit - async call doesn't need output
    raise typer.Exit(code=result.exit_code)


@app.command(
    short_help="Scan or reinforce the system against a security baseline.",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        "help_option_names": [],
    },
)
def harden(
    ctx: typer.Context,
    help_flag: bool = typer.Option(
        False,
        "--help",
        "-h",
        is_eager=True,
        help="Show concise harden help and examples.",
    ),
    downstream_help: bool = typer.Option(
        False,
        "--downstream-help",
        help="Show full `loongshield seharden` help and exit.",
    ),
):
    """Scan or reinforce the system against a security baseline."""
    if help_flag:
        typer.echo(_HARDEN_HELP_TEXT.rstrip())
        raise typer.Exit(code=0)

    if downstream_help:
        result = invoke("harden", args=["--help"])
    else:
        result = invoke("harden", args=_with_default_harden_args(list(ctx.args)))

    if result.stdout:
        typer.echo(result.stdout, nl=False)
    if result.error:
        typer.echo(result.error, err=True)
    raise typer.Exit(code=result.exit_code)


# ---------------------------------------------------------------------------
# Command: verify
# ---------------------------------------------------------------------------


@app.command()
def verify(
    skill: str = typer.Option(
        None,
        "--skill",
        help="Path to specific skill for verification",
    ),
):
    """Skill integrity verification."""
    result = invoke("verify", skill=skill)
    if result.stdout:
        typer.echo(result.stdout)
    if result.error:
        typer.echo(result.error, err=True)
    raise typer.Exit(code=result.exit_code)


# ---------------------------------------------------------------------------
# Command: events
#
# Examples:
#   # List recent events (default: table format, last 100)
#   agent-sec-cli events --last-hours 24
#
#   # Filter by type and show as JSON
#   agent-sec-cli events --event-type harden --output json
#
#   # Count hardening events in the last 8 hours
#   agent-sec-cli events --count --category hardening --last-hours 8
#
#   # Breakdown by category
#   agent-sec-cli events --count-by category --last-hours 24
#
#   # Paginate: skip first 50, show next 20
#   agent-sec-cli events --offset 50 --limit 20
#
#   # Stream events for scripting (one JSON object per line)
#   agent-sec-cli events --last-hours 1 --output jsonl | jq '.result'
# ---------------------------------------------------------------------------

_COUNT_BY_ALLOWED = {"category", "event_type", "trace_id"}
_OUTPUT_FORMATS = {"table", "json", "jsonl"}


def _format_table(events_list) -> str:
    """Format events as a kubectl-style columnar table.

    Column widths are computed dynamically from the data (like kubectl)
    so that long values never bleed into adjacent columns.
    """
    if not events_list:
        return "No events found."

    headers = ("EVENT_TYPE", "CATEGORY", "RESULT", "TIMESTAMP")
    rows = [
        (
            e.to_dict().get("event_type", ""),
            e.to_dict().get("category", ""),
            e.to_dict().get("result", "succeeded"),
            e.to_dict().get("timestamp", ""),
        )
        for e in events_list
    ]

    # Compute column widths: max(header, all values) + 2 padding
    col_widths = [
        max(len(h), *(len(r[i]) for r in rows)) + 2 for i, h in enumerate(headers)
    ]

    lines: list[str] = []
    lines.append("".join(h.ljust(w) for h, w in zip(headers, col_widths)).rstrip())
    for row in rows:
        lines.append("".join(v.ljust(w) for v, w in zip(row, col_widths)).rstrip())

    count = len(events_list)
    lines.append("")
    lines.append(f"{count} event{'s' if count != 1 else ''}")

    return "\n".join(lines)


@app.command()
def events(
    event_type: Optional[str] = typer.Option(
        None,
        "--event-type",
        help=(
            "Filter by event type. "
            "Known types: sandbox_prehook, harden, verify, summary, "
            "sandbox_prehook_error, harden_error, verify_error, summary_error."
        ),
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help=(
            "Filter by category. "
            "Known categories: sandbox, hardening, asset_verify, summary."
        ),
    ),
    trace_id: Optional[str] = typer.Option(
        None, "--trace-id", help="Filter by trace ID."
    ),
    since: Optional[str] = typer.Option(
        None, "--since", help="Inclusive lower bound (ISO-8601 timestamp)."
    ),
    until: Optional[str] = typer.Option(
        None, "--until", help="Exclusive upper bound (ISO-8601 timestamp)."
    ),
    last_hours: Optional[float] = typer.Option(
        None,
        "--last-hours",
        help="Query events from the last N hours (mutually exclusive with --since/--until).",
    ),
    limit: int = typer.Option(100, "--limit", help="Max results (default 100)."),
    offset: int = typer.Option(0, "--offset", help="Skip N results (default 0)."),
    count: bool = typer.Option(
        False, "--count", help="Output only the count of matching events."
    ),
    count_by: Optional[str] = typer.Option(
        None,
        "--count-by",
        help="Output grouped counts as JSON object. Allowed: category, event_type, trace_id.",
    ),
    output: str = typer.Option(
        "table",
        "--output",
        "-o",
        help="Output format: table (default, human-readable), json, jsonl.",
    ),
):
    """Query security events from the local SQLite store."""
    # TODO: Support paging with limit and continue

    # --- validation ---
    if output not in _OUTPUT_FORMATS:
        typer.echo(
            f"Error: --output must be one of: {', '.join(sorted(_OUTPUT_FORMATS))}.",
            err=True,
        )
        raise typer.Exit(code=1)

    if last_hours is not None and (since is not None or until is not None):
        typer.echo(
            "Error: --last-hours is mutually exclusive with --since/--until.",
            err=True,
        )
        raise typer.Exit(code=1)

    if count and count_by is not None:
        typer.echo("Error: --count and --count-by are mutually exclusive.", err=True)
        raise typer.Exit(code=1)

    if count_by is not None and count_by not in _COUNT_BY_ALLOWED:
        typer.echo(
            f"Error: --count-by must be one of: {', '.join(sorted(_COUNT_BY_ALLOWED))}.",
            err=True,
        )
        raise typer.Exit(code=1)

    from agent_sec_cli.security_events import get_reader

    reader = get_reader()

    # --- count mode ---
    if count:
        if last_hours is not None:
            # Use query_last_hours and count the results
            result = reader.query_last_hours(
                last_hours, event_type=event_type, category=category
            )
            typer.echo(json.dumps(len(result), ensure_ascii=False, indent=2))
        else:
            result = reader.count(
                event_type=event_type,
                category=category,
                since=since,
                until=until,
            )
            typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
        raise typer.Exit(code=0)

    # --- count-by mode ---
    if count_by is not None:
        result = reader.count_by(count_by, since=since, until=until)
        typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
        raise typer.Exit(code=0)

    # --- list mode ---
    if last_hours is not None:
        events_list = reader.query_last_hours(
            last_hours, event_type=event_type, category=category
        )
        # Apply limit/offset manually since query_last_hours doesn't support them
        events_list = events_list[offset : offset + limit]
    else:
        events_list = reader.query(
            event_type=event_type,
            category=category,
            trace_id=trace_id,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    if output == "table":
        typer.echo(_format_table(events_list))
    elif output == "json":
        output_data = [e.to_dict() for e in events_list]
        typer.echo(json.dumps(output_data, ensure_ascii=False, indent=2))
    elif output == "jsonl":
        for e in events_list:
            typer.echo(json.dumps(e.to_dict(), ensure_ascii=False))
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
