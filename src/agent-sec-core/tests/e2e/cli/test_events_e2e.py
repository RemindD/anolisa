"""E2E test: CLI capability invocation → event query pipeline.

Validates that invoking security capabilities through the CLI produces
queryable security events in the SQLite store.

NOTE: These tests verify the event-logging pipeline, not the security
capabilities themselves.  `harden` may exit 127 (loongshield missing),
`verify` may find zero skills — both are acceptable as long as an event
is recorded.

Isolation: Each test function uses its own dedicated temp directory (via
AGENT_SEC_DATA_DIR env var) so that tests are fully independent — no
shared state, no ordering dependency, no cascade failures.
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Use the venv's Python to invoke the CLI module
_VENV_PYTHON = str(
    Path(__file__).resolve().parents[3] / ".venv" / "bin" / "python"  # agent-sec-core/
)
_CLI_MODULE = "agent_sec_cli.cli"


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path):
    """Create a function-scoped temp directory for security event data.

    Each test gets a completely fresh SQLite DB — no cross-test pollution,
    no ordering dependency, no cascade failures.
    """
    data_dir = tmp_path / "agent-sec-e2e"
    data_dir.mkdir()
    os.environ["AGENT_SEC_DATA_DIR"] = str(data_dir)
    yield
    os.environ.pop("AGENT_SEC_DATA_DIR", None)


def _run_cli(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Run `python -m agent_sec_cli.cli <args>` and return CompletedProcess."""
    cmd = [_VENV_PYTHON, "-m", _CLI_MODULE, *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
        env=os.environ.copy(),  # inherits AGENT_SEC_DATA_DIR
    )


def _iso_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHardenEventLogging:
    """Verify that invoking `harden` produces a queryable event."""

    def test_harden_produces_event(self):
        """After `agent-sec-cli harden`, an event with event_type=harden is queryable."""
        since = _iso_now()

        # Small delay to ensure timestamp ordering
        time.sleep(0.05)

        # Invoke harden — exit code doesn't matter (loongshield may be absent)
        _run_cli("harden")

        # Small delay to let SQLite WAL flush
        time.sleep(0.1)

        # Query events since the start of this test
        result = _run_cli(
            "events", "--event-type", "harden", "--since", since, "--output", "json"
        )
        assert result.returncode == 0, f"events query failed: {result.stderr}"

        events = json.loads(result.stdout)
        assert isinstance(events, list)
        assert (
            len(events) == 1
        ), f"Expected exactly 1 harden event since {since}, got {len(events)}"

        # Verify event structure
        event = events[0]
        assert event["event_type"] == "harden"
        assert event["category"] == "hardening"
        assert "event_id" in event
        assert "timestamp" in event
        assert "details" in event

    def test_harden_event_count(self):
        """--count returns exactly 1 after a single harden invocation."""
        since = _iso_now()
        time.sleep(0.05)

        _run_cli("harden")
        time.sleep(0.1)

        result = _run_cli(
            "events", "--count", "--event-type", "harden", "--since", since
        )
        assert result.returncode == 0
        count = json.loads(result.stdout)
        assert count == 1


class TestVerifyEventLogging:
    """Verify that invoking `verify` produces a queryable event."""

    def test_verify_produces_event(self):
        """After `agent-sec-cli verify`, an event with event_type=verify is queryable."""
        since = _iso_now()
        time.sleep(0.05)

        # Invoke verify — may fail (no skills configured), that's acceptable
        _run_cli("verify")
        time.sleep(0.1)

        # Query events
        result = _run_cli(
            "events", "--event-type", "verify", "--since", since, "--output", "json"
        )
        assert result.returncode == 0

        events = json.loads(result.stdout)
        assert isinstance(events, list)
        assert (
            len(events) == 1
        ), f"Expected exactly 1 verify event since {since}, got {len(events)}"

        event = events[0]
        assert event["event_type"] == "verify"
        assert event["category"] == "asset_verify"
        assert "details" in event

    def test_verify_event_count_by_category(self):
        """--count-by category shows asset_verify: 1 after a single verify invocation."""
        since = _iso_now()
        time.sleep(0.05)

        _run_cli("verify")
        time.sleep(0.1)

        result = _run_cli("events", "--count-by", "category", "--since", since)
        assert result.returncode == 0

        counts = json.loads(result.stdout)
        assert isinstance(counts, dict)
        assert counts == {"asset_verify": 1}


class TestEventQueryFilters:
    """Verify that query filters work end-to-end."""

    def test_last_hours_filter(self):
        """--last-hours returns exactly the single event just created."""
        _run_cli("harden")
        time.sleep(0.1)

        # Fresh DB: only this test's event exists.
        result = _run_cli(
            "events", "--event-type", "harden", "--last-hours", "1", "--output", "json"
        )
        assert result.returncode == 0
        events = json.loads(result.stdout)
        assert len(events) == 1

    def test_nonexistent_type_returns_empty(self):
        """Filtering by a non-existent event_type returns empty list."""
        result = _run_cli(
            "events",
            "--event-type",
            "does_not_exist_xyz",
            "--last-hours",
            "1",
            "--output",
            "json",
        )
        assert result.returncode == 0

        events = json.loads(result.stdout)
        assert events == []

    def test_default_table_output(self):
        """Default output is human-readable table format."""
        since = _iso_now()
        time.sleep(0.05)
        _run_cli("harden")
        time.sleep(0.1)

        result = _run_cli("events", "--event-type", "harden", "--since", since)
        assert result.returncode == 0
        # Default output is table — should NOT be parseable as JSON
        lines = result.stdout.strip().split("\n")
        # Header + 1 data row + blank line + footer
        assert len(lines) == 4
        assert lines[0].startswith("EVENT_TYPE")
        assert "harden" in lines[1]
        assert "succeeded" in lines[1]
        assert "1 event" in lines[3]
