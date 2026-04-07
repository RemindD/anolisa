"""Unit tests for security_middleware.backends.summary — SummaryBackend.

Uses a temporary JSONL file instead of the real log path.
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from security_middleware.backends.summary import SummaryBackend
from security_middleware.context import RequestContext


def _make_event(category="sandbox", event_type="sandbox_exec", event_id=None,
                hours_ago=0):
    """Create a single JSONL event dict."""
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": event_id or f"evt-{id(ts)}",
        "event_type": event_type,
        "category": category,
        "timestamp": ts.isoformat(),
        "details": {},
    }


def _write_events(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for evt in events:
            f.write(json.dumps(evt) + "\n")


class TestSummaryBackend(unittest.TestCase):
    def setUp(self):
        self.backend = SummaryBackend()
        self.ctx = RequestContext(action="summary")

    @patch("security_events.config.get_log_path")
    def test_no_log_file(self, mock_path):
        mock_path.return_value = "/nonexistent/log.jsonl"
        result = self.backend.execute(self.ctx, hours=24)

        self.assertTrue(result.success)
        self.assertEqual(result.data["total_events"], 0)

    @patch("security_events.config.get_log_path")
    def test_events_within_window(self, mock_path):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            tmp = f.name
        try:
            events = [
                _make_event(category="sandbox", hours_ago=1),
                _make_event(category="hardening", hours_ago=2),
                _make_event(category="sandbox", hours_ago=3),
            ]
            _write_events(tmp, events)
            mock_path.return_value = tmp

            result = self.backend.execute(self.ctx, hours=24)
            self.assertTrue(result.success)
            self.assertEqual(result.data["total_events"], 3)
            self.assertEqual(result.data["categories"]["sandbox"], 2)
            self.assertEqual(result.data["categories"]["hardening"], 1)
        finally:
            os.unlink(tmp)

    @patch("security_events.config.get_log_path")
    def test_events_outside_window_filtered(self, mock_path):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            tmp = f.name
        try:
            events = [
                _make_event(category="sandbox", hours_ago=1),   # within 4h
                _make_event(category="sandbox", hours_ago=10),  # outside 4h
            ]
            _write_events(tmp, events)
            mock_path.return_value = tmp

            result = self.backend.execute(self.ctx, hours=4)
            self.assertEqual(result.data["total_events"], 1)
        finally:
            os.unlink(tmp)

    @patch("security_events.config.get_log_path")
    def test_deduplication(self, mock_path):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            tmp = f.name
        try:
            events = [
                _make_event(event_id="dup-1", hours_ago=1),
                _make_event(event_id="dup-1", hours_ago=1),  # duplicate
                _make_event(event_id="unique", hours_ago=2),
            ]
            _write_events(tmp, events)
            mock_path.return_value = tmp

            result = self.backend.execute(self.ctx, hours=24)
            self.assertEqual(result.data["total_events"], 2)
        finally:
            os.unlink(tmp)

    @patch("security_events.config.get_log_path")
    def test_malformed_lines_skipped(self, mock_path):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            tmp = f.name
        try:
            with open(tmp, "w") as f:
                f.write("not valid json\n")
                f.write(json.dumps(_make_event(hours_ago=1)) + "\n")
                f.write("\n")  # blank line
            mock_path.return_value = tmp

            result = self.backend.execute(self.ctx, hours=24)
            self.assertEqual(result.data["total_events"], 1)
        finally:
            os.unlink(tmp)

    @patch("security_events.config.get_log_path")
    def test_json_format(self, mock_path):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            tmp = f.name
        try:
            _write_events(tmp, [_make_event(hours_ago=1)])
            mock_path.return_value = tmp

            result = self.backend.execute(self.ctx, hours=24, format="json")
            self.assertTrue(result.success)
            # stdout should be valid JSON
            parsed = json.loads(result.stdout)
            self.assertIn("events", parsed)
            self.assertEqual(len(parsed["events"]), 1)
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
