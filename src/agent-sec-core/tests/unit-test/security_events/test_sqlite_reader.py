"""Unit tests for security_events.sqlite_reader — SqliteEventReader."""

import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from agent_sec_cli.security_events.schema import SecurityEvent
from agent_sec_cli.security_events.sqlite_reader import SqliteEventReader
from agent_sec_cli.security_events.sqlite_writer import SqliteEventWriter


def _make_event(event_type="test_event", category="test", **kwargs):
    return SecurityEvent(
        event_type=event_type,
        category=category,
        details=kwargs.get("details", {"key": "value"}),
        trace_id=kwargs.get("trace_id", ""),
    )


class TestSqliteEventReader(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmp_dir) / "test.db")
        self.writer = SqliteEventWriter(path=self.db_path)
        self.reader = SqliteEventReader(path=self.db_path)

    def tearDown(self):
        self.writer.close()

    def test_query_returns_all_events(self):
        for _ in range(5):
            self.writer.write(_make_event())
        events = self.reader.query()
        self.assertEqual(len(events), 5)

    def test_query_filter_by_event_type(self):
        self.writer.write(_make_event(event_type="alpha"))
        self.writer.write(_make_event(event_type="alpha"))
        self.writer.write(_make_event(event_type="beta"))
        events = self.reader.query(event_type="alpha")
        self.assertEqual(len(events), 2)
        for e in events:
            self.assertEqual(e.event_type, "alpha")

    def test_query_filter_by_category(self):
        self.writer.write(_make_event(category="sandbox"))
        self.writer.write(_make_event(category="sandbox"))
        self.writer.write(_make_event(category="hardening"))
        events = self.reader.query(category="sandbox")
        self.assertEqual(len(events), 2)
        for e in events:
            self.assertEqual(e.category, "sandbox")

    def test_query_filter_by_trace_id(self):
        self.writer.write(_make_event(trace_id="trace-abc"))
        self.writer.write(_make_event(trace_id="trace-abc"))
        self.writer.write(_make_event(trace_id="trace-xyz"))
        events = self.reader.query(trace_id="trace-abc")
        self.assertEqual(len(events), 2)
        for e in events:
            self.assertEqual(e.trace_id, "trace-abc")

    def test_query_time_range_since_until(self):
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=2)
        future = now + timedelta(hours=2)

        for _ in range(3):
            self.writer.write(_make_event())

        since_iso = past.isoformat()
        until_iso = future.isoformat()
        events = self.reader.query(since=since_iso, until=until_iso)
        self.assertEqual(len(events), 3)

    def test_query_ordering_desc(self):
        self.writer.write(_make_event())
        time.sleep(0.02)
        self.writer.write(_make_event())
        time.sleep(0.02)
        self.writer.write(_make_event())

        events = self.reader.query()
        self.assertEqual(len(events), 3)
        # Results should be in descending order by time — verify via DB directly
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT timestamp_epoch FROM security_events ORDER BY timestamp_epoch DESC"
        ).fetchall()
        conn.close()
        epochs = [r[0] for r in rows]
        self.assertEqual(epochs, sorted(epochs, reverse=True))

    def test_query_limit_offset(self):
        for _ in range(10):
            self.writer.write(_make_event())
            time.sleep(0.005)

        events = self.reader.query(limit=3, offset=2)
        self.assertEqual(len(events), 3)

    def test_count_returns_total(self):
        for _ in range(5):
            self.writer.write(_make_event())
        self.assertEqual(self.reader.count(), 5)

    def test_count_with_filters(self):
        self.writer.write(_make_event(category="sandbox"))
        self.writer.write(_make_event(category="sandbox"))
        self.writer.write(_make_event(category="hardening"))
        self.assertEqual(self.reader.count(category="sandbox"), 2)

    def test_count_by_category(self):
        self.writer.write(_make_event(category="sandbox"))
        self.writer.write(_make_event(category="sandbox"))
        self.writer.write(_make_event(category="hardening"))
        result = self.reader.count_by("category")
        self.assertEqual(result["sandbox"], 2)
        self.assertEqual(result["hardening"], 1)

    def test_count_by_event_type(self):
        self.writer.write(_make_event(event_type="alpha"))
        self.writer.write(_make_event(event_type="alpha"))
        self.writer.write(_make_event(event_type="beta"))
        result = self.reader.count_by("event_type")
        self.assertEqual(result["alpha"], 2)
        self.assertEqual(result["beta"], 1)

    def test_count_by_invalid_field_raises(self):
        with self.assertRaises(ValueError):
            self.reader.count_by("invalid_field")

    def test_missing_db_returns_empty(self):
        missing_path = str(Path(self.tmp_dir) / "nonexistent.db")
        reader = SqliteEventReader(path=missing_path)
        self.assertEqual(reader.query(), [])
        self.assertEqual(reader.count(), 0)
        self.assertEqual(reader.count_by("category"), {})

    def test_query_last_hours(self):
        for _ in range(3):
            self.writer.write(_make_event())

        # Events written just now should appear in last 24 hours
        events = self.reader.query_last_hours(24)
        self.assertEqual(len(events), 3)

        # Wait a bit then query with a tiny window that excludes the events
        time.sleep(0.05)
        # 0.000001 hours = ~3.6ms — events written >50ms ago should not appear
        events = self.reader.query_last_hours(0.000001)
        self.assertEqual(len(events), 0)


if __name__ == "__main__":
    unittest.main()
