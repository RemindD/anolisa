"""Unit tests for security_events.sqlite_writer — SqliteEventWriter."""

import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_sec_cli.security_events.schema import SecurityEvent
from agent_sec_cli.security_events.sqlite_writer import SqliteEventWriter


def _make_event(event_type="test_event", category="test", **kwargs):
    return SecurityEvent(
        event_type=event_type,
        category=category,
        details=kwargs.get("details", {"key": "value"}),
        trace_id=kwargs.get("trace_id", ""),
    )


class TestSqliteEventWriter(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmp_dir) / "test.db")

    def tearDown(self):
        # Best-effort cleanup
        for f in Path(self.tmp_dir).glob("*"):
            try:
                f.unlink()
            except OSError:
                pass
        try:
            os.rmdir(self.tmp_dir)
        except OSError:
            pass

    def test_write_creates_db_and_inserts(self):
        writer = SqliteEventWriter(path=self.db_path)
        evt = _make_event()
        writer.write(evt)

        self.assertTrue(Path(self.db_path).exists())

        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT * FROM security_events").fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        writer.close()

    def test_wal_mode_enabled(self):
        writer = SqliteEventWriter(path=self.db_path)
        writer.write(_make_event())

        conn = sqlite3.connect(self.db_path)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        self.assertEqual(mode, "wal")
        writer.close()

    def test_fire_and_forget_never_raises(self):
        invalid_path = "/nonexistent/dir/test.db"
        writer = SqliteEventWriter(path=invalid_path)
        # Should not raise
        writer.write(_make_event())

    def test_insert_or_ignore_dedup(self):
        writer = SqliteEventWriter(path=self.db_path)
        evt = _make_event()
        writer.write(evt)
        writer.write(evt)  # Same event_id

        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)
        writer.close()

    def test_thread_safety(self):
        writer = SqliteEventWriter(path=self.db_path)
        errors = []

        def write_events(thread_id):
            try:
                for i in range(10):
                    writer.write(
                        _make_event(
                            trace_id=f"thread-{thread_id}-event-{i}",
                        )
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_events, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)

        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        conn.close()
        self.assertEqual(count, 100)
        writer.close()

    def test_pruning_at_close(self):
        """Pruning happens in close(), not during writes.

        agent-sec-cli is short-lived: each invocation is a separate process,
        so counter-based pruning inside write() would never accumulate across
        invocations.  Instead, close() (called via atexit) prunes once per
        process lifetime.
        """
        writer = SqliteEventWriter(path=self.db_path, max_age_days=0)

        for _ in range(10):
            writer.write(_make_event())
        time.sleep(0.01)  # Ensure events are in the past relative to close()

        # Before close: all events still present
        conn = sqlite3.connect(self.db_path)
        count_before = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[
            0
        ]
        conn.close()
        self.assertEqual(count_before, 10)

        # After close: pruning removes events (max_age_days=0 means cutoff=now)
        writer.close()

        conn = sqlite3.connect(self.db_path)
        count_after = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        conn.close()
        self.assertLess(count_after, 10)

    def test_corruption_detection_and_rebuild(self):
        writer = SqliteEventWriter(path=self.db_path)
        writer.write(_make_event())
        writer.close()

        # Corrupt the DB file
        with open(self.db_path, "r+b") as f:
            f.write(b"CORRUPT_GARBAGE" * 100)

        # Create new writer on same path — should detect corruption, delete,
        # recreate fresh DB, and successfully write the current event
        writer2 = SqliteEventWriter(path=self.db_path)
        writer2.write(_make_event())

        # Fresh DB should exist with the event (no event dropped)
        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)
        writer2.close()

    def test_schema_migration_adds_columns(self):
        # _COLUMNS dict is currently empty, so just verify _ensure_schema runs without error
        writer = SqliteEventWriter(path=self.db_path)
        writer.write(_make_event())

        conn = sqlite3.connect(self.db_path)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(security_events)")}
        conn.close()
        # Verify core columns exist
        self.assertIn("event_id", columns)
        self.assertIn("event_type", columns)
        self.assertIn("category", columns)
        self.assertIn("timestamp_epoch", columns)
        writer.close()

    def test_close_performs_checkpoint(self):
        writer = SqliteEventWriter(path=self.db_path)
        writer.write(_make_event())
        writer.write(_make_event())

        writer.close()
        self.assertIsNone(writer._conn)

    def test_disabled_after_delete_failure(self):
        writer = SqliteEventWriter(path=self.db_path)
        writer.write(_make_event())
        writer.close()

        # Corrupt the DB
        with open(self.db_path, "r+b") as f:
            f.write(b"CORRUPT_GARBAGE" * 100)

        writer2 = SqliteEventWriter(path=self.db_path)

        # Mock Path.unlink to raise OSError
        with patch.object(Path, "unlink", side_effect=OSError("permission denied")):
            writer2.write(_make_event())

        # Writer should be disabled now
        self.assertTrue(writer2._disabled)

        # Subsequent writes should be no-ops
        writer2.write(_make_event())


if __name__ == "__main__":
    unittest.main()
