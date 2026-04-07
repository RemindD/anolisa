"""Unit tests for security_events.writer — SecurityEventWriter."""

import json
import os
import tempfile
import threading
import unittest

from security_events.schema import SecurityEvent
from security_events.writer import SecurityEventWriter


def _make_event(**overrides):
    defaults = dict(event_type="test", category="test_cat", details={"k": "v"})
    defaults.update(overrides)
    return SecurityEvent(**defaults)


class TestWriterBasic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        )
        self.tmp.close()
        self.writer = SecurityEventWriter(path=self.tmp.name)

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_write_appends_jsonl_line(self):
        evt = _make_event()
        self.writer.write(evt)
        with open(self.tmp.name) as fh:
            lines = fh.readlines()
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["event_type"], "test")

    def test_write_multiple_events(self):
        for i in range(3):
            self.writer.write(_make_event(event_type=f"evt_{i}"))
        with open(self.tmp.name) as fh:
            lines = fh.readlines()
        self.assertEqual(len(lines), 3)
        for i, line in enumerate(lines):
            self.assertEqual(json.loads(line)["event_type"], f"evt_{i}")


class TestWriterRotation(unittest.TestCase):
    def test_rotation_detection(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        )
        tmp.close()
        writer = SecurityEventWriter(path=tmp.name)

        # Write first event
        writer.write(_make_event(event_type="before_rotate"))

        # Simulate rotation: delete and recreate
        os.unlink(tmp.name)
        with open(tmp.name, "w"):
            pass  # empty file

        # Write after rotation
        writer.write(_make_event(event_type="after_rotate"))

        with open(tmp.name) as fh:
            lines = fh.readlines()
        # New file should have the post-rotation event
        self.assertTrue(len(lines) >= 1)
        parsed = json.loads(lines[-1])
        self.assertEqual(parsed["event_type"], "after_rotate")

        os.unlink(tmp.name)


class TestWriterFireAndForget(unittest.TestCase):
    def test_write_with_no_fd_does_not_raise(self):
        writer = SecurityEventWriter(path="/nonexistent/path/events.jsonl")
        # fd should be None after failed open, write should not raise
        writer.write(_make_event())


class TestWriterThreadSafety(unittest.TestCase):
    def test_concurrent_writes(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        )
        tmp.close()
        writer = SecurityEventWriter(path=tmp.name)

        n_threads = 10
        events_per_thread = 5
        errors = []

        def _write_events(tid):
            try:
                for i in range(events_per_thread):
                    writer.write(_make_event(event_type=f"t{tid}_{i}"))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=_write_events, args=(t,))
            for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Unexpected errors: {errors}")

        with open(tmp.name) as fh:
            lines = fh.readlines()
        self.assertEqual(len(lines), n_threads * events_per_thread)

        os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
