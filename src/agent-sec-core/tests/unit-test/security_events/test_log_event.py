"""Unit tests for security_events — module-level log_event() and get_writer()."""

import unittest
from unittest.mock import MagicMock, patch

from security_events.schema import SecurityEvent


class TestGetWriter(unittest.TestCase):
    def test_singleton_returns_same_instance(self):
        import security_events
        # Reset singleton
        security_events._writer = None
        w1 = security_events.get_writer()
        w2 = security_events.get_writer()
        self.assertIs(w1, w2)
        # Cleanup
        security_events._writer = None


class TestLogEvent(unittest.TestCase):
    @patch("security_events.get_writer")
    def test_log_event_delegates_to_writer(self, mock_get_writer):
        mock_writer = MagicMock()
        mock_get_writer.return_value = mock_writer

        from security_events import log_event

        evt = SecurityEvent(event_type="t", category="c", details={})
        log_event(evt)

        mock_writer.write.assert_called_once_with(evt)

    @patch("security_events.get_writer")
    def test_log_event_swallows_exceptions(self, mock_get_writer):
        mock_writer = MagicMock()
        mock_writer.write.side_effect = RuntimeError("disk full")
        mock_get_writer.return_value = mock_writer

        from security_events import log_event

        evt = SecurityEvent(event_type="t", category="c", details={})
        # Should not raise
        log_event(evt)


if __name__ == "__main__":
    unittest.main()
