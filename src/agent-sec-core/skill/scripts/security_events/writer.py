"""Thread-safe, rotation-aware JSONL writer for security events."""

from __future__ import annotations

import json
import os
import sys
import threading
from typing import Optional, TextIO

from .config import get_log_path
from .schema import SecurityEvent


class SecurityEventWriter:
    """Append ``SecurityEvent`` records to a JSONL file.

    * **Thread-safe** — every ``write()`` is guarded by a ``threading.Lock``.
    * **Rotation-safe** — before each write the current inode is compared to
      the one recorded at open time; a mismatch (or missing file) triggers a
      transparent reopen.
    * **Fire-and-forget** — all internal errors are swallowed so that logging
      never disrupts the caller.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self._path: str = path or get_log_path()
        self._lock = threading.Lock()
        self._fd: Optional[TextIO] = None
        self._inode: Optional[int] = None
        self._open()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _open(self) -> None:
        """Open (or reopen) the log file and record its inode."""
        try:
            self._fd = open(self._path, "a", encoding="utf-8")  # noqa: SIM115
            self._inode = os.stat(self._path).st_ino
        except OSError as exc:
            print(
                f"[security_events] failed to open {self._path}: {exc}",
                file=sys.stderr,
            )
            self._fd = None
            self._inode = None

    def _close(self) -> None:
        """Close the current file descriptor if open."""
        if self._fd is not None:
            try:
                self._fd.close()
            except OSError:
                pass
            self._fd = None
            self._inode = None

    def _ensure_file(self) -> None:
        """Reopen the log file when inode changed or file was deleted."""
        try:
            stat = os.stat(self._path)
            if stat.st_ino != self._inode:
                self._close()
                self._open()
        except FileNotFoundError:
            self._close()
            self._open()
        except OSError as exc:
            print(
                f"[security_events] stat failed for {self._path}: {exc}",
                file=sys.stderr,
            )
            self._close()
            self._open()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, event: SecurityEvent) -> None:
        """Serialize *event* and append it as a single JSONL line.

        This method is safe to call from any thread and will never raise.
        """
        with self._lock:
            try:
                self._ensure_file()
                if self._fd is None:
                    return
                line = json.dumps(event.to_dict(), ensure_ascii=False)
                self._fd.write(line + "\n")
                self._fd.flush()
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[security_events] write error: {exc}",
                    file=sys.stderr,
                )
