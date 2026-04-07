"""Summary backend — aggregate security events from the JSONL log."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from security_middleware.result import ActionResult


class SummaryBackend:
    """Read the security-events JSONL file and produce an aggregated report."""

    def execute(
        self,
        ctx,
        hours: int = 24,
        format: str = "text",
        **kwargs,
    ) -> ActionResult:
        """Generate a summary of security events within the last *hours* hours.

        Args:
            ctx:    Request context.
            hours:  Look-back window in hours (default 24).
            format: Output format — ``"text"`` or ``"json"``.
        """
        try:
            from security_events.config import get_log_path
        except ImportError:
            return ActionResult(
                success=False,
                error="security_events.config module not available",
            )

        log_path = get_log_path()

        if not os.path.isfile(log_path):
            return self._empty_report(hours, format)

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        seen_ids: set[str] = set()
        events: list[dict] = []

        try:
            with open(log_path, "r", encoding="utf-8") as fh:
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        evt = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue

                    # Deduplicate by event_id.
                    eid = evt.get("event_id", "")
                    if eid and eid in seen_ids:
                        continue
                    if eid:
                        seen_ids.add(eid)

                    # Filter by timestamp.
                    ts_str = evt.get("timestamp", "")
                    if ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            if ts.tzinfo is None:
                                ts = ts.replace(tzinfo=timezone.utc)
                            if ts < cutoff:
                                continue
                        except (ValueError, TypeError):
                            pass  # keep event if timestamp is unparseable

                    events.append(evt)
        except OSError as exc:
            return ActionResult(success=False, error=f"Cannot read log: {exc}")

        # ---- Aggregate by category ----
        categories: dict[str, int] = defaultdict(int)
        for evt in events:
            cat = evt.get("category", "unknown")
            categories[cat] += 1

        stats = {
            "period_hours": hours,
            "total_events": len(events),
            "categories": dict(categories),
        }

        if format == "json":
            report_data = {**stats, "events": events}
            report = json.dumps(report_data, indent=2, default=str)
        else:
            report = self._format_text(stats, categories)

        return ActionResult(success=True, stdout=report, data=stats)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_text(
        stats: dict,
        categories: dict[str, int],
    ) -> str:
        lines = [
            f"Security Event Summary (last {stats['period_hours']}h)",
            "=" * 50,
            f"Total events: {stats['total_events']}",
            "",
            "Category breakdown:",
        ]
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            lines.append(f"  {cat}: {count}")
        lines.append("=" * 50)
        return "\n".join(lines) + "\n"

    @staticmethod
    def _empty_report(hours: int, fmt: str) -> ActionResult:
        stats = {"period_hours": hours, "total_events": 0, "categories": {}}
        if fmt == "json":
            report = json.dumps({**stats, "events": []}, indent=2)
        else:
            report = (
                f"Security Event Summary (last {hours}h)\n"
                f"{'=' * 50}\n"
                f"Total events: 0\n"
                f"{'=' * 50}\n"
            )
        return ActionResult(success=True, stdout=report, data=stats)
