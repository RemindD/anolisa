"""prompt_scan backend — delegates to the prompt_scanner package."""

import json
from typing import Any

from agent_sec_cli.prompt_scanner.config import ScanMode
from agent_sec_cli.prompt_scanner.result import Verdict
from agent_sec_cli.prompt_scanner.scanner import PromptScanner
from agent_sec_cli.security_middleware.backends.base import BaseBackend
from agent_sec_cli.security_middleware.context import RequestContext
from agent_sec_cli.security_middleware.result import ActionResult


class PromptScanBackend(BaseBackend):
    """Scan prompt text for injection / jailbreak attempts using the prompt_scanner engine."""

    def execute(self, ctx: RequestContext, **kwargs: Any) -> ActionResult:
        text: str = kwargs.get("text", "")
        mode_str: str = kwargs.get("mode", "standard")
        source: str = kwargs.get("source", "")

        if not text or not text.strip():
            return ActionResult(
                success=False,
                error="prompt_scan error: no input text provided",
                exit_code=1,
            )

        try:
            scan_mode = ScanMode(mode_str.lower())
        except ValueError:
            return ActionResult(
                success=False,
                error=f"prompt_scan error: invalid mode '{mode_str}'. Choose from: fast, standard, strict",
                exit_code=1,
            )

        try:
            scanner = PromptScanner(mode=scan_mode)
            result = scanner.scan(text, source=source if source else None)
        except Exception as exc:
            return _scanner_error_result(f"Scanner error: {exc}")

        has_error = result.verdict == Verdict.ERROR
        d = result.to_dict()

        return ActionResult(
            success=not has_error,
            data=d,
            stdout=json.dumps(d, indent=2, ensure_ascii=False),
            exit_code=1 if has_error else 0,
        )


def _scanner_error_result(message: str) -> ActionResult:
    data = {
        "schema_version": "1.0",
        "ok": False,
        "verdict": Verdict.ERROR.value,
        "risk_level": "unknown",
        "threat_type": "unknown",
        "confidence": 0.0,
        "summary": message,
        "findings": [],
        "layer_results": [],
        "engine_version": "0.1.0",
        "elapsed_ms": 0,
    }
    return ActionResult(
        success=False,
        data=data,
        stdout=json.dumps(data, indent=2, ensure_ascii=False),
        error=message,
        exit_code=1,
    )
