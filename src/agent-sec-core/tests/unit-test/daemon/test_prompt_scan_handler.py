"""Tests for daemon scan-prompt handler."""

import asyncio
from pathlib import Path

import pytest
from agent_sec_cli.correlation_context import TraceContext
from agent_sec_cli.daemon.errors import UnavailableError
from agent_sec_cli.daemon.handlers.prompt_scan import prompt_scan_handler
from agent_sec_cli.daemon.protocol import DaemonRequest
from agent_sec_cli.daemon.request_context import daemon_request_context
from agent_sec_cli.daemon.runtime import DaemonRuntime
from agent_sec_cli.security_middleware.result import ActionResult


def test_prompt_scan_handler_rejects_when_prompt_runtime_not_ready(tmp_path: Path):
    runtime = DaemonRuntime(socket_path=tmp_path / "daemon.sock")
    request = DaemonRequest(
        method="scan-prompt",
        request_id="req-prompt",
        params={"text": "hello", "mode": "standard"},
    )

    with pytest.raises(UnavailableError, match="prompt scanner is not ready"):
        asyncio.run(prompt_scan_handler(request, runtime))


@pytest.mark.parametrize(
    ("status", "model", "last_error", "expected_parts"),
    [
        (
            "pending",
            None,
            None,
            ("prompt scanner is not ready: status=pending",),
        ),
        (
            "downloading",
            "LLM-Research/Llama-Prompt-Guard-2-86M",
            None,
            (
                "model download is still in progress",
                "status=downloading",
                "model=LLM-Research/Llama-Prompt-Guard-2-86M",
            ),
        ),
        (
            "loading",
            "LLM-Research/Llama-Prompt-Guard-2-86M",
            None,
            (
                "model download completed and the model is loading",
                "status=loading",
                "model=LLM-Research/Llama-Prompt-Guard-2-86M",
            ),
        ),
        (
            "degraded",
            "LLM-Research/Llama-Prompt-Guard-2-86M",
            "forced preload failure",
            (
                "prompt scanner preload failed",
                "agent-sec-cli scan-prompt warmup",
                "restart the agent-sec daemon process",
                "status=degraded",
                "model=LLM-Research/Llama-Prompt-Guard-2-86M",
                "last_error=forced preload failure",
            ),
        ),
    ],
)
def test_prompt_scan_handler_unavailable_message_describes_preload_state(
    status: str,
    model: str | None,
    last_error: str | None,
    expected_parts: tuple[str, ...],
    tmp_path: Path,
):
    runtime = DaemonRuntime(socket_path=tmp_path / "daemon.sock")
    runtime.prompt_scan_state.status = status
    runtime.prompt_scan_state.model = model
    runtime.prompt_scan_state.last_error = last_error
    request = DaemonRequest(
        method="scan-prompt",
        request_id="req-prompt",
        params={"text": "hello", "mode": "standard"},
    )

    with pytest.raises(UnavailableError) as exc_info:
        asyncio.run(prompt_scan_handler(request, runtime))

    message = exc_info.value.message
    for expected_part in expected_parts:
        assert expected_part in message


def test_prompt_scan_handler_invokes_middleware_with_prompt_params(
    monkeypatch,
    tmp_path: Path,
):
    runtime = DaemonRuntime(socket_path=tmp_path / "daemon.sock")
    runtime.prompt_scan_state.status = "ready"
    runtime.prompt_scan_state.loaded = True
    captured = {}

    def fake_invoke_prompt_scan(**kwargs):
        captured.update(kwargs)
        return ActionResult(
            success=True,
            data={"ok": True, "verdict": "pass"},
            stdout='{"ok": true, "verdict": "pass"}',
            exit_code=0,
        )

    monkeypatch.setattr(
        "agent_sec_cli.daemon.handlers.prompt_scan._invoke_prompt_scan",
        fake_invoke_prompt_scan,
    )
    request = DaemonRequest(
        method="scan-prompt",
        request_id="req-prompt",
        params={"text": "hello", "mode": "standard", "source": "user_input"},
        trace_context={"trace_id": "trace-1"},
    )

    result = asyncio.run(prompt_scan_handler(request, runtime))

    assert captured == {
        "text": "hello",
        "mode": "standard",
        "source": "user_input",
    }
    assert result.data == {"ok": True, "verdict": "pass"}
    assert result.stdout == '{"ok": true, "verdict": "pass"}'
    assert result.stderr == ""
    assert result.exit_code == 0


def test_prompt_scan_handler_uses_gateway_trace_context(
    monkeypatch,
    tmp_path: Path,
):
    runtime = DaemonRuntime(socket_path=tmp_path / "daemon.sock")
    runtime.prompt_scan_state.status = "ready"
    runtime.prompt_scan_state.loaded = True
    captured = {}

    class FakeBackend:
        def execute(self, ctx, **_kwargs):
            captured["ctx"] = ctx
            return ActionResult(success=True, data={"ok": True})

    monkeypatch.setattr(
        "agent_sec_cli.security_middleware.router.get_backend",
        lambda _action: FakeBackend(),
    )
    request = DaemonRequest(
        method="scan-prompt",
        request_id="req-prompt",
        params={"text": "hello", "mode": "standard"},
    )

    with daemon_request_context(
        TraceContext(
            trace_id="trace-1",
            session_id="session-1",
            run_id="run-1",
        )
    ):
        result = asyncio.run(prompt_scan_handler(request, runtime))

    ctx = captured["ctx"]
    assert ctx.trace_id == "trace-1"
    assert ctx.caller == "daemon"
    assert ctx.session_id == "session-1"
    assert ctx.run_id == "run-1"
    assert result.data == {"ok": True}


def test_prompt_scan_handler_preserves_action_result_error(
    monkeypatch,
    tmp_path: Path,
):
    runtime = DaemonRuntime(socket_path=tmp_path / "daemon.sock")
    runtime.prompt_scan_state.status = "ready"
    runtime.prompt_scan_state.loaded = True

    def fake_invoke_prompt_scan(**_kwargs):
        return ActionResult(
            success=False,
            error="prompt_scan error: no input text provided",
            exit_code=1,
        )

    monkeypatch.setattr(
        "agent_sec_cli.daemon.handlers.prompt_scan._invoke_prompt_scan",
        fake_invoke_prompt_scan,
    )
    request = DaemonRequest(method="scan-prompt", request_id="req-prompt")

    result = asyncio.run(prompt_scan_handler(request, runtime))

    assert result.stderr == "prompt_scan error: no input text provided"
    assert result.exit_code == 1
