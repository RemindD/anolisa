"""Contract tests for the shared Qwen Code trace-context helper."""

import ast
import importlib.util
import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_HOOKS_DIR = _ROOT / "qwen-code-extension" / "hooks"
_HELPER_PATH = _HOOKS_DIR / "trace_context.py"
_CONSUMERS = (
    "code_scanner_hook.py",
    "observability_hook.py",
    "pii_checker_hook.py",
    "prompt_scanner_hook.py",
    "skill_ledger_hook.py",
)


def _load_helper():
    spec = importlib.util.spec_from_file_location(
        "qwen_trace_context_helper", _HELPER_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trace_context_helper = _load_helper()


def test_trace_context_normalizes_identifiers_and_uses_canonical_precedence(
    monkeypatch,
):
    monkeypatch.setenv("QWEN_CODE_SESSION_ID", "environment-session")
    context = trace_context_helper.trace_context(
        {
            "trace_id": " trace-1 ",
            "session_id": " session-1 ",
            "run_id": "run-1",
            "turn_id": "fallback-run",
            "call_id": "call-1",
            "tool_call_id": "preferred-tool",
            "tool_use_id": "fallback-tool",
        }
    )

    assert context == {
        "agent_name": "qwen-code",
        "trace_id": "trace-1",
        "session_id": "session-1",
        "run_id": "run-1",
        "call_id": "call-1",
        "tool_call_id": "preferred-tool",
    }


def test_trace_context_uses_legacy_and_environment_fallbacks(monkeypatch):
    monkeypatch.setenv("QWEN_CODE_SESSION_ID", "s" * 300)

    context = trace_context_helper.trace_context(
        {
            "turn_id": "turn-1",
            "tool_use_id": "tool-use-1",
        }
    )

    assert context["agent_name"] == "qwen-code"
    assert context["run_id"] == "turn-1"
    assert context["tool_call_id"] == "tool-use-1"
    assert context["session_id"] == "s" * 256


def test_with_trace_context_inserts_one_compact_top_level_argument():
    command = trace_context_helper.with_trace_context(
        ["agent-sec-cli", "scan-pii", "--stdin"],
        {"session_id": "session-1"},
    )

    assert command[0:2] == ["agent-sec-cli", "--trace-context"]
    assert json.loads(command[2]) == {
        "agent_name": "qwen-code",
        "session_id": "session-1",
    }
    assert command[3:] == ["scan-pii", "--stdin"]


def test_all_qwen_hooks_import_the_shared_trace_context_helper():
    assert not (_HOOKS_DIR / "qwen_trace_context.py").exists()

    for filename in _CONSUMERS:
        tree = ast.parse((_HOOKS_DIR / filename).read_text(encoding="utf-8"))
        imports = {
            node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }
        assert "trace_context" in imports, filename
        assert "qwen_trace_context" not in imports, filename
        assert not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_trace_context"
            for node in ast.walk(tree)
        ), filename
