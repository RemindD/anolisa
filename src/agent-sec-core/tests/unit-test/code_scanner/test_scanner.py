from agent_sec_cli.code_scanner.models import Language, Verdict
from agent_sec_cli.code_scanner.scanner import scan


def test_scan_detection(scan_test_case: tuple) -> None:
    """Parametrised four-tuple test: (code, language, rule_id, expected_count)."""
    code, language, rule_id, expected_count = scan_test_case
    result = scan(code, language, rules=[rule_id])
    assert result.ok is True
    assert len(result.findings) == expected_count, (
        f"Expected {expected_count} finding(s) for rule '{rule_id}' on: {code!r}, "
        f"got {len(result.findings)}: {[f.rule_id for f in result.findings]}"
    )


def test_scan_pass_verdict() -> None:
    """When no rule matches, verdict should be PASS."""
    result = scan("echo hello", Language.BASH)
    assert result.ok is True
    assert result.verdict == Verdict.PASS
    assert result.findings == []


def test_scan_warn_verdict() -> None:
    """A matching warn-severity rule should produce WARN verdict."""
    result = scan("rm -rf /tmp/test", Language.BASH)
    assert result.ok is True
    assert result.verdict == Verdict.WARN
    assert len(result.findings) > 0
    assert all(f.severity.value == "warn" for f in result.findings)


def test_scan_result_schema_fields() -> None:
    """ScanResult must expose all required fields."""
    result = scan("ls -la", Language.BASH)
    assert result.language == Language.BASH
    assert isinstance(result.elapsed_ms, int)
    assert result.elapsed_ms >= 0


def test_scan_evidence_is_list() -> None:
    """evidence field must be a list of strings."""
    result = scan("rm -rf /a && rm -r /b", Language.BASH)
    assert result.ok is True
    for finding in result.findings:
        assert isinstance(finding.evidence, list)
        assert len(finding.evidence) >= 1
        assert all(isinstance(e, str) for e in finding.evidence)


def test_scan_unknown_language_no_rules() -> None:
    """Scanning with a language that has no rule files still returns ok=True, PASS."""
    result = scan("print('hello')", Language.PYTHON)
    assert result.ok is True
    assert result.verdict == Verdict.PASS
    assert result.findings == []
