"""Offline tests for the scanner adapters in :mod:`autotriage.scanners`.

No real scanner binaries or network access are used: ``shutil.which`` and the
subprocess boundary are monkeypatched so the adapters parse small, inlined,
representative JSON blobs captured from each tool.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from autotriage import scanners
from autotriage.schema import FindingType, ScannerTool

# ---------------------------------------------------------------------------
# Representative raw tool output (trimmed to the fields the adapters read).
# ---------------------------------------------------------------------------

SEMGREP_JSON: dict[str, Any] = {
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query",
            "path": "target/app.py",
            "start": {"line": 44, "col": 5},
            "end": {"line": 44, "col": 60},
            "extra": {
                "message": "User input is interpolated into a SQL query.",
                "severity": "ERROR",
                "lines": "cursor.execute(f\"SELECT * FROM users WHERE n='{u}'\")",
                "metadata": {
                    "cwe": [
                        "CWE-89: Improper Neutralization of Special Elements "
                        "used in an SQL Command ('SQL Injection')"
                    ],
                    "owasp": ["A03:2021 - Injection"],
                },
            },
        }
    ],
    "errors": [],
}

TRIVY_JSON: dict[str, Any] = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "target/requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2018-18074",
                    "PkgName": "requests",
                    "InstalledVersion": "2.19.1",
                    "FixedVersion": "2.20.0",
                    "Title": "requests leaks Authorization header on redirect",
                    "Description": "Vulnerable requests version.",
                    "Severity": "HIGH",
                    "CweIDs": ["CWE-200"],
                }
            ],
        },
        {
            "Target": "target/infra/main.tf",
            "Class": "config",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AVD-AWS-0086",
                    "AVDID": "AVD-AWS-0086",
                    "Title": "S3 bucket allows public read ACL",
                    "Description": "The bucket is world-readable.",
                    "Severity": "HIGH",
                    "CauseMetadata": {
                        "StartLine": 6,
                        "EndLine": 6,
                        "Code": {
                            "Lines": [{"Number": 6, "Content": 'acl = "public-read"'}]
                        },
                    },
                }
            ],
        },
        {
            "Target": "target/app.py",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "StartLine": 18,
                    "EndLine": 18,
                    "Match": 'AWS_ACCESS_KEY_ID = "AKIA****"',
                }
            ],
        },
    ],
}

GITLEAKS_JSON: list[dict[str, Any]] = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "StartLine": 18,
        "EndLine": 18,
        "Match": "AKIA4TQ7NREALKEY1234",
        "Secret": "AKIA4TQ7NREALKEY1234",
        "File": "target/app.py",
        "Fingerprint": "target/app.py:aws-access-token:18",
    }
]


class _FakeCompletedProcess:
    """Minimal stand-in for :class:`subprocess.CompletedProcess`."""

    def __init__(self, stdout: str = "", stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = 0


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------


def test_run_semgrep_normalizes_sast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        scanners.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess(stdout=json.dumps(SEMGREP_JSON)),
    )

    findings = scanners.run_semgrep(Path("target"))

    assert len(findings) == 1
    f = findings[0]
    assert f.tool is ScannerTool.SEMGREP
    assert f.type is FindingType.SAST
    assert f.rule_id == "python.lang.security.audit.formatted-sql-query"
    assert f.severity_raw == "ERROR"
    assert f.cwe == ["CWE-89"]
    assert f.owasp == ["A03:2021"]
    assert f.file == "target/app.py"
    assert f.line == 44
    assert "cursor.execute" in f.code_snippet
    assert f.raw == SEMGREP_JSON["results"][0]


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------


def test_run_trivy_normalizes_all_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(
        scanners.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess(stdout=json.dumps(TRIVY_JSON)),
    )

    findings = scanners.run_trivy(Path("target"))
    by_type = {f.type: f for f in findings}

    assert set(by_type) == {
        FindingType.SCA,
        FindingType.IAC,
        FindingType.SECRET,
    }

    sca = by_type[FindingType.SCA]
    assert sca.tool is ScannerTool.TRIVY
    assert sca.rule_id == "CVE-2018-18074"
    assert sca.cwe == ["CWE-200"]
    assert sca.file == "target/requirements.txt"
    assert sca.package == "requests"
    assert sca.installed_version == "2.19.1"
    assert sca.fixed_version == "2.20.0"
    assert sca.severity_raw == "HIGH"

    iac = by_type[FindingType.IAC]
    assert iac.rule_id == "AVD-AWS-0086"
    assert iac.file == "target/infra/main.tf"
    assert iac.line == 6
    assert "public-read" in iac.code_snippet

    secret = by_type[FindingType.SECRET]
    assert secret.rule_id == "aws-access-key-id"
    assert secret.line == 18
    assert secret.cwe == ["CWE-798"]


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------


def test_run_gitleaks_normalizes_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/bin/gitleaks")

    def _fake_run(cmd: list[str], **_: object) -> _FakeCompletedProcess:
        # Gitleaks writes its report to the path after --report-path.
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text(json.dumps(GITLEAKS_JSON), encoding="utf-8")
        return _FakeCompletedProcess()

    monkeypatch.setattr(scanners.subprocess, "run", _fake_run)

    findings = scanners.run_gitleaks(Path("target"))

    assert len(findings) == 1
    f = findings[0]
    assert f.tool is ScannerTool.GITLEAKS
    assert f.type is FindingType.SECRET
    assert f.rule_id == "aws-access-token"
    assert f.file == "target/app.py"
    assert f.line == 18
    assert f.cwe == ["CWE-798"]
    assert "AKIA" in f.code_snippet


# ---------------------------------------------------------------------------
# Missing binaries / resilience
# ---------------------------------------------------------------------------


def test_missing_binary_returns_empty_and_warns(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(scanners.shutil, "which", lambda _: None)

    def _boom(*_: object, **__: object) -> None:
        raise AssertionError("subprocess must not run when binary is missing")

    monkeypatch.setattr(scanners.subprocess, "run", _boom)

    with caplog.at_level("WARNING", logger="autotriage.scanners"):
        assert scanners.run_semgrep(Path("target")) == []
        assert scanners.run_trivy(Path("target")) == []
        assert scanners.run_gitleaks(Path("target")) == []

    assert "not found" in caplog.text


def test_subprocess_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/bin/semgrep")

    def _raise(*_: object, **__: object) -> None:
        raise subprocess.SubprocessError("boom")

    monkeypatch.setattr(scanners.subprocess, "run", _raise)

    assert scanners.run_semgrep(Path("target")) == []


def test_invalid_json_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(
        scanners.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess(stdout="not json {"),
    )

    assert scanners.run_trivy(Path("target")) == []


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def test_run_scans_dedupes_and_selects_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        scanners.subprocess,
        "run",
        lambda *a, **k: _FakeCompletedProcess(stdout=json.dumps(SEMGREP_JSON)),
    )

    findings = scanners.run_scans(Path("target"), tools=[ScannerTool.SEMGREP])
    ids = [f.id for f in findings]

    assert len(findings) == 1
    assert len(ids) == len(set(ids))
