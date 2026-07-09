"""Property-based robustness tests for the scanner normalizers.

The adapters consume third-party JSON that varies wildly between tool versions.
These tests fuzz each adapter with synthetic, deliberately-messy scanner-shaped
payloads and assert two invariants for every input:

* the normalizer never raises; and
* whatever it returns is a list of schema-valid :class:`Finding` objects.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest import mock

import hypothesis.strategies as st
import pytest
from hypothesis import HealthCheck, given, settings

from autotriage import scanners
from autotriage.schema import Finding

pytestmark = pytest.mark.property

_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-5, max_value=5)
    | st.text(max_size=12)
)
# Line-number fields are numeric in every real scanner's JSON; the adapters
# coerce them with int(), so fuzz them as integers rather than arbitrary text.
_line = st.none() | st.integers(min_value=0, max_value=9999)


class _FakeProc:
    """Stand-in for a completed subprocess with canned stdout."""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def _assert_valid_findings(findings: list[Finding]) -> None:
    """Every returned finding must itself round-trip through the schema."""
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, Finding)
        assert Finding.model_validate(finding.model_dump()) == finding
        assert len(finding.id) == 12


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
_semgrep_result = st.fixed_dictionaries(
    {},
    optional={
        "check_id": _scalars,
        "path": _scalars,
        "start": st.fixed_dictionaries({}, optional={"line": _line}),
        "extra": st.fixed_dictionaries(
            {},
            optional={
                "message": _scalars,
                "severity": _scalars,
                "lines": _scalars,
                "metadata": st.fixed_dictionaries(
                    {},
                    optional={
                        "cwe": _scalars | st.lists(_scalars),
                        "owasp": _scalars,
                    },
                ),
            },
        ),
    },
)
_semgrep_payload = st.fixed_dictionaries(
    {}, optional={"results": st.lists(_semgrep_result | _scalars, max_size=4)}
)


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(payload=_semgrep_payload)
def test_semgrep_normalizer_is_total(payload: dict[str, Any]) -> None:
    """Semgrep normalization never crashes and yields valid findings."""
    with (
        mock.patch.object(scanners.shutil, "which", return_value="/bin/semgrep"),
        mock.patch.object(
            scanners.subprocess, "run", return_value=_FakeProc(json.dumps(payload))
        ),
    ):
        _assert_valid_findings(scanners.run_semgrep(Path("target")))


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------
_trivy_vuln = st.fixed_dictionaries(
    {},
    optional={
        "VulnerabilityID": _scalars,
        "PkgName": _scalars,
        "InstalledVersion": _scalars,
        "FixedVersion": _scalars,
        "Title": _scalars,
        "Description": _scalars,
        "Severity": _scalars,
        "CweIDs": _scalars | st.lists(_scalars),
    },
)
_trivy_misconfig = st.fixed_dictionaries(
    {},
    optional={
        "ID": _scalars,
        "AVDID": _scalars,
        "Title": _scalars,
        "Description": _scalars,
        "Severity": _scalars,
        "CauseMetadata": st.fixed_dictionaries(
            {},
            optional={
                "StartLine": _line,
                "Code": st.none()
                | st.fixed_dictionaries(
                    {},
                    optional={
                        "Lines": st.lists(
                            st.none()
                            | st.fixed_dictionaries({}, optional={"Content": _scalars}),
                            max_size=3,
                        )
                    },
                ),
            },
        ),
    },
)
_trivy_secret = st.fixed_dictionaries(
    {},
    optional={
        "RuleID": _scalars,
        "Severity": _scalars,
        "Title": _scalars,
        "StartLine": _line,
        "Match": _scalars,
    },
)
_trivy_result = st.fixed_dictionaries(
    {},
    optional={
        "Target": _scalars,
        "Vulnerabilities": st.lists(_trivy_vuln, max_size=3),
        "Misconfigurations": st.lists(_trivy_misconfig, max_size=3),
        "Secrets": st.lists(_trivy_secret, max_size=3),
    },
)
_trivy_payload = st.fixed_dictionaries(
    {}, optional={"Results": st.lists(_trivy_result | _scalars, max_size=3)}
)


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(payload=_trivy_payload)
def test_trivy_normalizer_is_total(payload: dict[str, Any]) -> None:
    """Trivy normalization never crashes and yields valid findings."""
    with (
        mock.patch.object(scanners.shutil, "which", return_value="/bin/trivy"),
        mock.patch.object(
            scanners.subprocess, "run", return_value=_FakeProc(json.dumps(payload))
        ),
    ):
        _assert_valid_findings(scanners.run_trivy(Path("target")))


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------
_gitleaks_record = st.fixed_dictionaries(
    {},
    optional={
        "RuleID": _scalars,
        "Description": _scalars,
        "StartLine": _line,
        "Match": _scalars,
        "File": _scalars,
    },
)
_gitleaks_payload = st.lists(_gitleaks_record | _scalars, max_size=4)


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(payload=_gitleaks_payload)
def test_gitleaks_normalizer_is_total(payload: list[Any]) -> None:
    """Gitleaks normalization never crashes and yields valid findings."""

    def _fake_run(cmd: list[str], **_: object) -> _FakeProc:
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text(json.dumps(payload), encoding="utf-8")
        return _FakeProc("")

    with (
        mock.patch.object(scanners.shutil, "which", return_value="/bin/gitleaks"),
        mock.patch.object(scanners.subprocess, "run", _fake_run),
    ):
        _assert_valid_findings(scanners.run_gitleaks(Path("target")))
