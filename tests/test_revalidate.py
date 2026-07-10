"""Offline tests for the fix-validation loop.

No scanners or network: the re-scan is a deterministic fake that emits a finding
whenever a marker token is present in the (isolated, patched) working copy. This
exercises the *real* copy -> apply-patch -> re-scan flow — including path
isolation — while staying fully reproducible in CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from autotriage.revalidate import (
    FixApplyError,
    apply_fix_patch,
    finding_signature,
    make_rescan,
    render_report,
    validate_fix,
    validate_fixes,
)
from autotriage.schema import (
    FileEdit,
    Finding,
    FindingType,
    FixPatch,
    ScannerTool,
    ValidationStatus,
)

#: Marker tokens the fake scanner keys on, and the rule each maps to.
_MARKERS = {"INSECURE": "R1-insecure", "NEWBUG": "R2-newbug"}


def _finding(rule_id: str, *, file: str = "vuln.txt", line: int = 1) -> Finding:
    """Build a minimal IaC-style finding for a given rule id."""
    return Finding(
        id=f"id-{rule_id}",
        tool=ScannerTool.TRIVY,
        type=FindingType.IAC,
        rule_id=rule_id,
        title=f"planted {rule_id}",
        severity_raw="HIGH",
        file=file,
        line=line,
    )


def _fake_rescan(workdir: Path) -> list[Finding]:
    """Emit a finding for every marker token found in any file under ``workdir``."""
    findings: list[Finding] = []
    for path in sorted(workdir.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(workdir))
        for token, rule in _MARKERS.items():
            if token in text:
                findings.append(_finding(rule, file=rel))
    return findings


@pytest.fixture
def target(tmp_path: Path) -> Path:
    """A tiny target tree whose single file trips the ``INSECURE`` marker."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "vuln.txt").write_text("token=INSECURE keep=HARMLESS\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# finding_signature
# ---------------------------------------------------------------------------
def test_signature_ignores_line_and_uses_basename() -> None:
    a = _finding("R1", file="infra/main.tf", line=6)
    b = _finding("R1", file="target/infra/main.tf", line=42)
    # Same tool + rule + basename -> same signature despite different line/dir.
    assert finding_signature(a) == finding_signature(b)
    assert finding_signature(a) == ("trivy", "R1", "main.tf")


# ---------------------------------------------------------------------------
# apply_fix_patch
# ---------------------------------------------------------------------------
def test_apply_patch_replaces_unique_match(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("a INSECURE b", encoding="utf-8")
    patch = FixPatch(
        finding_id="x",
        edits=[FileEdit(file="f.txt", search="INSECURE", replace="SAFE")],
    )
    apply_fix_patch(patch, tmp_path)
    assert (tmp_path / "f.txt").read_text(encoding="utf-8") == "a SAFE b"


def test_apply_patch_missing_search_raises(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("nothing here", encoding="utf-8")
    patch = FixPatch(
        finding_id="x", edits=[FileEdit(file="f.txt", search="ABSENT", replace="y")]
    )
    with pytest.raises(FixApplyError, match="not found"):
        apply_fix_patch(patch, tmp_path)


def test_apply_patch_ambiguous_search_refuses(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("dup dup", encoding="utf-8")
    patch = FixPatch(
        finding_id="x", edits=[FileEdit(file="f.txt", search="dup", replace="z")]
    )
    with pytest.raises(FixApplyError, match="ambiguous"):
        apply_fix_patch(patch, tmp_path)


def test_apply_patch_path_traversal_rejected(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    workdir.mkdir()
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")
    patch = FixPatch(
        finding_id="x",
        edits=[FileEdit(file="../outside.txt", search="secret", replace="pwned")],
    )
    with pytest.raises(FixApplyError, match="escapes"):
        apply_fix_patch(patch, workdir)
    # The out-of-tree file must be untouched.
    assert (tmp_path / "outside.txt").read_text(encoding="utf-8") == "secret"


# ---------------------------------------------------------------------------
# validate_fix — every status, driven by the deterministic fake scanner
# ---------------------------------------------------------------------------
def test_validate_resolved(target: Path) -> None:
    finding = _finding("R1-insecure")
    patch = FixPatch(
        finding_id=finding.id,
        edits=[FileEdit(file="vuln.txt", search="INSECURE", replace="SAFE")],
    )
    result = validate_fix(target, finding, patch, rescan=_fake_rescan)
    assert result.status is ValidationStatus.RESOLVED
    assert result.resolved is True
    assert result.signatures_before == 1
    assert result.signatures_after == 0
    # The original target is never mutated.
    assert "INSECURE" in (target / "vuln.txt").read_text(encoding="utf-8")


def test_validate_unresolved_when_fix_misses_root_cause(target: Path) -> None:
    finding = _finding("R1-insecure")
    # Edits an unrelated token; the INSECURE marker still trips the scanner.
    patch = FixPatch(
        finding_id=finding.id,
        edits=[FileEdit(file="vuln.txt", search="HARMLESS", replace="TIDIED")],
    )
    result = validate_fix(target, finding, patch, rescan=_fake_rescan)
    assert result.status is ValidationStatus.UNRESOLVED
    assert result.resolved is False


def test_validate_regressed_when_fix_introduces_new_finding(target: Path) -> None:
    finding = _finding("R1-insecure")
    # Removes the original marker but plants a new one -> regression.
    patch = FixPatch(
        finding_id=finding.id,
        edits=[FileEdit(file="vuln.txt", search="INSECURE", replace="NEWBUG")],
    )
    result = validate_fix(target, finding, patch, rescan=_fake_rescan)
    assert result.status is ValidationStatus.REGRESSED
    assert result.resolved is False
    assert result.new_signatures == ["trivy:R2-newbug:vuln.txt"]


def test_validate_error_when_baseline_not_reproduced(target: Path) -> None:
    # No scanner emits this rule, so the baseline can't observe it -> ERROR.
    finding = _finding("R9-phantom")
    patch = FixPatch(
        finding_id=finding.id,
        edits=[FileEdit(file="vuln.txt", search="INSECURE", replace="SAFE")],
    )
    result = validate_fix(target, finding, patch, rescan=_fake_rescan)
    assert result.status is ValidationStatus.ERROR
    assert "did not reproduce" in result.detail


def test_validate_error_when_patch_does_not_apply(target: Path) -> None:
    finding = _finding("R1-insecure")
    patch = FixPatch(
        finding_id=finding.id,
        edits=[FileEdit(file="vuln.txt", search="ABSENT-TEXT", replace="x")],
    )
    result = validate_fix(target, finding, patch, rescan=_fake_rescan)
    assert result.status is ValidationStatus.ERROR
    assert "did not apply" in result.detail


def test_validate_skipped_when_no_edits(target: Path) -> None:
    finding = _finding("R1-insecure")
    result = validate_fix(
        target, finding, FixPatch(finding_id=finding.id), rescan=_fake_rescan
    )
    assert result.status is ValidationStatus.SKIPPED
    assert result.resolved is False


# ---------------------------------------------------------------------------
# batch + report
# ---------------------------------------------------------------------------
def test_validate_fixes_batch_is_independent(target: Path) -> None:
    good = _finding("R1-insecure")
    good_patch = FixPatch(
        finding_id=good.id,
        edits=[FileEdit(file="vuln.txt", search="INSECURE", replace="SAFE")],
    )
    bad = _finding("R1-insecure")
    bad_patch = FixPatch(
        finding_id=bad.id,
        edits=[FileEdit(file="vuln.txt", search="HARMLESS", replace="TIDIED")],
    )
    results = validate_fixes(
        target, [(good, good_patch), (bad, bad_patch)], rescan=_fake_rescan
    )
    assert [r.status for r in results] == [
        ValidationStatus.RESOLVED,
        ValidationStatus.UNRESOLVED,
    ]


def test_render_report_summarizes_counts(target: Path) -> None:
    finding = _finding("R1-insecure")
    patch = FixPatch(
        finding_id=finding.id,
        edits=[FileEdit(file="vuln.txt", search="INSECURE", replace="SAFE")],
    )
    result = validate_fix(target, finding, patch, rescan=_fake_rescan)
    report = render_report([result])
    assert "Fix-Validation Report" in report
    assert "1/1" in report
    assert finding.id in report


def test_make_rescan_returns_callable() -> None:
    assert callable(make_rescan())
    assert callable(make_rescan([ScannerTool.TRIVY]))
