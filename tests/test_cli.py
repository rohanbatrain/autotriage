"""Tests for the ``autotriage.__main__`` command-line entry point.

The triage backend is stubbed at the ``__main__`` seam so the whole CLI —
argument parsing, the per-finding loop, owner assignment, dispatch, and the
summary — runs offline against a temporary findings file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from autotriage import __main__ as cli
from autotriage.schema import (
    Action,
    Finding,
    Severity,
    TriageDecision,
    Verdict,
)

_CODEOWNERS = "*  @security-team\ntarget/app.py  @app-team\n"


def _write_findings(path: Path, findings: list[Finding]) -> None:
    """Serialize findings to a JSON array the CLI can load."""
    path.write_text(
        json.dumps([f.model_dump(mode="json") for f in findings]),
        encoding="utf-8",
    )


def _stub_triage(action: Action, *, confidence: float = 0.9) -> object:
    """Return a ``triage_finding`` replacement emitting a fixed decision."""

    def _triage(
        finding: Finding, *, backend: str = "api", model: str | None = None
    ) -> TriageDecision:
        verdict = (
            Verdict.FALSE_POSITIVE
            if action is Action.SUPPRESS
            else Verdict.TRUE_POSITIVE
        )
        return TriageDecision(
            finding_id=finding.id,
            verdict=verdict,
            severity=Severity.HIGH,
            confidence=confidence,
            business_impact="impact",
            reasoning="reasoning",
            recommended_action=action,
            suggested_owner=None,
        )

    return _triage


def _run_cli(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> int:
    """Invoke ``cli.main`` with ``args`` as argv (prog name prepended)."""
    monkeypatch.setattr("sys.argv", ["autotriage", *args])
    return cli.main()


def test_cli_full_run_writes_tickets_and_reports_counts(
    monkeypatch: pytest.MonkeyPatch,
    sample_findings: list[Finding],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A non-dry-run writes tickets, assigns owners, and summarizes counts."""
    findings = sample_findings[:3]
    findings_file = tmp_path / "findings.json"
    _write_findings(findings_file, findings)
    codeowners = tmp_path / "CODEOWNERS"
    codeowners.write_text(_CODEOWNERS, encoding="utf-8")
    tickets_dir = tmp_path / "tickets"
    tracker = tmp_path / "TRACKER.md"

    monkeypatch.setattr(cli, "triage_finding", _stub_triage(Action.OPEN_TICKET))

    exit_code = _run_cli(
        monkeypatch,
        [
            "--findings",
            str(findings_file),
            "--codeowners",
            str(codeowners),
            "--tickets-dir",
            str(tickets_dir),
            "--tracker",
            str(tracker),
            "--pr-dir",
            str(tmp_path / "prs"),
        ],
    )

    assert exit_code == 0
    for finding in findings:
        assert (tickets_dir / f"{finding.id}.md").is_file()
    assert tracker.is_file()

    out = capsys.readouterr().out
    assert "=== AutoTriage summary ===" in out
    assert f"findings triaged : {len(findings)}" in out
    assert f"tickets to write : {len(findings)}" in out
    assert "escalations      : 0" in out
    assert f"actions taken    : {len(findings)}" in out
    # CODEOWNERS owner was assigned for the app.py finding.
    app_ticket = next(
        tickets_dir / f"{f.id}.md" for f in findings if f.file == "target/app.py"
    )
    assert "@app-team" in app_ticket.read_text(encoding="utf-8")


def test_cli_dry_run_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
    sample_findings: list[Finding],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--dry-run`` triages and summarizes but writes no artifacts."""
    findings = sample_findings[:4]
    findings_file = tmp_path / "findings.json"
    _write_findings(findings_file, findings)
    tickets_dir = tmp_path / "tickets"
    tracker = tmp_path / "TRACKER.md"

    monkeypatch.setattr(cli, "triage_finding", _stub_triage(Action.OPEN_TICKET))

    exit_code = _run_cli(
        monkeypatch,
        [
            "--findings",
            str(findings_file),
            "--tickets-dir",
            str(tickets_dir),
            "--tracker",
            str(tracker),
            "--dry-run",
        ],
    )

    assert exit_code == 0
    assert not tickets_dir.exists()
    assert not tracker.exists()

    out = capsys.readouterr().out
    assert "mode             : dry-run (no actions taken)" in out
    assert f"findings triaged : {len(findings)}" in out


def test_cli_summary_counts_escalations(
    monkeypatch: pytest.MonkeyPatch,
    sample_findings: list[Finding],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Low-confidence decisions surface as escalations in the summary."""
    findings = sample_findings[:2]
    findings_file = tmp_path / "findings.json"
    _write_findings(findings_file, findings)

    # Sub-threshold confidence -> guardrail coerces every finding to escalate.
    monkeypatch.setattr(
        cli, "triage_finding", _stub_triage(Action.OPEN_TICKET, confidence=0.2)
    )

    exit_code = _run_cli(
        monkeypatch,
        [
            "--findings",
            str(findings_file),
            "--tickets-dir",
            str(tmp_path / "tickets"),
            "--tracker",
            str(tmp_path / "TRACKER.md"),
            "--pr-dir",
            str(tmp_path / "prs"),
        ],
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert f"escalations      : {len(findings)}" in out
    assert "tickets to write : 0" in out
    assert "needs_human" in out
