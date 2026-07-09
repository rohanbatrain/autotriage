"""Offline tests for the triage agent's action layer and orchestration.

No network or LLM calls: the agent backend is monkeypatched to return canned
:class:`TriageDecision` objects, so these tests exercise dispatch routing,
CODEOWNERS parsing, the confidence guardrail, and the ``triage_all`` loop
entirely offline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from autotriage import agent, tools
from autotriage.schema import (
    Action,
    Finding,
    FindingType,
    ScannerTool,
    Severity,
    TriageDecision,
    Verdict,
)

_CODEOWNERS = """\
# Sample CODEOWNERS for tests
*                       @security-team
target/app.py           @app-team @alice
target/infra/           @infra-team
target/requirements.txt @deps-team
"""


def _make_finding(
    *,
    finding_id: str = "sast-sqli-001",
    file: str = "target/app.py",
    line: int = 44,
) -> Finding:
    """Build a minimal valid ``Finding`` for tests."""
    return Finding(
        id=finding_id,
        tool=ScannerTool.SEMGREP,
        type=FindingType.SAST,
        rule_id="python.lang.security.sql-injection",
        title="SQL injection via f-string",
        severity_raw="ERROR",
        cwe=["CWE-89"],
        file=file,
        line=line,
        code_snippet='cursor.execute(f"... {user}")',
        description="User input flows into a SQL query.",
    )


def _make_decision(
    finding: Finding,
    *,
    action: Action = Action.OPEN_TICKET,
    confidence: float = 0.9,
    owner: str | None = "@app-team",
) -> TriageDecision:
    """Build a canned ``TriageDecision`` for a finding."""
    return TriageDecision(
        finding_id=finding.id,
        verdict=Verdict.TRUE_POSITIVE,
        severity=Severity.HIGH,
        confidence=confidence,
        business_impact="Attacker could read customer payment records.",
        reasoning="User-controlled input is interpolated into SQL.",
        recommended_action=action,
        suggested_owner=owner,
        remediation="Use a parameterized query.",
        cwe=["CWE-89"],
    )


# ---------------------------------------------------------------------------
# (a) dispatch routing writes tickets and appends the tracker
# ---------------------------------------------------------------------------
def test_dispatch_open_ticket_writes_ticket_and_tracker(tmp_path: Path) -> None:
    finding = _make_finding()
    decision = _make_decision(finding, action=Action.OPEN_TICKET)
    tickets_dir = tmp_path / "tickets"
    tracker = tmp_path / "TRACKER.md"
    pr_dir = tmp_path / "pull_requests"

    summary = tools.dispatch(
        finding,
        decision,
        tickets_dir=tickets_dir,
        tracker_path=tracker,
        pr_dir=pr_dir,
    )

    ticket = tickets_dir / f"{finding.id}.md"
    assert ticket.is_file()
    assert "SQL injection" in ticket.read_text(encoding="utf-8")
    assert "ticket" in summary

    tracker_text = tracker.read_text(encoding="utf-8")
    assert "# AutoTriage Tracker" in tracker_text
    assert finding.id in tracker_text
    assert "open_ticket" in tracker_text


def test_dispatch_draft_pr_writes_pr_and_ticket(tmp_path: Path) -> None:
    finding = _make_finding()
    decision = _make_decision(finding, action=Action.DRAFT_PR)
    tickets_dir = tmp_path / "tickets"
    pr_dir = tmp_path / "pull_requests"
    tracker = tmp_path / "TRACKER.md"

    summary = tools.dispatch(
        finding,
        decision,
        tickets_dir=tickets_dir,
        tracker_path=tracker,
        pr_dir=pr_dir,
    )

    assert (pr_dir / f"{finding.id}.pr.md").is_file()
    assert (tickets_dir / f"{finding.id}.md").is_file()
    assert "PR" in summary


def test_dispatch_suppress_is_log_only(tmp_path: Path) -> None:
    finding = _make_finding()
    decision = _make_decision(finding, action=Action.SUPPRESS)
    tickets_dir = tmp_path / "tickets"
    tracker = tmp_path / "TRACKER.md"

    tools.dispatch(
        finding,
        decision,
        tickets_dir=tickets_dir,
        tracker_path=tracker,
        pr_dir=tmp_path / "pr",
    )

    assert not (tickets_dir / f"{finding.id}.md").exists()
    assert "suppress" in tracker.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# (b) assign_owner parses CODEOWNERS correctly
# ---------------------------------------------------------------------------
def test_assign_owner_matches_codeowners(tmp_path: Path) -> None:
    codeowners = tmp_path / "CODEOWNERS"
    codeowners.write_text(_CODEOWNERS, encoding="utf-8")

    app = _make_finding(file="target/app.py")
    infra = _make_finding(finding_id="iac-1", file="target/infra/main.tf")
    reqs = _make_finding(finding_id="sca-1", file="target/requirements.txt")
    other = _make_finding(finding_id="misc-1", file="README.md")

    assert tools.assign_owner(app, codeowners) == "@app-team @alice"
    assert tools.assign_owner(infra, codeowners) == "@infra-team"
    assert tools.assign_owner(reqs, codeowners) == "@deps-team"
    # Falls back to the catch-all last-match rule.
    assert tools.assign_owner(other, codeowners) == "@security-team"


def test_assign_owner_missing_file_returns_none(tmp_path: Path) -> None:
    finding = _make_finding()
    assert tools.assign_owner(finding, tmp_path / "nope") is None


# ---------------------------------------------------------------------------
# (c) low-confidence decisions are escalated by the guardrail
# ---------------------------------------------------------------------------
def test_low_confidence_decision_is_escalated(tmp_path: Path) -> None:
    finding = _make_finding()
    # Guardrail coerces sub-threshold confidence to NEEDS_HUMAN / ESCALATE even
    # though we requested OPEN_TICKET.
    decision = _make_decision(finding, action=Action.OPEN_TICKET, confidence=0.2)
    assert decision.verdict is Verdict.NEEDS_HUMAN
    assert decision.recommended_action is Action.ESCALATE

    tracker = tmp_path / "TRACKER.md"
    summary = tools.dispatch(
        finding,
        decision,
        tickets_dir=tmp_path / "tickets",
        tracker_path=tracker,
        pr_dir=tmp_path / "pr",
    )

    assert "escalated" in summary
    assert not (tmp_path / "tickets" / f"{finding.id}.md").exists()
    assert "escalate:human-review" in tracker.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# (d) end-to-end triage_all with a stubbed backend
# ---------------------------------------------------------------------------
def test_triage_all_with_stubbed_backend(
    monkeypatch: pytest.MonkeyPatch, sample_findings: list[Finding]
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    def _fake_backend(finding: Finding, *, model: str) -> TriageDecision:
        assert model  # the resolved model id is threaded through
        return _make_decision(finding, action=Action.OPEN_TICKET)

    monkeypatch.setattr(agent, "_triage_via_api", _fake_backend)

    subset = sample_findings[:3]
    decisions = agent.triage_all(subset, backend="api")

    assert len(decisions) == len(subset)
    assert [d.finding_id for d in decisions] == [f.id for f in subset]
    assert all(d.verdict is Verdict.TRUE_POSITIVE for d in decisions)


def test_triage_finding_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        agent.triage_finding(_make_finding())
