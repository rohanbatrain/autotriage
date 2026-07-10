"""Unit tests for the Markdown triage report renderer."""

from __future__ import annotations

from autotriage.report import COMMENT_MARKER, render_markdown_report
from autotriage.schema import (
    Action,
    Finding,
    FindingType,
    ScannerTool,
    Severity,
    TriageDecision,
    Verdict,
)


def _finding(
    fid: str, *, title: str = "SQL injection", file: str = "svc/app.py"
) -> Finding:
    return Finding(
        id=fid,
        tool=ScannerTool.SEMGREP,
        type=FindingType.SAST,
        rule_id="rule",
        title=title,
        severity_raw="HIGH",
        file=file,
        line=42,
    )


def _decision(  # noqa: PLR0913 - mirrors the decision model's fields
    fid: str,
    *,
    verdict: Verdict = Verdict.TRUE_POSITIVE,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    action: Action = Action.OPEN_TICKET,
    owner: str | None = "@payments",
) -> TriageDecision:
    return TriageDecision(
        finding_id=fid,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        business_impact="impact",
        reasoning="reasoning",
        recommended_action=action,
        suggested_owner=owner,
    )


def test_report_has_marker_headline_and_a_row_per_finding() -> None:
    findings = [_finding("a"), _finding("b", title="Weak hash")]
    decisions = [_decision("a"), _decision("b")]
    md = render_markdown_report(findings, decisions, backend="api", dry_run=True)

    assert md.startswith(COMMENT_MARKER)
    assert "Triaged **2** finding(s)" in md
    assert "| Severity | Finding |" in md  # table header present
    assert "SQL injection" in md
    assert "Weak hash" in md
    assert "`svc/app.py:42`" in md


def test_report_counts_tickets_prs_escalations_and_suppressions() -> None:
    findings = [_finding(x) for x in ("t", "p", "e", "s")]
    decisions = [
        _decision("t", action=Action.OPEN_TICKET),
        _decision("p", action=Action.DRAFT_PR),
        # Low confidence trips the guardrail -> escalate.
        _decision("e", confidence=0.2),
        _decision("s", verdict=Verdict.FALSE_POSITIVE, action=Action.SUPPRESS),
    ]
    md = render_markdown_report(findings, decisions, backend="api", dry_run=False)

    assert "**1** ticket(s)" in md
    assert "**1** fix PR(s)" in md
    assert "**1** escalation(s)" in md
    assert "**1** suppressed" in md
    assert "escalated to a human" in md


def test_report_notes_when_run_was_capped() -> None:
    findings = [_finding("a")]
    decisions = [_decision("a")]
    md = render_markdown_report(
        findings, decisions, backend="stub", dry_run=True, capped_from=50
    )
    assert "Capped to the 1 most severe of 50" in md


def test_report_labels_each_backend() -> None:
    f, d = [_finding("a")], [_decision("a")]
    assert "Messages API" in render_markdown_report(f, d, backend="api", dry_run=True)
    assert "Agent SDK" in render_markdown_report(f, d, backend="sdk", dry_run=True)
    assert "no LLM" in render_markdown_report(f, d, backend="stub", dry_run=True)


def test_report_escapes_pipes_in_titles() -> None:
    findings = [_finding("a", title="a | b pipe")]
    decisions = [_decision("a")]
    md = render_markdown_report(findings, decisions, backend="api", dry_run=True)
    assert "a \\| b pipe" in md


def test_report_orders_rows_by_severity() -> None:
    findings = [_finding("low"), _finding("crit")]
    decisions = [
        _decision("low", severity=Severity.LOW),
        _decision("crit", severity=Severity.CRITICAL),
    ]
    md = render_markdown_report(findings, decisions, backend="api", dry_run=True)
    # The critical row must appear before the low row regardless of input order.
    assert md.index("🟥 critical") < md.index("🟦 low")
