"""Unit tests for the offline ``stub`` triage backend.

The stub is the graceful-degradation path (no API key), so its contract must
stay stable: false positives are suppressed, everything else is a true positive
with a scanner-derived severity, and secrets are always critical.
"""

from __future__ import annotations

from autotriage.schema import (
    Action,
    Finding,
    FindingType,
    ScannerTool,
    Severity,
    Verdict,
)
from autotriage.stub import (
    looks_ambiguous,
    looks_like_false_positive,
    raw_severity_rank,
    severity_rank,
    stub_severity,
    stub_triage,
    stub_triage_finding,
)


def _finding(
    *,
    fid: str = "sast-x-001",
    ftype: FindingType = FindingType.SAST,
    severity_raw: str = "HIGH",
    description: str = "",
    fixed_version: str | None = None,
) -> Finding:
    """Build a minimal finding for the stub to triage."""
    return Finding(
        id=fid,
        tool=ScannerTool.SEMGREP,
        type=ftype,
        rule_id="rule",
        title="a finding",
        severity_raw=severity_raw,
        file="svc/app.py",
        line=10,
        description=description,
        fixed_version=fixed_version,
    )


def test_false_positive_detected_by_description_and_id() -> None:
    assert looks_like_false_positive(_finding(description="This is a false positive."))
    assert looks_like_false_positive(_finding(fid="sast-fp-009"))
    assert not looks_like_false_positive(_finding(description="real bug"))


def test_stub_severity_secret_is_always_critical() -> None:
    secret = _finding(ftype=FindingType.SECRET, severity_raw="low")
    assert stub_severity(secret) is Severity.CRITICAL


def test_stub_severity_maps_raw_token_and_defaults_to_medium() -> None:
    assert stub_severity(_finding(severity_raw="ERROR")) is Severity.HIGH
    assert stub_severity(_finding(severity_raw="wat")) is Severity.MEDIUM


def test_severity_rank_orders_critical_above_info() -> None:
    assert severity_rank(Severity.CRITICAL) == 4
    assert severity_rank(Severity.INFO) == 0
    assert severity_rank(Severity.CRITICAL) > severity_rank(Severity.LOW)


def test_raw_severity_rank_uses_scanner_severity_before_triage() -> None:
    assert raw_severity_rank(_finding(ftype=FindingType.SECRET)) == 4
    assert raw_severity_rank(_finding(severity_raw="low")) == 1


def test_true_positive_with_fixed_version_drafts_pr() -> None:
    decision = stub_triage_finding(_finding(fixed_version="2.0.0"))
    assert decision.verdict is Verdict.TRUE_POSITIVE
    assert decision.recommended_action is Action.DRAFT_PR
    assert decision.confidence >= 0.6  # never trips the escalation guardrail


def test_true_positive_without_fix_opens_ticket() -> None:
    decision = stub_triage_finding(_finding())
    assert decision.recommended_action is Action.OPEN_TICKET


def test_false_positive_is_suppressed() -> None:
    decision = stub_triage_finding(_finding(description="benign false positive"))
    assert decision.verdict is Verdict.FALSE_POSITIVE
    assert decision.recommended_action is Action.SUPPRESS
    assert decision.severity is Severity.INFO


def test_looks_ambiguous_detects_marker_and_id() -> None:
    assert looks_ambiguous(_finding(description="AMBIGUOUS: reachability unclear"))
    assert looks_ambiguous(_finding(fid="sast-cmdexec-amb-016"))
    assert not looks_ambiguous(_finding(description="a clear bug"))


def test_ambiguous_finding_is_escalated_via_guardrail() -> None:
    decision = stub_triage_finding(
        _finding(fid="sast-x-amb-016", description="AMBIGUOUS: needs more context")
    )
    assert decision.verdict is Verdict.NEEDS_HUMAN
    assert decision.recommended_action is Action.ESCALATE
    assert decision.confidence < 0.6  # deliberately trips the escalation guardrail


def test_stub_triage_returns_one_decision_per_finding() -> None:
    findings = [_finding(fid=f"f-{i}") for i in range(4)]
    decisions = stub_triage(findings)
    assert [d.finding_id for d in decisions] == [f.id for f in findings]
