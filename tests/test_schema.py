"""Tests for the shared contracts in :mod:`autotriage.schema`."""

from __future__ import annotations

from autotriage.schema import (
    Action,
    Finding,
    TriageDecision,
    Verdict,
)


def test_fixture_findings_validate(sample_findings: list[Finding]) -> None:
    """Every record in the sample fixture parses into a ``Finding``."""
    assert len(sample_findings) >= 10
    assert all(isinstance(f, Finding) for f in sample_findings)


def test_make_id_is_deterministic() -> None:
    """The same inputs always hash to the same 12-char id."""
    a = Finding.make_id("semgrep", "rule.x", "app.py", 42)
    b = Finding.make_id("semgrep", "rule.x", "app.py", 42)
    assert a == b
    assert len(a) == 12


def test_low_confidence_is_coerced_to_human_escalation() -> None:
    """The guardrail downgrades sub-threshold confidence to a human review."""
    decision = TriageDecision(
        finding_id="abc123",
        verdict=Verdict.TRUE_POSITIVE,
        severity="high",  # type: ignore[arg-type]
        confidence=0.2,
        business_impact="Potential data exposure.",
        reasoning="Model was unsure.",
        recommended_action=Action.OPEN_TICKET,
    )
    assert decision.verdict is Verdict.NEEDS_HUMAN
    assert decision.recommended_action is Action.ESCALATE
