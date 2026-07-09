"""Property-based invariants for the shared schema contracts.

These tests assert behaviors that must hold for *all* valid inputs rather than a
few hand-picked examples: id determinism, the confidence guardrail, and
serialization round-trip stability.
"""

from __future__ import annotations

import hypothesis.strategies as st
import pytest
from hypothesis import given

from autotriage.schema import (
    GUARDRAIL_CONFIDENCE_THRESHOLD,
    Action,
    Finding,
    FindingType,
    ScannerTool,
    Severity,
    TriageDecision,
    Verdict,
)

pytestmark = pytest.mark.property

# Text that is safe inside a Finding/TriageDecision (no surrogate weirdness).
_text = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=0x7E), max_size=40
)
_ids = st.text(alphabet="abcdef0123456789", min_size=1, max_size=16)
_lines = st.integers(min_value=0, max_value=1_000_000)


@given(tool=_text, rule_id=_text, file=_text, line=_lines)
def test_make_id_is_deterministic_and_12_chars(
    tool: str, rule_id: str, file: str, line: int
) -> None:
    """``make_id`` is a pure 12-char function of its inputs."""
    first = Finding.make_id(tool, rule_id, file, line)
    second = Finding.make_id(tool, rule_id, file, line)
    assert first == second
    assert len(first) == 12
    assert all(c in "0123456789abcdef" for c in first)


@st.composite
def _findings(draw: st.DrawFn) -> Finding:
    """Draw an arbitrary valid ``Finding``."""
    tool = draw(st.sampled_from(list(ScannerTool)))
    rule_id = draw(_text.filter(bool))
    file = draw(_text.filter(bool))
    line = draw(_lines)
    return Finding(
        id=Finding.make_id(tool.value, rule_id, file, line),
        tool=tool,
        type=draw(st.sampled_from(list(FindingType))),
        rule_id=rule_id,
        title=draw(_text),
        severity_raw=draw(_text),
        cwe=draw(st.lists(st.from_regex(r"CWE-\d{1,4}", fullmatch=True), max_size=3)),
        file=file,
        line=line,
        code_snippet=draw(_text),
        description=draw(_text),
        package=draw(st.none() | _text),
    )


@st.composite
def _decisions(draw: st.DrawFn, *, confidence: st.SearchStrategy[float]) -> dict:
    """Draw a raw decision payload with a caller-chosen confidence strategy."""
    return {
        "finding_id": draw(_ids),
        "verdict": draw(st.sampled_from(list(Verdict))).value,
        "severity": draw(st.sampled_from(list(Severity))).value,
        "confidence": draw(confidence),
        "business_impact": draw(_text),
        "reasoning": draw(_text),
        "recommended_action": draw(st.sampled_from(list(Action))).value,
        "suggested_owner": draw(st.none() | _text),
        "remediation": draw(_text),
    }


@given(
    payload=_decisions(
        confidence=st.floats(
            min_value=0.0,
            max_value=GUARDRAIL_CONFIDENCE_THRESHOLD,
            exclude_max=True,
        )
    )
)
def test_low_confidence_always_escalates(payload: dict) -> None:
    """Any sub-threshold confidence is coerced to needs_human / escalate."""
    decision = TriageDecision.model_validate(payload)
    assert decision.verdict is Verdict.NEEDS_HUMAN
    assert decision.recommended_action is Action.ESCALATE


@given(
    payload=_decisions(
        confidence=st.floats(min_value=GUARDRAIL_CONFIDENCE_THRESHOLD, max_value=1.0)
    )
)
def test_at_or_above_threshold_preserves_decision(payload: dict) -> None:
    """At/above the threshold the verdict and action are left untouched."""
    decision = TriageDecision.model_validate(payload)
    assert decision.verdict.value == payload["verdict"]
    assert decision.recommended_action.value == payload["recommended_action"]


@given(finding=_findings())
def test_finding_round_trip_is_stable(finding: Finding) -> None:
    """``model_dump`` -> ``model_validate`` is a fixed point for findings."""
    dumped = finding.model_dump(mode="json")
    assert Finding.model_validate(dumped) == finding
    # Idempotent across a second round trip.
    revalidated = Finding.model_validate(dumped).model_dump()
    assert Finding.model_validate(revalidated) == finding


@given(
    payload=_decisions(
        confidence=st.floats(min_value=GUARDRAIL_CONFIDENCE_THRESHOLD, max_value=1.0)
    )
)
def test_decision_round_trip_is_stable(payload: dict) -> None:
    """``model_dump`` -> ``model_validate`` is a fixed point for decisions."""
    decision = TriageDecision.model_validate(payload)
    assert TriageDecision.model_validate(decision.model_dump()) == decision
