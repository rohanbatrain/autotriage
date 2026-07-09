"""End-to-end pipeline tests: findings -> triage_all -> dispatch.

Every test here is offline. The LLM backends are replaced either at the
``triage_finding`` seam (via the ``fake_backend`` fixture) or at the third-party
client boundary (``anthropic.Anthropic`` / ``claude_agent_sdk.query``), so the
real parsing, finalization, and dispatch code paths run without a network call.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import anthropic
import claude_agent_sdk
import pytest
from pydantic import ValidationError

from autotriage import agent, tools
from autotriage.schema import (
    Action,
    Finding,
    FindingType,
    Severity,
    TriageDecision,
    Verdict,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

    from tests.conftest import CannedDecision, FakeBackend

pytestmark = pytest.mark.integration


def _decider_by_type(
    canned: CannedDecision,
) -> Callable[[Finding], TriageDecision]:
    """Map each finding class to a distinct action for full-flow coverage."""

    def _decide(finding: Finding) -> TriageDecision:
        if finding.type is FindingType.SAST:
            return canned(finding, action=Action.DRAFT_PR)
        if finding.type is FindingType.SCA:
            return canned(finding, action=Action.OPEN_TICKET, owner="@deps-team")
        if finding.type is FindingType.IAC:
            # Sub-threshold confidence: the guardrail coerces this to escalate.
            return canned(finding, action=Action.OPEN_TICKET, confidence=0.3)
        # SECRET -> benign example -> suppressed false positive.
        return canned(
            finding,
            verdict=Verdict.FALSE_POSITIVE,
            action=Action.SUPPRESS,
            confidence=0.95,
        )

    return _decide


def test_full_flow_writes_expected_artifacts(
    fake_backend: FakeBackend,
    canned_decision: CannedDecision,
    sample_findings: list[Finding],
    tmp_path: Path,
) -> None:
    """The full flow writes tickets, PRs, tracker rows, and suppresses FPs."""
    fake_backend(_decider_by_type(canned_decision))

    tickets_dir = tmp_path / "tickets"
    pr_dir = tmp_path / "pull_requests"
    tracker = tmp_path / "TRACKER.md"

    decisions = agent.triage_all(sample_findings, backend="api")
    assert [d.finding_id for d in decisions] == [f.id for f in sample_findings]

    for finding, decision in zip(sample_findings, decisions, strict=True):
        tools.dispatch(
            finding,
            decision,
            tickets_dir=tickets_dir,
            tracker_path=tracker,
            pr_dir=pr_dir,
        )

    sast = [f for f in sample_findings if f.type is FindingType.SAST]
    sca = [f for f in sample_findings if f.type is FindingType.SCA]
    iac = [f for f in sample_findings if f.type is FindingType.IAC]
    secrets = [f for f in sample_findings if f.type is FindingType.SECRET]

    # SAST -> draft_pr writes both a PR draft and a tracking ticket.
    for finding in sast:
        assert (pr_dir / f"{finding.id}.pr.md").is_file()
        assert (tickets_dir / f"{finding.id}.md").is_file()

    # SCA -> open_ticket writes a ticket but no PR.
    for finding in sca:
        assert (tickets_dir / f"{finding.id}.md").is_file()
        assert not (pr_dir / f"{finding.id}.pr.md").exists()

    # SECRET false positives are suppressed: no ticket, no PR.
    for finding in secrets:
        assert not (tickets_dir / f"{finding.id}.md").exists()
        assert not (pr_dir / f"{finding.id}.pr.md").exists()

    tracker_text = tracker.read_text(encoding="utf-8")
    # IAC findings were escalated to human review by the confidence guardrail.
    for finding in iac:
        assert not (tickets_dir / f"{finding.id}.md").exists()
        assert finding.id in tracker_text
    assert "escalate:human-review" in tracker_text
    assert "suppress" in tracker_text
    # Every finding is recorded in the append-only ledger exactly once.
    for finding in sample_findings:
        assert tracker_text.count(f"| {finding.id} |") == 1


# ---------------------------------------------------------------------------
# Real parsing path: anthropic Messages API (forced tool_use), no network.
# ---------------------------------------------------------------------------
def _fake_anthropic_module(
    monkeypatch: pytest.MonkeyPatch, blocks: list[object]
) -> dict[str, Any]:
    """Patch ``anthropic.Anthropic`` to return ``blocks`` and record the call."""
    captured: dict[str, Any] = {}

    class _FakeMessages:
        def create(self, **kwargs: object) -> SimpleNamespace:
            """Record the request kwargs and return the canned response."""
            captured.update(kwargs)
            return SimpleNamespace(content=blocks)

    class _FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.messages = _FakeMessages()

    monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)
    return captured


def test_api_backend_parses_forced_tool_use(
    monkeypatch: pytest.MonkeyPatch, sample_findings: list[Finding]
) -> None:
    """``_triage_via_api`` turns a forced tool_use block into a TriageDecision."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    finding = sample_findings[0]
    tool_block = SimpleNamespace(
        type="tool_use",
        name="submit_triage",
        input={
            "finding_id": "model-made-this-up",
            "verdict": "true_positive",
            "severity": "critical",
            "confidence": 0.91,
            "business_impact": "SQL injection on a payments endpoint.",
            # Model leaked tool markup; it must be stripped from free text.
            "reasoning": "Injection is reachable.</reasoning><parameter>junk",
            # recommended_action omitted on purpose -> derived from verdict.
            "remediation": "Parameterize the query.",
        },
    )
    captured = _fake_anthropic_module(
        monkeypatch, [SimpleNamespace(type="text"), tool_block]
    )

    decision = agent.triage_finding(finding, backend="api", model="claude-test")

    # finding_id is pinned to the real finding, not the model's echo.
    assert decision.finding_id == finding.id
    assert decision.verdict is Verdict.TRUE_POSITIVE
    assert decision.severity is Severity.CRITICAL
    # Missing recommended_action derived from the true_positive verdict.
    assert decision.recommended_action is Action.OPEN_TICKET
    # Leaked markup truncated at the first marker.
    assert decision.reasoning == "Injection is reachable."
    assert "<" not in decision.reasoning
    # The resolved model + rendered prompt were actually threaded through.
    assert captured["model"] == "claude-test"
    assert "code_snippet" in captured["messages"][0]["content"]


def test_api_backend_missing_tool_call_raises(
    monkeypatch: pytest.MonkeyPatch, sample_findings: list[Finding]
) -> None:
    """A response without the submit_triage tool call fails loudly."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    _fake_anthropic_module(monkeypatch, [SimpleNamespace(type="text")])

    with pytest.raises(RuntimeError, match="did not call"):
        agent.triage_finding(sample_findings[0], backend="api")


def test_triage_all_fails_closed_to_escalation(
    monkeypatch: pytest.MonkeyPatch,
    sample_findings: list[Finding],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A backend that raises escalates that finding without aborting the batch."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    calls = {"n": 0}

    def _flaky(finding: Finding, *, model: str) -> TriageDecision:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("model exploded")
        return TriageDecision(
            finding_id=finding.id,
            verdict=Verdict.TRUE_POSITIVE,
            severity=Severity.HIGH,
            confidence=0.9,
            business_impact="ok",
            reasoning="ok",
            recommended_action=Action.OPEN_TICKET,
        )

    monkeypatch.setattr(agent, "_triage_via_api", _flaky)

    subset = sample_findings[:3]
    decisions = agent.triage_all(subset, backend="api")

    assert len(decisions) == len(subset)  # batch not aborted
    escalated = decisions[1]
    assert escalated.verdict is Verdict.NEEDS_HUMAN
    assert escalated.recommended_action is Action.ESCALATE
    assert escalated.confidence == 0.0
    assert "escalating" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Real parsing path: Claude Agent SDK structured output, no network.
# ---------------------------------------------------------------------------
def test_sdk_backend_reads_structured_output(
    monkeypatch: pytest.MonkeyPatch, sample_findings: list[Finding]
) -> None:
    """``_triage_via_sdk`` reads ``structured_output`` off the SDK messages."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    finding = sample_findings[0]
    payload = {
        "finding_id": "ignored",
        "verdict": "false_positive",
        "severity": "low",
        "confidence": 0.88,
        "business_impact": "Test-only code path.",
        "reasoning": "Lives under tests/.",
        "recommended_action": "suppress",
    }

    async def _fake_query(
        *, prompt: str, options: object
    ) -> AsyncIterator[SimpleNamespace]:
        assert "finding_id" in prompt
        yield SimpleNamespace(structured_output=None)  # non-final message
        yield SimpleNamespace(structured_output=payload)

    monkeypatch.setattr(claude_agent_sdk, "query", _fake_query)

    decision = agent.triage_finding(finding, backend="sdk")

    assert decision.finding_id == finding.id
    assert decision.verdict is Verdict.FALSE_POSITIVE
    assert decision.recommended_action is Action.SUPPRESS


def test_sdk_backend_without_structured_output_raises(
    monkeypatch: pytest.MonkeyPatch, sample_findings: list[Finding]
) -> None:
    """The SDK backend raises when no structured output is ever produced."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    async def _fake_query(
        *, prompt: str, options: object
    ) -> AsyncIterator[SimpleNamespace]:
        yield SimpleNamespace(structured_output=None)

    monkeypatch.setattr(claude_agent_sdk, "query", _fake_query)

    with pytest.raises(RuntimeError, match="no structured output"):
        agent.triage_finding(sample_findings[0], backend="sdk")


def test_unknown_backend_raises(
    monkeypatch: pytest.MonkeyPatch, sample_findings: list[Finding]
) -> None:
    """An unsupported backend name is rejected."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    with pytest.raises(ValueError, match="Unknown backend"):
        agent.triage_finding(sample_findings[0], backend="carrier-pigeon")


# ---------------------------------------------------------------------------
# agent._finalize sanitization branches (exercised directly).
# ---------------------------------------------------------------------------
def test_finalize_derives_action_from_verdict(
    sample_findings: list[Finding],
) -> None:
    """A missing recommended_action is derived from a valid verdict."""
    decision = agent._finalize(
        {
            "verdict": "false_positive",
            "severity": "low",
            "confidence": 0.9,
            "business_impact": "Example code only.",
            "reasoning": "Under tests/.",
        },
        sample_findings[0],
    )
    # false_positive -> suppress via the _ACTION_BY_VERDICT fallback table.
    assert decision.recommended_action is Action.SUPPRESS


def test_finalize_bogus_verdict_defaults_to_escalate_then_rejects(
    sample_findings: list[Finding],
) -> None:
    """An unparseable verdict trips the escalate fallback, then fails validation."""
    with pytest.raises(ValidationError):
        agent._finalize(
            {
                "verdict": "totally-bogus",
                "severity": "medium",
                "confidence": 0.9,
                "business_impact": "x",
                "reasoning": "y",
            },
            sample_findings[0],
        )


def test_finalize_strips_leaked_markup_across_fields(
    sample_findings: list[Finding],
) -> None:
    """Leaked markup is truncated in every free-text field."""
    leak_marker = "<" + "function=leak>"
    decision = agent._finalize(
        {
            "verdict": "true_positive",
            "severity": "high",
            "confidence": 0.9,
            "business_impact": "Impacts payments " + leak_marker,
            "reasoning": "Clean reasoning " + leak_marker,
            "remediation": "Do the fix " + leak_marker,
            "recommended_action": "open_ticket",
        },
        sample_findings[0],
    )
    assert decision.business_impact == "Impacts payments"
    assert decision.reasoning == "Clean reasoning"
    assert decision.remediation == "Do the fix"
    assert "<" not in decision.reasoning
