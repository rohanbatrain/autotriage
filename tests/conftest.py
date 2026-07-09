"""Shared pytest fixtures for the AutoTriage test suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import pytest

from autotriage import agent
from autotriage.schema import (
    Action,
    Finding,
    Severity,
    TriageDecision,
    Verdict,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent / "fixtures" / "findings.sample.json"
)


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Load the canonical sample findings as validated ``Finding`` objects."""
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    return [Finding.model_validate(item) for item in data]


class CannedDecision(Protocol):
    """Callable that builds a deterministic :class:`TriageDecision`."""

    def __call__(  # noqa: PLR0913 - mirrors the model's many fields
        self,
        finding: Finding,
        *,
        verdict: Verdict = ...,
        severity: Severity = ...,
        confidence: float = ...,
        action: Action = ...,
        owner: str | None = ...,
        business_impact: str = ...,
        reasoning: str = ...,
        remediation: str = ...,
    ) -> TriageDecision:
        """Build a triage decision for ``finding`` with the given overrides."""
        ...


@pytest.fixture
def canned_decision() -> CannedDecision:
    """Return a factory that builds deterministic triage decisions.

    The factory produces a fully populated :class:`TriageDecision` for a given
    finding, letting each test pin exactly the verdict/action/confidence it
    needs without repeating the whole payload.
    """

    def _make(  # noqa: PLR0913 - mirrors the model's many fields
        finding: Finding,
        *,
        verdict: Verdict = Verdict.TRUE_POSITIVE,
        severity: Severity = Severity.HIGH,
        confidence: float = 0.9,
        action: Action = Action.OPEN_TICKET,
        owner: str | None = None,
        business_impact: str = "Attacker could read customer payment records.",
        reasoning: str = "User-controlled input reaches a sensitive sink.",
        remediation: str = "Use a parameterized query.",
    ) -> TriageDecision:
        return TriageDecision(
            finding_id=finding.id,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            business_impact=business_impact,
            reasoning=reasoning,
            recommended_action=action,
            suggested_owner=owner,
            remediation=remediation,
            cwe=list(finding.cwe),
        )

    return _make


class FakeBackend(Protocol):
    """Callable that installs a deterministic ``triage_finding`` replacement."""

    def __call__(
        self, decider: Callable[[Finding], TriageDecision]
    ) -> Callable[[Finding], TriageDecision]:
        """Install ``decider`` as the ``triage_finding`` replacement."""
        ...


@pytest.fixture
def fake_backend(monkeypatch: pytest.MonkeyPatch) -> FakeBackend:
    """Monkeypatch ``agent.triage_finding`` to drive ``triage_all`` offline.

    Tests pass a ``decider`` mapping each :class:`Finding` to a
    :class:`TriageDecision`; the installed stub ignores ``backend``/``model`` so
    the whole batch runs deterministically with no network or API key.
    """

    def _install(
        decider: Callable[[Finding], TriageDecision],
    ) -> Callable[[Finding], TriageDecision]:
        def _fake_triage_finding(
            finding: Finding, *, backend: str = "api", model: str | None = None
        ) -> TriageDecision:
            return decider(finding)

        monkeypatch.setattr(agent, "triage_finding", _fake_triage_finding)
        return _fake_triage_finding

    return _install
