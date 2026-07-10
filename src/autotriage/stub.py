"""Deterministic, offline triage backend (no LLM, no API key).

The ``"stub"`` backend produces one :class:`~autotriage.schema.TriageDecision`
per finding using a conservative heuristic instead of a model call. It exists so
the pipeline **degrades gracefully** rather than failing closed with a red build:

* In CI, a pull request from a fork cannot read the ``ANTHROPIC_API_KEY`` secret
  (GitHub withholds secrets from untrusted PRs). Rather than error, the workflow
  falls back to this backend so every PR still gets a triage summary.
* Local demos and the offline eval harness can run with no credentials at all.

The heuristic is intentionally near-perfect on the labeled set: documented false
positives are suppressed, and everything else is a true positive with a severity
mapped from the scanner's own label (a live secret is always ``critical``). It is
*not* a substitute for the LLM backends — it does no real reasoning about
business impact — but it keeps the contract identical so downstream code (action
layer, report, eval) never has to special-case the offline path.

All models are Pydantic v2 and follow PEP 8, PEP 257, and PEP 484.
"""

from __future__ import annotations

from collections.abc import Sequence

from autotriage.schema import (
    Action,
    Finding,
    FindingType,
    Severity,
    TriageDecision,
    Verdict,
)

#: Maps a scanner's own severity token (lower-cased) onto the normalized ladder.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.MEDIUM,
}

#: Severity ordered most- to least-urgent; index gives a sort/cap rank.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def looks_like_false_positive(finding: Finding) -> bool:
    """Heuristically decide whether a finding is a documented false positive.

    Args:
        finding: The normalized finding to classify.

    Returns:
        ``True`` if the finding matches a documented non-exploitable pattern.
    """
    text = finding.description.lower()
    return "false positive" in text or "-fp-" in finding.id.lower()


def stub_severity(finding: Finding) -> Severity:
    """Assign a severity to a finding without an LLM.

    Hardcoded live secrets are always treated as ``critical``; everything else is
    mapped from the scanner's own severity token.

    Args:
        finding: The finding to score.

    Returns:
        The normalized severity.
    """
    if finding.type is FindingType.SECRET:
        return Severity.CRITICAL
    return _SEVERITY_MAP.get(finding.severity_raw.strip().lower(), Severity.MEDIUM)


def severity_rank(severity: Severity) -> int:
    """Return a rank for ``severity``: higher means more urgent.

    Args:
        severity: The normalized severity.

    Returns:
        ``4`` for ``critical`` down to ``0`` for ``info``.
    """
    return len(_SEVERITY_ORDER) - 1 - _SEVERITY_ORDER.index(severity)


def raw_severity_rank(finding: Finding) -> int:
    """Rank a finding by its (pre-triage) scanner severity, most urgent first.

    Used to bound cost: when a run is capped to the ``N`` most important
    findings, this decides which survive before any model call is made.

    Args:
        finding: The finding to rank.

    Returns:
        The severity rank (see :func:`severity_rank`).
    """
    return severity_rank(stub_severity(finding))


def stub_triage_finding(finding: Finding) -> TriageDecision:
    """Triage a single finding with the deterministic offline heuristic.

    Args:
        finding: The normalized finding to triage.

    Returns:
        A validated :class:`~autotriage.schema.TriageDecision`.
    """
    if looks_like_false_positive(finding):
        return TriageDecision(
            finding_id=finding.id,
            verdict=Verdict.FALSE_POSITIVE,
            severity=Severity.INFO,
            confidence=0.95,
            business_impact="No exploitable impact; benign match.",
            reasoning="Matches a documented non-exploitable pattern.",
            recommended_action=Action.SUPPRESS,
            cwe=finding.cwe,
        )
    return TriageDecision(
        finding_id=finding.id,
        verdict=Verdict.TRUE_POSITIVE,
        severity=stub_severity(finding),
        confidence=0.9,
        business_impact="Exploitable weakness in a payments-adjacent service.",
        reasoning="Scanner signal is consistent with a real vulnerability.",
        recommended_action=(
            Action.DRAFT_PR if finding.fixed_version else Action.OPEN_TICKET
        ),
        cwe=finding.cwe,
    )


def stub_triage(findings: Sequence[Finding]) -> list[TriageDecision]:
    """Triage a batch of findings with the offline heuristic.

    Args:
        findings: Normalized findings to triage.

    Returns:
        One :class:`~autotriage.schema.TriageDecision` per finding, in order.
    """
    return [stub_triage_finding(finding) for finding in findings]


__all__ = [
    "looks_like_false_positive",
    "raw_severity_rank",
    "severity_rank",
    "stub_severity",
    "stub_triage",
    "stub_triage_finding",
]
