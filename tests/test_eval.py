"""Offline tests for the evaluation harness.

These tests build :class:`~autotriage.schema.TriageDecision` lists by hand and
assert the exact metrics the scorer must produce. They never touch the network
and never import :mod:`autotriage.agent`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from autotriage.eval_harness import (
    GroundTruth,
    load_ground_truth,
    render_report,
    score,
)
from autotriage.schema import (
    Action,
    Severity,
    TriageDecision,
    Verdict,
)

_LABELS_PATH = (
    Path(__file__).resolve().parent.parent / "evals" / "labeled_findings.json"
)

# (finding_id, expected_verdict, expected_severity) — mirrors the ground truth.
_LABELS: list[tuple[str, Verdict, Severity]] = [
    ("sast-sqli-001", Verdict.TRUE_POSITIVE, Severity.HIGH),
    ("secret-awskey-002", Verdict.TRUE_POSITIVE, Severity.CRITICAL),
    ("sast-cmdinj-003", Verdict.TRUE_POSITIVE, Severity.HIGH),
    ("sast-eval-004", Verdict.TRUE_POSITIVE, Severity.HIGH),
    ("sast-md5-005", Verdict.TRUE_POSITIVE, Severity.MEDIUM),
    ("sast-pickle-006", Verdict.TRUE_POSITIVE, Severity.HIGH),
    ("sast-flaskdebug-007", Verdict.TRUE_POSITIVE, Severity.MEDIUM),
    ("sca-requests-008", Verdict.TRUE_POSITIVE, Severity.HIGH),
    ("sca-pyyaml-009", Verdict.TRUE_POSITIVE, Severity.CRITICAL),
    ("sca-flask-010", Verdict.TRUE_POSITIVE, Severity.MEDIUM),
    ("iac-s3public-011", Verdict.TRUE_POSITIVE, Severity.HIGH),
    ("iac-sgopen-012", Verdict.TRUE_POSITIVE, Severity.HIGH),
    ("iac-s3noenc-013", Verdict.TRUE_POSITIVE, Severity.LOW),
    ("sast-sqli-fp-014", Verdict.FALSE_POSITIVE, Severity.INFO),
    ("secret-fp-015", Verdict.FALSE_POSITIVE, Severity.INFO),
    ("sast-cmdexec-amb-016", Verdict.NEEDS_HUMAN, Severity.MEDIUM),
    ("secret-amb-017", Verdict.NEEDS_HUMAN, Severity.MEDIUM),
]


def _make_decision(
    finding_id: str,
    verdict: Verdict,
    severity: Severity,
) -> TriageDecision:
    """Build a valid, above-guardrail decision for a single finding."""
    return TriageDecision(
        finding_id=finding_id,
        verdict=verdict,
        severity=severity,
        confidence=0.9,
        business_impact="Test impact.",
        reasoning="Test reasoning.",
        recommended_action=Action.OPEN_TICKET,
    )


def _truth() -> dict[str, GroundTruth]:
    """Return the ground truth built directly from ``_LABELS``."""
    return {
        fid: GroundTruth(
            finding_id=fid,
            expected_verdict=verdict,
            expected_severity=severity,
        )
        for fid, verdict, severity in _LABELS
    }


def _perfect_decisions() -> list[TriageDecision]:
    """Return a decision set that matches every label exactly."""
    return [_make_decision(fid, v, s) for fid, v, s in _LABELS]


def test_perfect_set_scores_all_ones() -> None:
    report = score(_perfect_decisions(), _truth())

    assert report.total == 17
    assert report.true_positives == 13
    assert report.false_positives == 0
    assert report.false_negatives == 0
    # The two needs_human ground-truth rows are correctly escalated, not scored
    # as TP/FP — they count as (correct) abstentions.
    assert report.abstentions == 2
    assert report.precision == pytest.approx(1.0)
    assert report.recall == pytest.approx(1.0)
    assert report.f1 == pytest.approx(1.0)
    assert report.accuracy == pytest.approx(1.0)
    assert report.severity_agreement == pytest.approx(1.0)
    assert all(row.passed for row in report.results)


def test_imperfect_set_metrics() -> None:
    # One wrong verdict (a false alarm on a real false positive) and one wrong
    # severity (verdict still correct).
    decisions: list[TriageDecision] = []
    for fid, verdict, severity in _LABELS:
        pred_verdict = verdict
        pred_severity = severity
        if fid == "secret-fp-015":
            pred_verdict = Verdict.TRUE_POSITIVE  # wrong verdict: FP called TP
        if fid == "sca-flask-010":
            pred_severity = Severity.HIGH  # wrong severity: expected medium
        decisions.append(_make_decision(fid, pred_verdict, pred_severity))

    report = score(decisions, _truth())

    # Classifier tallies: all 13 real TPs caught, plus one false alarm. The two
    # needs_human rows are correctly escalated (abstentions), not misclassified.
    assert report.true_positives == 13
    assert report.false_positives == 1
    assert report.false_negatives == 0
    assert report.abstentions == 2

    assert report.precision == pytest.approx(13 / 14)
    assert report.recall == pytest.approx(1.0)
    assert report.f1 == pytest.approx(2 * 13 / (2 * 13 + 1))
    assert report.accuracy == pytest.approx(16 / 17)
    assert report.severity_agreement == pytest.approx(12 / 13)

    passed = {row.finding_id for row in report.results if row.passed}
    assert "secret-fp-015" not in passed  # wrong verdict
    assert "sca-flask-010" not in passed  # wrong severity
    assert len(passed) == 15


def test_needs_human_counts_as_abstain_recall_miss() -> None:
    # Abstaining on a real true positive must cost recall but not precision.
    decisions = _perfect_decisions()
    decisions[0] = _make_decision(_LABELS[0][0], Verdict.NEEDS_HUMAN, Severity.HIGH)

    report = score(decisions, _truth())

    # One forced abstain on a real TP, plus the two genuine needs_human rows.
    assert report.abstentions == 3
    assert report.true_positives == 12
    assert report.false_positives == 0
    assert report.false_negatives == 1
    assert report.precision == pytest.approx(1.0)  # abstain excluded
    assert report.recall == pytest.approx(12 / 13)


def test_load_ground_truth() -> None:
    truth = load_ground_truth(_LABELS_PATH)

    assert len(truth) == 17
    assert truth["sca-pyyaml-009"].expected_verdict is Verdict.TRUE_POSITIVE
    assert truth["sca-pyyaml-009"].expected_severity is Severity.CRITICAL
    assert truth["secret-fp-015"].expected_verdict is Verdict.FALSE_POSITIVE
    assert truth["secret-fp-015"].expected_severity is Severity.INFO
    assert truth["secret-amb-017"].expected_verdict is Verdict.NEEDS_HUMAN


def test_render_report_contains_sections() -> None:
    report = score(_perfect_decisions(), _truth())
    markdown = render_report(report)

    assert "# AutoTriage Evaluation Report" in markdown
    assert "## Metrics" in markdown
    assert "## Verdict Confusion Matrix" in markdown
    assert "## Per-finding Results" in markdown
    assert "sast-sqli-001" in markdown
