"""Evaluation harness that scores triage quality against ground truth.

The harness compares a batch of :class:`~autotriage.schema.TriageDecision`
objects produced by the agent against a hand-labeled set of
:class:`GroundTruth` records and computes the metrics a reviewer cares about:

* verdict **precision / recall / F1** for detecting a ``true_positive``,
* overall verdict **accuracy**, and
* **severity-agreement** rate on the findings that are genuinely true
  positives.

``needs_human`` convention
--------------------------
A ``needs_human`` verdict (and, equivalently, a finding for which the agent
produced no decision at all) is treated as an **abstention** rather than a
prediction. Concretely:

* It is never counted as a ``true_positive`` prediction, so it stays out of
  precision's denominator (it can neither help nor hurt precision).
* If the ground truth for that finding is ``true_positive``, the abstention is
  counted as a **recall miss** (a false negative) — the agent failed to catch a
  real issue.

This mirrors how a security team reasons about escalations: punting to a human
is safe (it costs no precision) but still means the automation did not resolve a
real vulnerability on its own.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from pydantic import BaseModel, Field

from autotriage.schema import Severity, TriageDecision, Verdict

#: Verdicts, in a stable order, used as the columns of the confusion matrix.
_VERDICT_ORDER: tuple[Verdict, ...] = (
    Verdict.TRUE_POSITIVE,
    Verdict.FALSE_POSITIVE,
    Verdict.NEEDS_HUMAN,
)


class GroundTruth(BaseModel):
    """A single hand-labeled expectation for one finding.

    Attributes:
        finding_id: Stable id of the finding this label applies to.
        expected_verdict: The verdict a correct triage should reach.
        expected_severity: The severity a correct triage should assign.
    """

    finding_id: str
    expected_verdict: Verdict
    expected_severity: Severity


class FindingResult(BaseModel):
    """The per-finding outcome of comparing a decision to its ground truth.

    Attributes:
        finding_id: Stable id of the finding.
        expected_verdict: The labeled verdict.
        predicted_verdict: The agent's verdict, or ``None`` if it abstained by
            producing no decision for this finding.
        expected_severity: The labeled severity.
        predicted_severity: The agent's severity, or ``None`` if no decision was
            produced.
        verdict_ok: Whether the predicted verdict matches the label.
        severity_ok: Whether the predicted severity matches the label.
        passed: Whether the finding is considered correctly triaged overall.
            Severity is only required to match for findings whose ground-truth
            verdict is ``true_positive`` (a false positive's severity is moot).
    """

    finding_id: str
    expected_verdict: Verdict
    predicted_verdict: Verdict | None
    expected_severity: Severity
    predicted_severity: Severity | None
    verdict_ok: bool
    severity_ok: bool
    passed: bool


class EvalReport(BaseModel):
    """Aggregated scoring of a triage run against the labeled set.

    Attributes:
        total: Number of ground-truth findings scored.
        true_positives: Correct ``true_positive`` predictions (classifier TP).
        false_positives: ``true_positive`` predictions on non-TP findings
            (classifier FP / false alarms).
        false_negatives: Genuine true positives the agent missed, whether by
            calling them false positives or by abstaining (classifier FN).
        abstentions: Predictions treated as abstain (``needs_human`` or absent).
        precision: ``true_positive`` precision, ``TP / (TP + FP)``.
        recall: ``true_positive`` recall, ``TP / (TP + FN)``.
        f1: Harmonic mean of precision and recall.
        accuracy: Fraction of findings whose verdict exactly matches the label.
        severity_agreement: Exact-match severity rate over findings whose
            ground-truth verdict is ``true_positive``.
        confusion: Verdict confusion matrix keyed as
            ``confusion[expected][predicted] -> count``.
        results: Per-finding pass/fail breakdown.
    """

    total: int
    true_positives: int
    false_positives: int
    false_negatives: int
    abstentions: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    severity_agreement: float
    confusion: dict[str, dict[str, int]] = Field(default_factory=dict)
    results: list[FindingResult] = Field(default_factory=list)


def load_ground_truth(path: Path) -> dict[str, GroundTruth]:
    """Load the labeled findings file into a lookup keyed by finding id.

    Args:
        path: Path to the JSON array of ground-truth records.

    Returns:
        A mapping from ``finding_id`` to its :class:`GroundTruth`.

    Raises:
        ValueError: If two records share the same ``finding_id``.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    truth: dict[str, GroundTruth] = {}
    for item in raw:
        record = GroundTruth.model_validate(item)
        if record.finding_id in truth:
            msg = f"duplicate ground-truth finding_id: {record.finding_id}"
            raise ValueError(msg)
        truth[record.finding_id] = record
    return truth


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Return ``numerator / denominator``, or ``0.0`` when undefined."""
    return numerator / denominator if denominator else 0.0


def _empty_confusion() -> dict[str, dict[str, int]]:
    """Return a zero-filled ``expected -> predicted -> count`` matrix."""
    return {
        expected.value: {predicted.value: 0 for predicted in _VERDICT_ORDER}
        for expected in _VERDICT_ORDER
    }


def score(
    decisions: Sequence[TriageDecision],
    truth: Mapping[str, GroundTruth],
) -> EvalReport:
    """Score triage decisions against ground truth.

    Scoring iterates over the ground-truth findings; a missing decision is
    treated as an abstention. See the module docstring for how ``needs_human``
    abstentions affect precision and recall.

    Args:
        decisions: The agent's triage decisions. Decisions whose ``finding_id``
            is not present in ``truth`` are ignored.
        truth: Ground-truth labels keyed by finding id.

    Returns:
        An :class:`EvalReport` with the aggregate metrics and per-finding rows.
    """
    by_id = {decision.finding_id: decision for decision in decisions}

    tp = fp = fn = abstentions = 0
    verdict_correct = 0
    severity_matches = 0
    positive_total = 0
    confusion = _empty_confusion()
    results: list[FindingResult] = []

    for finding_id, gt in truth.items():
        decision = by_id.get(finding_id)
        predicted_verdict = decision.verdict if decision is not None else None
        predicted_severity = decision.severity if decision is not None else None
        is_positive = gt.expected_verdict is Verdict.TRUE_POSITIVE

        # Confusion matrix: an absent decision is bucketed with needs_human.
        confusion_col = predicted_verdict or Verdict.NEEDS_HUMAN
        confusion[gt.expected_verdict.value][confusion_col.value] += 1

        # Precision / recall accounting with the abstain convention.
        if predicted_verdict is Verdict.TRUE_POSITIVE:
            if is_positive:
                tp += 1
            else:
                fp += 1
        elif predicted_verdict is Verdict.FALSE_POSITIVE:
            if is_positive:
                fn += 1
        else:  # needs_human or no decision -> abstain
            abstentions += 1
            if is_positive:
                fn += 1

        verdict_ok = predicted_verdict is gt.expected_verdict
        if verdict_ok:
            verdict_correct += 1

        severity_ok = predicted_severity is gt.expected_severity
        if is_positive:
            positive_total += 1
            if severity_ok:
                severity_matches += 1

        passed = verdict_ok and (not is_positive or severity_ok)
        results.append(
            FindingResult(
                finding_id=finding_id,
                expected_verdict=gt.expected_verdict,
                predicted_verdict=predicted_verdict,
                expected_severity=gt.expected_severity,
                predicted_severity=predicted_severity,
                verdict_ok=verdict_ok,
                severity_ok=severity_ok,
                passed=passed,
            )
        )

    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return EvalReport(
        total=len(truth),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        abstentions=abstentions,
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=_safe_ratio(verdict_correct, len(truth)),
        severity_agreement=_safe_ratio(severity_matches, positive_total),
        confusion=confusion,
        results=results,
    )


def _fmt_pct(value: float) -> str:
    """Format a 0..1 ratio as a percentage with one decimal place."""
    return f"{value * 100:.1f}%"


def render_report(report: EvalReport) -> str:
    """Render an :class:`EvalReport` as a Markdown document.

    The document contains a metrics table, the verdict confusion matrix, and a
    per-finding pass/fail table.

    Args:
        report: The scored report to render.

    Returns:
        A Markdown string ready to be written to ``report.md``.
    """
    passed = sum(1 for row in report.results if row.passed)
    lines: list[str] = ["# AutoTriage Evaluation Report", ""]

    lines += [
        f"Scored **{report.total}** findings — "
        f"**{passed}/{report.total}** fully correct.",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Verdict precision (true_positive) | {_fmt_pct(report.precision)} |",
        f"| Verdict recall (true_positive) | {_fmt_pct(report.recall)} |",
        f"| Verdict F1 (true_positive) | {_fmt_pct(report.f1)} |",
        f"| Verdict accuracy (all findings) | {_fmt_pct(report.accuracy)} |",
        f"| Severity agreement (true positives) | "
        f"{_fmt_pct(report.severity_agreement)} |",
        f"| Classifier TP / FP / FN | "
        f"{report.true_positives} / {report.false_positives} / "
        f"{report.false_negatives} |",
        f"| Abstentions (needs_human) | {report.abstentions} |",
        "",
    ]

    lines += ["## Verdict Confusion Matrix", ""]
    header = (
        "| expected \\ predicted | "
        + " | ".join(v.value for v in _VERDICT_ORDER)
        + " |"
    )
    lines.append(header)
    lines.append("| --- | " + " | ".join("---" for _ in _VERDICT_ORDER) + " |")
    for expected in _VERDICT_ORDER:
        matrix_row = report.confusion.get(expected.value)
        if matrix_row is None:
            continue
        cells = " | ".join(str(matrix_row.get(p.value, 0)) for p in _VERDICT_ORDER)
        lines.append(f"| {expected.value} | {cells} |")
    lines.append("")

    lines += ["## Per-finding Results", ""]
    lines.append("| Finding | Expected | Predicted | Severity (exp/pred) | Result |")
    lines.append("| --- | --- | --- | --- | --- |")
    for row in report.results:
        predicted = row.predicted_verdict.value if row.predicted_verdict else "—"
        pred_sev = row.predicted_severity.value if row.predicted_severity else "—"
        status = "✅ pass" if row.passed else "❌ fail"
        lines.append(
            f"| {row.finding_id} | {row.expected_verdict.value} | {predicted} | "
            f"{row.expected_severity.value} / {pred_sev} | {status} |"
        )
    lines.append("")

    return "\n".join(lines)


__all__ = [
    "EvalReport",
    "FindingResult",
    "GroundTruth",
    "load_ground_truth",
    "render_report",
    "score",
]
