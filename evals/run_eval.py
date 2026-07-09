"""CLI to score AutoTriage's verdicts against the labeled findings set.

Typical usage::

    # Offline demo / CI — no API key required:
    python evals/run_eval.py --stub

    # Score the real agent (imported lazily so this file never hard-depends
    # on the agent module existing):
    python evals/run_eval.py --backend sdk

The command writes ``evals/report.md`` and prints a one-line metric summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

# Make the ``src`` layout importable when this script is run directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from autotriage.eval_harness import (  # noqa: E402
    load_ground_truth,
    render_report,
    score,
)
from autotriage.schema import (  # noqa: E402
    Action,
    Finding,
    FindingType,
    Severity,
    TriageDecision,
    Verdict,
)

_DEFAULT_FINDINGS = _REPO_ROOT / "fixtures" / "findings.sample.json"
_DEFAULT_LABELS = Path(__file__).resolve().parent / "labeled_findings.json"
_DEFAULT_REPORT = Path(__file__).resolve().parent / "report.md"

#: Maps a scanner's raw severity token onto the normalized ladder.
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


def _load_findings(path: Path) -> list[Finding]:
    """Load and validate normalized findings from ``path``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Finding.model_validate(item) for item in data]


def _looks_like_false_positive(finding: Finding) -> bool:
    """Heuristically decide whether a finding is a documented false positive."""
    text = finding.description.lower()
    return "false positive" in text or "-fp-" in finding.id.lower()


def _stub_severity(finding: Finding) -> Severity:
    """Assign a severity to a true-positive finding without an LLM.

    Hardcoded live secrets are always treated as ``critical``; everything else
    is mapped from the scanner's own severity token.
    """
    if finding.type is FindingType.SECRET:
        return Severity.CRITICAL
    return _SEVERITY_MAP.get(finding.severity_raw.strip().lower(), Severity.MEDIUM)


def stub_triage(findings: Sequence[Finding]) -> list[TriageDecision]:
    """Triage findings with a deterministic, near-perfect offline heuristic.

    This lets the evaluation run with no API key (for CI and demos). It marks
    documented false positives as ``false_positive`` and everything else as a
    ``true_positive`` with a severity derived from the scanner output.

    Args:
        findings: Normalized findings to triage.

    Returns:
        One :class:`~autotriage.schema.TriageDecision` per finding.
    """
    decisions: list[TriageDecision] = []
    for finding in findings:
        if _looks_like_false_positive(finding):
            decisions.append(
                TriageDecision(
                    finding_id=finding.id,
                    verdict=Verdict.FALSE_POSITIVE,
                    severity=Severity.INFO,
                    confidence=0.95,
                    business_impact="No exploitable impact; benign match.",
                    reasoning="Matches a documented non-exploitable pattern.",
                    recommended_action=Action.SUPPRESS,
                    cwe=finding.cwe,
                )
            )
            continue
        decisions.append(
            TriageDecision(
                finding_id=finding.id,
                verdict=Verdict.TRUE_POSITIVE,
                severity=_stub_severity(finding),
                confidence=0.9,
                business_impact="Exploitable weakness in a payments-adjacent service.",
                reasoning="Scanner signal is consistent with a real vulnerability.",
                recommended_action=(
                    Action.DRAFT_PR if finding.fixed_version else Action.OPEN_TICKET
                ),
                cwe=finding.cwe,
            )
        )
    return decisions


def _build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Score AutoTriage verdicts against the labeled findings set.",
    )
    parser.add_argument(
        "--backend",
        choices=("api", "sdk"),
        default="api",
        help="Agent backend to use when not running with --stub.",
    )
    parser.add_argument(
        "--stub",
        action="store_true",
        help="Use the built-in offline stub triage (no API key required).",
    )
    parser.add_argument(
        "--findings",
        type=Path,
        default=_DEFAULT_FINDINGS,
        help="Path to the normalized findings JSON.",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=_DEFAULT_LABELS,
        help="Path to the ground-truth labels JSON.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=_DEFAULT_REPORT,
        help="Where to write the Markdown report.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the evaluation and write the report.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv``).

    Returns:
        Process exit code (``0`` on success).
    """
    args = _build_parser().parse_args(argv)

    findings = _load_findings(args.findings)
    truth = load_ground_truth(args.labels)

    if args.stub:
        decisions = stub_triage(findings)
    else:
        # Imported lazily so this CLI does not hard-depend on the agent module.
        from autotriage.agent import triage_all  # noqa: PLC0415

        decisions = triage_all(findings, backend=args.backend)

    report = score(decisions, truth)
    markdown = render_report(report)
    args.report.write_text(markdown, encoding="utf-8")

    print(
        f"precision={report.precision:.3f} recall={report.recall:.3f} "
        f"f1={report.f1:.3f} accuracy={report.accuracy:.3f} "
        f"severity_agreement={report.severity_agreement:.3f}"
    )
    print(f"report written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
