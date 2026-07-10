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
from autotriage.schema import Finding  # noqa: E402
from autotriage.stub import stub_triage  # noqa: E402

_DEFAULT_FINDINGS = _REPO_ROOT / "fixtures" / "findings.sample.json"
_DEFAULT_LABELS = Path(__file__).resolve().parent / "labeled_findings.json"
_DEFAULT_REPORT = Path(__file__).resolve().parent / "report.md"


def _load_findings(path: Path) -> list[Finding]:
    """Load and validate normalized findings from ``path``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Finding.model_validate(item) for item in data]


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
