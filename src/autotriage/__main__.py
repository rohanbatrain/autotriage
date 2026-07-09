"""Command-line entry point: scan findings -> triage -> act.

Runs the full pipeline over a JSON list of :class:`Finding` records: triage
each finding with the agent, assign an owner from CODEOWNERS, dispatch the
resulting action (unless ``--dry-run``), and print a summary of verdicts,
severities, tickets written, and escalations.

Invoke with ``python -m autotriage`` (or the ``autotriage`` console script).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from autotriage import observability
from autotriage.agent import DEFAULT_MODEL, triage_finding
from autotriage.config import Settings, get_settings
from autotriage.observability import configure_logging, new_run_id
from autotriage.schema import Action, Finding, TriageDecision
from autotriage.tools import assign_owner, dispatch

#: Findings input has no configurable setting; keep its historical default here.
_DEFAULT_FINDINGS = Path("fixtures/findings.sample.json")

_LOGGER = observability.get_logger(__name__)


def _load_findings(path: Path) -> list[Finding]:
    """Load and validate a JSON array of findings.

    Args:
        path: Path to a JSON file containing a list of finding objects.

    Returns:
        The validated findings.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Finding.model_validate(item) for item in data]


def _build_parser(settings: Settings) -> argparse.ArgumentParser:
    """Construct the argument parser for the CLI.

    Flag defaults are sourced from ``settings`` (env / ``.env`` backed), so an
    explicit command-line flag always overrides the environment.

    Args:
        settings: The resolved runtime settings supplying flag defaults.

    Returns:
        The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="autotriage",
        description="Autonomously triage scanner findings and take action.",
    )
    parser.add_argument(
        "--findings",
        type=Path,
        default=_DEFAULT_FINDINGS,
        help="Path to a JSON array of findings (default: %(default)s).",
    )
    parser.add_argument(
        "--backend",
        choices=("api", "sdk"),
        default=settings.backend,
        help="Triage backend to use (default: %(default)s).",
    )
    parser.add_argument(
        "--model",
        default=settings.model,
        help=f"Model id override (default: {DEFAULT_MODEL} or $AUTOTRIAGE_MODEL).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Triage and summarize but do not write tickets or dispatch actions.",
    )
    parser.add_argument(
        "--tickets-dir",
        type=Path,
        default=settings.tickets_dir,
        help="Directory for ticket files (default: %(default)s).",
    )
    parser.add_argument(
        "--codeowners",
        type=Path,
        default=settings.codeowners,
        help="Path to a CODEOWNERS file (default: %(default)s).",
    )
    parser.add_argument(
        "--tracker",
        type=Path,
        default=settings.tracker_path,
        help="Path to the TRACKER.md ledger (default: %(default)s).",
    )
    parser.add_argument(
        "--pr-dir",
        type=Path,
        default=settings.pr_dir,
        help="Directory for remediation PR drafts (default: %(default)s).",
    )
    return parser


def _print_summary(
    decisions: list[TriageDecision], actions: list[str], *, dry_run: bool
) -> None:
    """Print a run summary: counts by verdict and severity, plus actions.

    Args:
        decisions: Every triage decision produced this run.
        actions: Per-finding action summaries (empty when ``dry_run``).
        dry_run: Whether actions were suppressed.
    """
    verdicts = Counter(d.verdict.value for d in decisions)
    severities = Counter(d.severity.value for d in decisions)
    escalations = sum(1 for d in decisions if d.recommended_action is Action.ESCALATE)
    tickets = sum(
        1
        for d in decisions
        if d.recommended_action in (Action.OPEN_TICKET, Action.DRAFT_PR)
    )

    print("\n=== AutoTriage summary ===")
    print(f"findings triaged : {len(decisions)}")
    print("verdicts         : " + ", ".join(f"{k}={v}" for k, v in verdicts.items()))
    print("severities       : " + ", ".join(f"{k}={v}" for k, v in severities.items()))
    print(f"tickets to write : {tickets}")
    print(f"escalations      : {escalations}")
    if dry_run:
        print("mode             : dry-run (no actions taken)")
    else:
        print(f"actions taken    : {len(actions)}")
        for summary in actions:
            print(f"  - {summary}")


def main() -> int:
    """Run the triage pipeline from the command line.

    Returns:
        A process exit code (``0`` on success).
    """
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    run_id = new_run_id()

    args = _build_parser(settings).parse_args()
    findings = _load_findings(args.findings)

    _LOGGER.info(
        "run started",
        extra={
            "event": "run.started",
            "run_id": run_id,
            "findings": len(findings),
            "backend": args.backend,
            "model": args.model,
            "dry_run": args.dry_run,
        },
    )

    decisions: list[TriageDecision] = []
    actions: list[str] = []
    for finding in findings:
        decision = triage_finding(finding, backend=args.backend, model=args.model)
        if decision.suggested_owner is None:
            owner = assign_owner(finding, args.codeowners)
            if owner is not None:
                decision.suggested_owner = owner
        decisions.append(decision)
        if not args.dry_run:
            summary = dispatch(
                finding,
                decision,
                tickets_dir=args.tickets_dir,
                tracker_path=args.tracker,
                pr_dir=args.pr_dir,
            )
            actions.append(f"{finding.id}: {summary}")

    escalations = sum(1 for d in decisions if d.recommended_action is Action.ESCALATE)
    _LOGGER.info(
        "run complete",
        extra={
            "event": "run.complete",
            "findings": len(decisions),
            "escalations": escalations,
            "actions": len(actions),
            "dry_run": args.dry_run,
        },
    )

    _print_summary(decisions, actions, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
