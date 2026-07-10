"""Render a triage run as GitHub-flavored Markdown.

The same Markdown document is used for two surfaces in CI: it is appended to the
job's ``$GITHUB_STEP_SUMMARY`` and posted as a single (upserted) pull-request
comment, so a reviewer sees the agent's verdicts inline on the PR. The renderer
is pure and dependency-free so it is trivially unit-testable and deterministic
(no timestamps), which keeps the golden/snapshot tests stable.

All functions follow PEP 8, PEP 257, and PEP 484.
"""

from __future__ import annotations

from collections.abc import Sequence

from autotriage.schema import Action, Finding, Severity, TriageDecision, Verdict
from autotriage.stub import severity_rank

#: A stable marker so CI can find and update its own PR comment instead of
#: posting a new one on every push.
COMMENT_MARKER = "<!-- autotriage-report -->"

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "🟥 critical",
    Severity.HIGH: "🟧 high",
    Severity.MEDIUM: "🟨 medium",
    Severity.LOW: "🟦 low",
    Severity.INFO: "⬜ info",
}

_VERDICT_LABEL: dict[Verdict, str] = {
    Verdict.TRUE_POSITIVE: "✅ true positive",
    Verdict.FALSE_POSITIVE: "🟢 false positive",
    Verdict.NEEDS_HUMAN: "⚠️ needs human",
}

_ACTION_LABEL: dict[Action, str] = {
    Action.OPEN_TICKET: "open ticket",
    Action.DRAFT_PR: "draft PR",
    Action.SUPPRESS: "suppress",
    Action.ESCALATE: "escalate → human",
}


def _short_location(finding: Finding) -> str:
    """Return a compact ``file:line`` (or just ``file``) for a finding."""
    return f"{finding.file}:{finding.line}" if finding.line else finding.file


def _escape_cell(text: str) -> str:
    """Make text safe for a Markdown table cell (no pipes / newlines)."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown_report(  # noqa: PLR0913 — display options, all with defaults
    findings: Sequence[Finding],
    decisions: Sequence[TriageDecision],
    *,
    backend: str,
    dry_run: bool,
    capped_from: int | None = None,
    title: str = "AutoTriage — security triage",
) -> str:
    """Render a triage run as a Markdown report.

    Args:
        findings: The findings that were triaged (same order as ``decisions``).
        decisions: The triage decision for each finding.
        backend: The triage backend used (``"api"``, ``"sdk"`` or ``"stub"``).
        dry_run: Whether actions were suppressed (no tickets/PRs written).
        capped_from: If the run was capped to the most severe findings, the
            original finding count before capping; otherwise ``None``.
        title: Heading for the report.

    Returns:
        A GitHub-flavored Markdown document, prefixed with :data:`COMMENT_MARKER`.
    """
    by_id = {d.finding_id: d for d in decisions}
    tickets = sum(1 for d in decisions if d.recommended_action is Action.OPEN_TICKET)
    prs = sum(1 for d in decisions if d.recommended_action is Action.DRAFT_PR)
    escalations = sum(1 for d in decisions if d.recommended_action is Action.ESCALATE)
    suppressed = sum(1 for d in decisions if d.recommended_action is Action.SUPPRESS)

    backend_label = {"api": "Claude (Messages API)", "sdk": "Claude Agent SDK"}.get(
        backend, "offline heuristic (no LLM)"
    )
    mode = "dry-run — no files written" if dry_run else "actions dispatched"

    lines: list[str] = [
        COMMENT_MARKER,
        f"## {title}",
        "",
        (
            f"Triaged **{len(decisions)}** finding(s) → "
            f"**{tickets}** ticket(s), **{prs}** fix PR(s), "
            f"**{escalations}** escalation(s), **{suppressed}** suppressed."
        ),
        "",
        f"_Backend: {backend_label} · {mode}._",
    ]
    if capped_from is not None and capped_from > len(decisions):
        lines.append(
            f"> ⚠️ Capped to the {len(decisions)} most severe of {capped_from} "
            "findings to bound cost; the remainder were not triaged this run."
        )
    lines += [
        "",
        "| Severity | Finding | Location | Verdict | Conf. | Action | Owner |",
        "|---|---|---|---|---:|---|---|",
    ]

    ordered = sorted(
        findings,
        key=lambda f: (
            -severity_rank(by_id[f.id].severity) if f.id in by_id else 99,
            f.file,
        ),
    )
    for finding in ordered:
        decision = by_id.get(finding.id)
        if decision is None:
            continue
        lines.append(
            "| {sev} | {title} | `{loc}` | {verdict} | {conf:.0%} | "
            "{action} | {owner} |".format(
                sev=_SEVERITY_BADGE.get(decision.severity, decision.severity.value),
                title=_escape_cell(finding.title),
                loc=_escape_cell(_short_location(finding)),
                verdict=_VERDICT_LABEL.get(decision.verdict, decision.verdict.value),
                conf=decision.confidence,
                action=_ACTION_LABEL.get(
                    decision.recommended_action, decision.recommended_action.value
                ),
                owner=_escape_cell(decision.suggested_owner or "—"),
            )
        )

    if escalations:
        lines += [
            "",
            (
                f"**{escalations} finding(s) fell below the confidence guardrail "
                "and were escalated to a human** — the agent never auto-acts when "
                "it is unsure."
            ),
        ]

    lines += [
        "",
        "<sub>Generated by "
        "[AutoTriage](https://github.com/rohanbatrain/autotriage) — "
        "autonomous vulnerability triage.</sub>",
        "",
    ]
    return "\n".join(lines)


__all__ = ["COMMENT_MARKER", "render_markdown_report"]
