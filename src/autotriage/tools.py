"""Deterministic action layer: owners, tickets, PRs, escalation, dispatch.

Everything here is pure, offline, and unit-testable — no LLM or network calls.
The agent produces a :class:`TriageDecision`; these functions turn that decision
into durable artifacts (ticket files, a ``TRACKER.md`` ledger, remediation PR
drafts) and route each finding to the right action.

The same three write actions are also exposed as Claude Agent SDK tools via
:func:`build_action_mcp_server`, for an optional fully-autonomous mode where the
model itself decides when to act.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from autotriage import observability
from autotriage.schema import Action, Finding, TriageDecision

if TYPE_CHECKING:
    from claude_agent_sdk import McpSdkServerConfig

#: Minimum tokens on a CODEOWNERS line (one pattern + at least one owner).
_MIN_CODEOWNERS_TOKENS = 2

#: Header written to a fresh ``TRACKER.md`` ledger.
_TRACKER_HEADER = (
    "# AutoTriage Tracker\n\n"
    "Append-only ledger of triage actions taken by the agent.\n\n"
    "| Timestamp (UTC) | Finding | Verdict | Severity | Confidence "
    "| Action | Owner | Location |\n"
    "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
)


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string (seconds precision)."""
    return datetime.now(tz=UTC).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Owner assignment
# ---------------------------------------------------------------------------
def _codeowners_pattern_matches(pattern: str, file_path: str) -> bool:
    """Return whether a CODEOWNERS ``pattern`` matches ``file_path``.

    Implements the common subset of GitHub CODEOWNERS semantics: a bare ``*``
    matches everything, a trailing-slash pattern matches a directory subtree,
    a slash-bearing pattern is anchored to the repo root, and a slash-free
    pattern matches by basename anywhere in the tree.

    Args:
        pattern: A CODEOWNERS path pattern (the first token on a line).
        file_path: The finding's file path, relative to the repo root.

    Returns:
        ``True`` if the pattern matches the path.
    """
    normalized = file_path.lstrip("/")
    pat = pattern.lstrip("/")
    if pat in ("", "*", "**"):
        return True
    if pat.endswith("/"):
        prefix = pat.rstrip("/")
        return normalized == prefix or normalized.startswith(f"{prefix}/")
    if "/" in pat:
        return fnmatch(normalized, pat) or fnmatch(normalized, f"{pat}/*")
    basename = PurePosixPath(normalized).name
    return (
        fnmatch(normalized, pat)
        or fnmatch(basename, pat)
        or fnmatch(normalized, f"*/{pat}")
    )


def assign_owner(finding: Finding, codeowners_path: Path) -> str | None:
    """Return the CODEOWNERS owner(s) responsible for a finding's file.

    Follows CODEOWNERS "last match wins" precedence: the last matching line in
    the file determines ownership.

    Args:
        finding: The finding whose ``file`` is matched against the patterns.
        codeowners_path: Path to a CODEOWNERS file.

    Returns:
        A space-separated string of owner handles, or ``None`` if the file does
        not exist or no pattern matches.
    """
    if not codeowners_path.is_file():
        return None
    matched: str | None = None
    for raw_line in codeowners_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < _MIN_CODEOWNERS_TOKENS:
            continue
        pattern, owners = parts[0], parts[1:]
        if _codeowners_pattern_matches(pattern, finding.file):
            matched = " ".join(owners)
    return matched


# ---------------------------------------------------------------------------
# Ticket + tracker writing
# ---------------------------------------------------------------------------
def _append_tracker_row(
    tracker_path: Path,
    finding: Finding,
    decision: TriageDecision,
    *,
    action_label: str,
    owner: str,
) -> None:
    """Append a single ledger row to ``tracker_path``, creating it if absent.

    Args:
        tracker_path: Path to the ``TRACKER.md`` ledger.
        finding: The finding being recorded.
        decision: The triage decision for the finding.
        action_label: Human-readable action taken (e.g. ``"open_ticket"``).
        owner: Owner handle(s), or a placeholder such as ``"unassigned"``.
    """
    tracker_path.parent.mkdir(parents=True, exist_ok=True)
    if not tracker_path.exists():
        tracker_path.write_text(_TRACKER_HEADER, encoding="utf-8")
    row = (
        f"| {_now()} | {finding.id} | {decision.verdict.value} "
        f"| {decision.severity.value} | {decision.confidence:.2f} "
        f"| {action_label} | {owner} | {finding.file}:{finding.line} |\n"
    )
    with tracker_path.open("a", encoding="utf-8") as handle:
        handle.write(row)


def file_ticket(
    finding: Finding,
    decision: TriageDecision,
    *,
    tickets_dir: Path,
    tracker_path: Path,
) -> Path:
    """Write a Markdown ticket for a finding and append a tracker row.

    Args:
        finding: The finding to file.
        decision: The triage decision for the finding.
        tickets_dir: Directory to write ``<finding-id>.md`` into (created if
            needed).
        tracker_path: Path to the ``TRACKER.md`` ledger to append to.

    Returns:
        The path to the written ticket file.
    """
    tickets_dir.mkdir(parents=True, exist_ok=True)
    owner = decision.suggested_owner or "unassigned"
    cwe = ", ".join(decision.cwe or finding.cwe) or "n/a"
    ticket = f"""\
# [{decision.severity.value.upper()}] {finding.title}

- **Finding ID:** {finding.id}
- **Scanner:** {finding.tool.value} ({finding.type.value})
- **Rule:** {finding.rule_id}
- **Location:** `{finding.file}:{finding.line}`
- **CWE:** {cwe}
- **Verdict:** {decision.verdict.value}
- **Severity:** {decision.severity.value}
- **Confidence:** {decision.confidence:.2f}
- **Recommended action:** {decision.recommended_action.value}
- **Owner:** {owner}

## Business impact
{decision.business_impact}

## Reasoning
{decision.reasoning}

## Remediation
{decision.remediation or "See reasoning; remediation to be determined."}

## Offending code
```
{finding.code_snippet}
```
"""
    ticket_path = tickets_dir / f"{finding.id}.md"
    ticket_path.write_text(ticket, encoding="utf-8")
    _append_tracker_row(
        tracker_path,
        finding,
        decision,
        action_label=decision.recommended_action.value,
        owner=owner,
    )
    return ticket_path


def draft_pr(finding: Finding, decision: TriageDecision, *, out_dir: Path) -> Path:
    """Write a remediation PR draft (Markdown) with the suggested fix.

    Args:
        finding: The finding being remediated.
        decision: The triage decision carrying the remediation text.
        out_dir: Directory to write ``<finding-id>.pr.md`` into (created if
            needed).

    Returns:
        The path to the written PR draft.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    owner = decision.suggested_owner or "unassigned"
    remediation = decision.remediation or (
        "No concrete remediation was provided; a maintainer should implement "
        "the fix described in the reasoning."
    )
    body = f"""\
# Fix: {finding.title}

_Automated remediation draft generated by AutoTriage._

- **Finding ID:** {finding.id}
- **Location:** `{finding.file}:{finding.line}`
- **Severity:** {decision.severity.value}
- **Suggested reviewer:** {owner}

## Why
{decision.business_impact}

{decision.reasoning}

## Proposed change
{remediation}

## Original code
```
{finding.code_snippet}
```
"""
    pr_path = out_dir / f"{finding.id}.pr.md"
    pr_path.write_text(body, encoding="utf-8")
    return pr_path


def escalate(finding: Finding, decision: TriageDecision, *, tracker_path: Path) -> None:
    """Record a human-review row for a finding in the tracker.

    Args:
        finding: The finding to escalate.
        decision: The triage decision (typically low-confidence / needs_human).
        tracker_path: Path to the ``TRACKER.md`` ledger to append to.
    """
    _append_tracker_row(
        tracker_path,
        finding,
        decision,
        action_label="escalate:human-review",
        owner=decision.suggested_owner or "security-team",
    )


def dispatch(
    finding: Finding,
    decision: TriageDecision,
    *,
    tickets_dir: Path,
    tracker_path: Path,
    pr_dir: Path,
) -> str:
    """Route a decision to the appropriate action and return a summary.

    Routing by :attr:`TriageDecision.recommended_action`:

    * ``OPEN_TICKET`` -> :func:`file_ticket`.
    * ``DRAFT_PR`` -> :func:`draft_pr` **and** :func:`file_ticket` (the PR needs
      a tracking ticket).
    * ``ESCALATE`` -> :func:`escalate` (human-in-the-loop).
    * ``SUPPRESS`` -> log-only (a tracker row, no ticket).

    Args:
        finding: The finding to act on.
        decision: The triage decision to route.
        tickets_dir: Directory for ticket files.
        tracker_path: Path to the ``TRACKER.md`` ledger.
        pr_dir: Directory for PR drafts.

    Returns:
        A short, human-readable summary of the action taken.
    """
    action = decision.recommended_action
    if action is Action.OPEN_TICKET:
        ticket = file_ticket(
            finding, decision, tickets_dir=tickets_dir, tracker_path=tracker_path
        )
        summary = f"opened ticket {ticket.name}"
    elif action is Action.DRAFT_PR:
        pr = draft_pr(finding, decision, out_dir=pr_dir)
        file_ticket(
            finding, decision, tickets_dir=tickets_dir, tracker_path=tracker_path
        )
        summary = f"drafted PR {pr.name} and opened tracking ticket"
    elif action is Action.ESCALATE:
        escalate(finding, decision, tracker_path=tracker_path)
        summary = "escalated to human review"
    else:
        # Action.SUPPRESS — record the suppression but take no further action.
        _append_tracker_row(
            tracker_path,
            finding,
            decision,
            action_label="suppress",
            owner=decision.suggested_owner or "n/a",
        )
        summary = "suppressed (false positive)"
    # Best-effort telemetry: logging must never break dispatch.
    with contextlib.suppress(Exception):
        observability.log_action(finding, summary)
    return summary


# ---------------------------------------------------------------------------
# Optional: expose the action layer as Claude Agent SDK tools.
# ---------------------------------------------------------------------------
def build_action_mcp_server(
    *,
    tickets_dir: Path,
    tracker_path: Path,
    pr_dir: Path,
) -> McpSdkServerConfig:
    """Build a Claude Agent SDK MCP server exposing the write actions.

    This enables an optional autonomous mode: instead of the deterministic
    :func:`dispatch` router, the agent itself calls ``file_ticket``,
    ``draft_pr``, or ``escalate`` as tools. Each tool takes a ``finding`` and a
    ``decision`` object matching the shared schemas and delegates to the
    corresponding function above.

    The ``claude_agent_sdk`` import is deferred so this module stays importable
    without the SDK installed.

    Args:
        tickets_dir: Directory for ticket files.
        tracker_path: Path to the ``TRACKER.md`` ledger.
        pr_dir: Directory for PR drafts.

    Returns:
        An MCP server config registrable via
        ``ClaudeAgentOptions(mcp_servers=...)`` and ``allowed_tools``.
    """
    from claude_agent_sdk import create_sdk_mcp_server, tool  # noqa: PLC0415

    def _parse(args: dict[str, Any]) -> tuple[Finding, TriageDecision]:
        finding = Finding.model_validate(args["finding"])
        decision = TriageDecision.model_validate(args["decision"])
        return finding, decision

    def _ok(text: str) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": text}]}

    schema: dict[str, Any] = {
        "type": "object",
        "properties": {"finding": {"type": "object"}, "decision": {"type": "object"}},
        "required": ["finding", "decision"],
    }

    @tool("file_ticket", "File a ticket and append the tracker.", schema)
    async def _file_ticket_tool(args: dict[str, Any]) -> dict[str, Any]:
        finding, decision = _parse(args)
        path = file_ticket(
            finding, decision, tickets_dir=tickets_dir, tracker_path=tracker_path
        )
        return _ok(f"filed ticket at {path}")

    @tool("draft_pr", "Draft a remediation PR for a finding.", schema)
    async def _draft_pr_tool(args: dict[str, Any]) -> dict[str, Any]:
        finding, decision = _parse(args)
        path = draft_pr(finding, decision, out_dir=pr_dir)
        return _ok(f"drafted PR at {path}")

    @tool("escalate", "Escalate a finding to human review.", schema)
    async def _escalate_tool(args: dict[str, Any]) -> dict[str, Any]:
        finding, decision = _parse(args)
        escalate(finding, decision, tracker_path=tracker_path)
        return _ok(f"escalated {finding.id} to human review")

    return create_sdk_mcp_server(
        name="autotriage-actions",
        version="0.1.0",
        tools=[_file_ticket_tool, _draft_pr_tool, _escalate_tool],
    )


__all__ = [
    "assign_owner",
    "build_action_mcp_server",
    "dispatch",
    "draft_pr",
    "escalate",
    "file_ticket",
]
