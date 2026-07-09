"""The triage agent: turn a :class:`Finding` into a :class:`TriageDecision`.

Two interchangeable backends sit behind one interface so the demo stays robust
even if one runtime is unavailable:

* ``"api"`` (default) — the :mod:`anthropic` Messages API with a single forced
  tool call whose ``input_schema`` is the :class:`TriageDecision` JSON schema.
  This is the most reliable path: structured output is guaranteed by the tool
  contract.
* ``"sdk"`` — the Claude Agent SDK's :func:`query` with a ``json_schema``
  output format, read back off the result message's ``structured_output``.

Both backends read ``ANTHROPIC_API_KEY`` from the environment and import their
heavy third-party dependency lazily, so this module imports cleanly even when
neither ``anthropic`` nor ``claude_agent_sdk`` is installed.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from collections.abc import Sequence
from typing import Any, cast

from autotriage import observability
from autotriage.prompts import SYSTEM_PROMPT, render_finding_prompt
from autotriage.schema import Action, Finding, Severity, TriageDecision, Verdict

#: Fallback action to use when a model omits ``recommended_action``, keyed by
#: the verdict it did provide.
_ACTION_BY_VERDICT: dict[Verdict, Action] = {
    Verdict.TRUE_POSITIVE: Action.OPEN_TICKET,
    Verdict.FALSE_POSITIVE: Action.SUPPRESS,
    Verdict.NEEDS_HUMAN: Action.ESCALATE,
}

#: Default model, overridable via the ``AUTOTRIAGE_MODEL`` environment variable.
DEFAULT_MODEL = "claude-sonnet-5"

#: Name of the forced structured-output tool used by the ``"api"`` backend.
_SUBMIT_TOOL_NAME = "submit_triage"

#: Output-token ceiling for a single triage decision (well under SDK timeouts).
_MAX_TOKENS = 4096


def _resolve_model(model: str | None) -> str:
    """Return the model id to use, honoring the ``AUTOTRIAGE_MODEL`` override.

    Args:
        model: An explicit model id, or ``None`` to fall back to the environment
            variable and then :data:`DEFAULT_MODEL`.

    Returns:
        The resolved model identifier.
    """
    return model or os.environ.get("AUTOTRIAGE_MODEL") or DEFAULT_MODEL


def _require_api_key() -> None:
    """Raise a clear error if ``ANTHROPIC_API_KEY`` is not set.

    Raises:
        RuntimeError: If the environment variable is missing or empty.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set; export it before running the triage "
            "agent (or use --dry-run with a stubbed backend)."
        )


#: Free-text fields that must be scrubbed of any leaked markup before use.
_TEXT_FIELDS = ("reasoning", "remediation", "business_impact")

#: Markers that indicate a model has leaked tool-call / prompt markup into a
#: string field; everything from the first marker onward is discarded.
_LEAK_MARKERS = ("</reasoning>", "<parameter", "<", "</antml", "<function")


def _strip_leaked_markup(value: object) -> object:
    """Truncate a string at the first leaked-markup marker, if any.

    Some models occasionally append tool-call or prompt scaffolding (e.g.
    ``</reasoning>`` or ``<parameter ...>``) into a free-text field. Committing
    that to a ticket looks broken, so we cut the field at the first marker.

    Args:
        value: A candidate field value (only strings are altered).

    Returns:
        The cleaned string, or ``value`` unchanged if it is not a string.
    """
    if not isinstance(value, str):
        return value
    cut = len(value)
    for marker in _LEAK_MARKERS:
        idx = value.find(marker)
        if idx != -1:
            cut = min(cut, idx)
    return value[:cut].rstrip()


def _finalize(payload: dict[str, Any], finding: Finding) -> TriageDecision:
    """Validate a raw decision payload, pinning ``finding_id`` to the finding.

    Overriding ``finding_id`` makes the pipeline robust to a model that
    paraphrases or drops the id, and validation re-applies the confidence
    guardrail defined on :class:`TriageDecision`.

    Args:
        payload: The raw decision object emitted by a backend.
        finding: The finding being triaged.

    Returns:
        A validated :class:`TriageDecision`.
    """
    data = dict(payload)
    data["finding_id"] = finding.id
    for field in _TEXT_FIELDS:
        if field in data:
            data[field] = _strip_leaked_markup(data[field])
    # Models occasionally omit recommended_action; derive a safe default from the
    # verdict rather than discarding an otherwise-valid decision.
    if not data.get("recommended_action"):
        try:
            verdict = Verdict(cast("str", data.get("verdict")))
        except ValueError:
            data["recommended_action"] = Action.ESCALATE
        else:
            data["recommended_action"] = _ACTION_BY_VERDICT[verdict]
    return TriageDecision.model_validate(data)


def _escalation_fallback(finding: Finding, reason: str) -> TriageDecision:
    """Return a safe human-escalation decision for an untriageable finding.

    Failing closed (escalate to a human) rather than dropping the finding keeps
    the batch aligned with the confidence guardrail: when the agent cannot
    produce a trustworthy verdict, a person decides.

    Args:
        finding: The finding that could not be triaged.
        reason: A short description of why triage failed.

    Returns:
        A ``needs_human`` decision at zero confidence.
    """
    return TriageDecision(
        finding_id=finding.id,
        verdict=Verdict.NEEDS_HUMAN,
        severity=Severity.MEDIUM,
        confidence=0.0,
        business_impact="Automated triage failed; requires human review.",
        reasoning=f"Escalated automatically: {reason}",
        recommended_action=Action.ESCALATE,
        cwe=list(finding.cwe),
    )


def _triage_via_api(finding: Finding, *, model: str) -> TriageDecision:
    """Triage one finding via the anthropic Messages API (forced tool call).

    Args:
        finding: The finding to triage.
        model: The resolved model id.

    Returns:
        The validated triage decision.

    Raises:
        RuntimeError: If the model does not return the expected tool call.
    """
    import anthropic  # noqa: PLC0415
    from anthropic.types import (  # noqa: PLC0415
        MessageParam,
        ToolChoiceToolParam,
        ToolParam,
    )

    client = anthropic.Anthropic()
    tool: ToolParam = {
        "name": _SUBMIT_TOOL_NAME,
        "description": (
            "Submit the structured triage decision for the finding. Call this "
            "exactly once with every field populated."
        ),
        "input_schema": cast("Any", TriageDecision.model_json_schema()),
    }
    tool_choice: ToolChoiceToolParam = {"type": "tool", "name": _SUBMIT_TOOL_NAME}
    messages: list[MessageParam] = [
        {"role": "user", "content": render_finding_prompt(finding)}
    ]
    response = client.messages.create(
        model=model,
        max_tokens=_MAX_TOKENS,
        system=SYSTEM_PROMPT,
        tools=[tool],
        tool_choice=tool_choice,
        messages=messages,
    )
    for block in response.content:
        if block.type == "tool_use" and block.name == _SUBMIT_TOOL_NAME:
            raw = block.input
            if not isinstance(raw, dict):
                raise RuntimeError(
                    f"submit_triage returned a non-object input: {type(raw)!r}"
                )
            return _finalize(raw, finding)
    raise RuntimeError(
        f"Model did not call {_SUBMIT_TOOL_NAME!r} for finding {finding.id!r}."
    )


async def _triage_via_sdk_async(finding: Finding, *, model: str) -> TriageDecision:
    """Async worker for the Claude Agent SDK backend.

    Args:
        finding: The finding to triage.
        model: The resolved model id.

    Returns:
        The validated triage decision.

    Raises:
        RuntimeError: If no structured output is produced.
    """
    from claude_agent_sdk import ClaudeAgentOptions, query  # noqa: PLC0415

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=SYSTEM_PROMPT,
        output_format={
            "type": "json_schema",
            "schema": TriageDecision.model_json_schema(),
        },
    )
    structured: Any = None
    async for message in query(prompt=render_finding_prompt(finding), options=options):
        candidate = getattr(message, "structured_output", None)
        if candidate is not None:
            structured = candidate
    if not isinstance(structured, dict):
        raise RuntimeError(
            f"Claude Agent SDK produced no structured output for {finding.id!r}."
        )
    return _finalize(structured, finding)


def _triage_via_sdk(finding: Finding, *, model: str) -> TriageDecision:
    """Synchronous wrapper around :func:`_triage_via_sdk_async`.

    Args:
        finding: The finding to triage.
        model: The resolved model id.

    Returns:
        The validated triage decision.
    """
    return asyncio.run(_triage_via_sdk_async(finding, model=model))


def triage_finding(
    finding: Finding, *, backend: str = "api", model: str | None = None
) -> TriageDecision:
    """Triage a single finding into a validated :class:`TriageDecision`.

    Args:
        finding: The normalized scanner finding to triage.
        backend: ``"api"`` (anthropic Messages API, default and most reliable)
            or ``"sdk"`` (Claude Agent SDK structured output).
        model: Optional model override; defaults to ``AUTOTRIAGE_MODEL`` or
            :data:`DEFAULT_MODEL`.

    Returns:
        The agent's structured verdict for the finding.

    Raises:
        RuntimeError: If ``ANTHROPIC_API_KEY`` is unset or a backend fails.
        ValueError: If ``backend`` is not ``"api"`` or ``"sdk"``.
    """
    _require_api_key()
    resolved = _resolve_model(model)
    if backend == "api":
        return _triage_via_api(finding, model=resolved)
    if backend == "sdk":
        return _triage_via_sdk(finding, model=resolved)
    raise ValueError(f"Unknown backend {backend!r}; expected 'api' or 'sdk'.")


def triage_all(
    findings: Sequence[Finding], *, backend: str = "api", model: str | None = None
) -> list[TriageDecision]:
    """Triage a batch of findings, one decision per finding, in order.

    Args:
        findings: The findings to triage.
        backend: The triage backend (see :func:`triage_finding`).
        model: Optional model override (see :func:`triage_finding`).

    Returns:
        A list of decisions aligned with ``findings``. A finding whose triage
        raises is escalated to a human rather than aborting the batch.
    """
    decisions: list[TriageDecision] = []
    for finding in findings:
        try:
            decision = triage_finding(finding, backend=backend, model=model)
        except Exception as exc:  # noqa: BLE001 - fail closed to human escalation
            print(
                f"[triage] {finding.id}: {type(exc).__name__}: {exc}; escalating",
                file=sys.stderr,
            )
            decision = _escalation_fallback(finding, f"{type(exc).__name__}: {exc}")
        decisions.append(decision)
        # Best-effort telemetry: logging must never break the triage batch.
        with contextlib.suppress(Exception):
            observability.log_decision(finding, decision)
    return decisions


__all__ = ["DEFAULT_MODEL", "triage_all", "triage_finding"]
