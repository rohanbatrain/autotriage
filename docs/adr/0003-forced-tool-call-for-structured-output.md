# 3. Forced tool-call / JSON-schema for structured triage output

- Status: Accepted
- Date: 2026-07-09
- Deciders: AutoTriage maintainers

## Context

The triage agent must return a machine-consumable verdict — a `TriageDecision`
with a fixed set of typed fields — for every finding. Downstream code (the action
router and the eval harness) cannot tolerate prose, partial JSON, or free-text
that "mostly" parses. A model that returns an explanation instead of a decision,
or that hallucinates an extra field, would break the pipeline or, worse, cause an
action to be taken on malformed data.

Free-text-then-parse approaches (regex, "return JSON only" instructions,
best-effort `json.loads`) are brittle: they fail intermittently, are hard to test,
and give no schema guarantee.

## Decision

Constrain the model to emit structured output that validates against the
`TriageDecision` JSON schema, on both backends:

- **`api` backend (default)** — the Anthropic Messages API is called with a
  single tool whose `input_schema` is `TriageDecision.model_json_schema()`, and
  `tool_choice` is set to force that exact tool (`submit_triage`). The decision is
  read from the tool-use block. Structured output is guaranteed by the tool
  contract.
- **`sdk` backend** — the Claude Agent SDK's `query` is configured with an
  `output_format` of `{"type": "json_schema", "schema": ...}` and the result is
  read from the message's `structured_output`.

Both paths funnel through `_finalize()`, which:

- pins `finding_id` to the real finding (robust to a model that paraphrases or
  drops it),
- derives a safe `recommended_action` from the verdict if the model omits it,
- strips leaked tool-call / prompt markup from free-text fields, and
- runs Pydantic validation, which re-applies the confidence guardrail (ADR-0004).

## Consequences

- Positive: every decision that reaches the action layer is schema-valid by
  construction; there is no bespoke parsing.
- Positive: the schema is defined once in Python and reused as the wire contract
  for both backends — no drift between validation and prompt.
- Positive: validation is the natural place to enforce invariants (guardrail,
  id-pinning, markup scrubbing).
- Negative: a model that refuses to call the tool is a hard failure — handled by
  failing closed to a human escalation (ADR-0004), never by guessing.
- Neutral: forcing a tool call spends a few output tokens on structure; bounded
  by `_MAX_TOKENS = 4096` per decision.
