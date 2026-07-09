# 4. Confidence guardrail enforced in the type layer, fail closed to human

- Status: Accepted
- Date: 2026-07-09
- Deciders: AutoTriage maintainers

## Context

AutoTriage takes autonomous actions on the basis of an LLM's judgment. The
dangerous failure mode is *over-confidence*: the agent marks a real vulnerability
as a false positive and suppresses it, or auto-actions a decision it should not
have trusted. In a payments-scale threat model, a silently dropped critical is far
worse than an unnecessary escalation.

We need the safety property "low-confidence decisions never auto-action" to hold
**regardless of how the model is prompted or which backend runs**. A rule that
lives only in the system prompt can be undermined by prompt injection, prompt
drift, or a backend change. A rule enforced only in the action router could be
bypassed by any new call site.

## Decision

Bake the guardrail into the data contract itself. `TriageDecision` (in
`src/autotriage/schema.py`) carries a Pydantic `model_validator(mode="after")`
that runs on **every** construction and validation:

```python
if self.confidence < GUARDRAIL_CONFIDENCE_THRESHOLD:  # 0.6
    self.verdict = Verdict.NEEDS_HUMAN
    self.recommended_action = Action.ESCALATE
```

Because it lives in the type, any low-confidence decision is *structurally*
incapable of carrying an autonomous action — no prompt wording and no backend can
produce a low-confidence auto-action object.

Complementary fail-closed behavior in `src/autotriage/agent.py`:

- If a backend raises (API error, no tool call, no structured output, malformed
  payload), `triage_all` catches it per finding and substitutes
  `_escalation_fallback(...)` — a `needs_human` / `escalate` decision at
  `confidence = 0.0`. One bad finding never aborts the batch and is never
  silently dropped.
- The system prompt tells the model that under-confidence is safe (it routes to a
  human) and over-confidence is dangerous, so the model is incentivized to abstain
  when genuinely unsure.

The threshold is a single named constant, `GUARDRAIL_CONFIDENCE_THRESHOLD = 0.6`,
so it is auditable and tunable in one place.

## Consequences

- Positive: the core safety invariant holds independently of prompt and backend —
  it is verified by the type, not merely described.
- Positive: every failure path (parse error, API failure, model refusal, low
  confidence) converges on the same safe outcome: a human decides.
- Positive: the threshold and the fallback are unit-testable without any network.
- Negative: recall is capped by abstention — genuine positives the agent is unsure
  about become escalations (false negatives in the eval sense). This is an
  intentional precision/recall trade in favor of safety.
- Negative: a mis-calibrated model that is confidently wrong can still auto-action;
  the guardrail bounds *under*-confidence, not *over*-confidence. This residual
  risk is tracked in the threat model and eval calibration work.
