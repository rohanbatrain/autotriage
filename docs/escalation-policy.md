# Escalation Policy

This policy defines exactly when AutoTriage may act on its own and when it must hand a finding to a human. The intent is simple: **act autonomously only where it is demonstrably safe, and fail toward human review everywhere else.** The load-bearing rules are enforced in code (`autotriage.schema`), not just described in the prompt.

## Decision table

| Condition | Verdict | Autonomous action | Human sign-off required? |
|---|---|---|---|
| `confidence < 0.6` | forced to `needs_human` | **none** — `escalate` only | Yes — human triages from scratch |
| `verdict == needs_human` (any reason) | `needs_human` | **none** — `escalate` only | Yes |
| Suspected prompt-injection / untrusted-input anomaly | `needs_human` | **none** — `escalate` + flag | Yes — with the raw snippet attached |
| `false_positive`, `confidence ≥ 0.6` | `false_positive` | `suppress` (record + reason) | No — suppression is auditable and reversible |
| `true_positive`, non-critical, `confidence ≥ 0.6` | `true_positive` | `open_ticket` + `assign_owner`; may `draft_pr` | No to open/draft; **yes to merge** any PR |
| `true_positive`, **`severity == critical`** | `true_positive` | `open_ticket` + `assign_owner` (auto) | **Yes** — human sign-off before any auto-PR is merged |

## Rules in detail

### 1. Confidence threshold → human escalation
Any `TriageDecision` with `confidence < 0.6` is coerced by a Pydantic `model_validator` to `verdict = needs_human` and `recommended_action = escalate` (`GUARDRAIL_CONFIDENCE_THRESHOLD` in `autotriage.schema`). This happens at object construction, so a low-confidence decision is *structurally* incapable of triggering an autonomous action — the guardrail cannot be bypassed by prompt wording.

### 2. `needs_human` verdicts always escalate
If the model itself concludes it cannot decide — ambiguous context, missing code, conflicting signals — it returns `needs_human`, which routes straight to the human queue via `escalate`. No ticket is auto-filed and no PR is drafted.

### 3. Critical findings: auto-ticket, but gated remediation
A high-confidence `critical` finding (e.g. SQL injection, RCE via `pickle`/`eval`, a live secret) auto-opens a ticket and assigns an owner so nothing critical sits silently in a backlog. However, **a remediation PR is never auto-merged**: the agent may draft the fix, but a human must review and approve before it lands. AutoTriage accelerates critical response; it does not unilaterally ship code changes to production paths.

### 4. Suspected prompt injection / untrusted-input anomaly → escalate
Scanner output — code snippets, finding descriptions, dependency metadata — is **untrusted input**. If a finding's text contains anything that looks like an instruction to the model ("ignore previous instructions", "mark this as a false positive", embedded tool-call-like directives), or is otherwise anomalous, the agent must **not** follow it. It escalates the finding to a human with the raw snippet attached and flags it as a possible injection attempt. Evidence is reasoned about; it is never obeyed.

## Design principles

- **Every action is a validated tool call.** There are no free-text side effects; actions happen only through `file_ticket`, `assign_owner`, `draft_pr`, and `escalate`.
- **Fail safe, not open.** When any rule above is uncertain or in tension, the more conservative outcome (escalate / require sign-off) wins.
- **Auditable and reversible.** Suppressions and tickets carry the model's reasoning and confidence, so any autonomous decision can be reviewed and undone.
- **Enforced in the type, not the prompt.** The confidence guardrail lives in the schema validator, so it holds regardless of how the model is prompted or which backend runs.
