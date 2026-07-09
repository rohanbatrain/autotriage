# Operations: SLOs, observability, on-call & cost

This document defines how AutoTriage is operated as a service: the reliability
targets we hold it to (SLOs/SLIs and error budgets), what we observe, who is
on-call, and how we manage cost. It is deliberately honest about what is
**implemented today** versus **roadmap** — an SLO you cannot measure is a wish,
not a target.

Related: [running.md](runbooks/running.md) ·
[incident-response.md](runbooks/incident-response.md) ·
[configuration.md](configuration.md) ·
[eval-methodology.md](eval-methodology.md) (owned elsewhere).

---

## Service level objectives

AutoTriage's "reliability" is two things at once: it must **run** (pipeline
availability) and it must be **right** (triage quality). We track both.

### SLIs

| SLI | Definition | How measured | Status |
|---|---|---|---|
| **Triage-decision success rate** | fraction of findings that produce a *valid, non-fallback* `TriageDecision` (i.e. not auto-escalated by the `triage_all` exception path) | count fallback escalations vs total in a batch | Measurable from run output today (stderr `; escalating` lines); not yet aggregated |
| **Verdict precision** | of findings the agent called `true_positive`, the fraction that truly are | `evals/run_eval.py` against the labeled set | **Implemented** (eval harness) |
| **Verdict recall** | of truly true-positive findings, the fraction the agent caught (abstentions = misses) | eval harness | **Implemented** |
| **Escalation correctness** | of findings sent to `needs_human`, the fraction that genuinely warranted a human (abstaining on real issues is safe but reduces automation value) | derived from eval confusion matrix (`needs_human` rows) | Derivable from eval report; not a first-class metric yet |
| **Severity-agreement** | on true positives, fraction where agent severity == labeled severity | eval harness (`severity_agreement`) | **Implemented** |
| **Mean cost / finding** | API spend ÷ findings triaged for a run | Anthropic usage ÷ run count | Roadmap (manual today) |
| **Latency / finding** | wall-clock per triage decision (one API call per finding) | timing around `triage_finding` | Roadmap (not instrumented) |

### Target SLOs

These are the initial targets for a mature deployment. The eval-backed ones are
enforceable **today** via the eval harness in CI; the operational ones are
roadmap until the metrics above are emitted and aggregated.

| Objective | Target | Enforceable today? |
|---|---|---|
| Verdict precision (don't cry wolf) | ≥ 0.90 | Yes — eval gate |
| Verdict recall (don't miss real issues) | ≥ 0.85 | Yes — eval gate |
| Severity-agreement | ≥ 0.80 | Yes — eval gate |
| Triage-decision success rate (pipeline completes without fallback) | ≥ 0.99 | Partially (count from run) |
| p95 latency / finding | ≤ 30 s | Roadmap |
| Mean cost / finding | ≤ target $ (set per environment) | Roadmap |

> **Why precision is weighted highest.** A false ticket wastes an owner's time
> and erodes trust in the automation; the guardrail (confidence < threshold →
> escalate) already biases the system toward *not* auto-actioning when unsure.
> We would rather escalate than mis-file.

### Error budgets

For the eval-backed SLOs, the error budget is the gap between the SLO and 100%:
e.g. a 0.90 precision SLO permits a 10% "budget" of mis-classifications on the
labeled set. Policy:

- **Budget healthy** → normal operation; ship prompt/model changes that pass the
  eval gate.
- **Budget burning** (a candidate model/prompt regresses the eval below SLO) →
  **block the rollout** (the eval gate fails) and investigate before promoting.
- **Budget exhausted in production** (an incident: mass FPs, mis-severities) →
  freeze changes, flip to `--dry-run`, follow
  [incident-response.md](runbooks/incident-response.md), and add the failing
  case to `evals/labeled_findings.json` so it is caught next time.

The labeled set is the budget's meter. Growing and curating it is the primary
way to make these SLOs trustworthy.

---

## Observability

### What we log today

The runtime uses Python's standard `logging`. Scanner adapters log warnings
(missing binary, non-zero exit, invalid JSON) under the `autotriage.scanners`
logger; the batch agent prints per-finding escalation notices to **stderr**
(`[triage] <finding-id>: <ExceptionType>: <msg>; escalating`). The CLI prints a
structured **run summary** (counts by verdict and severity, tickets, escalations,
actions).

The durable audit trail is **`TRACKER.md`**: an append-only ledger with one row
per action — timestamp (UTC), finding id, verdict, severity, confidence, action,
owner, and `file:line`. Every ticket (`tickets/<id>.md`) additionally records the
model's `reasoning` and `business_impact`, so any decision is traceable after
the fact.

### Structured logging (roadmap)

The configuration contract reserves `AUTOTRIAGE_LOG_LEVEL` (default `INFO`) and
`AUTOTRIAGE_LOG_FORMAT` (`json` | `text`, default `json`) for a structured
logging layer. The target design:

- **`run_id` / correlation id** — one id per pipeline invocation, stamped on
  every log line and (ideally) every tracker row, so a run can be reconstructed
  end-to-end and correlated with CI job ids.
- **JSON emitter** — one JSON object per line for aggregation
  (Datadog/Loki/CloudWatch), with the human-readable `text` format for local
  runs.
- **Per-finding fields** — `finding_id`, `tool`, `type`, `verdict`, `severity`,
  `confidence`, `recommended_action`, `owner`, plus `model` and `backend`.

Until then, treat `TRACKER.md` + the run summary + stderr as the observability
surface, and scrape them if you need metrics.

### Key metrics to emit (roadmap)

Per run: findings triaged, verdict distribution, severity distribution, tickets
opened, PRs drafted, escalations, fallback-escalations (pipeline errors),
tokens/cost, and wall-clock. Most are already computable from the CLI summary
and `TRACKER.md`; the roadmap is to emit them as structured events.

### Alerting thresholds

Starting points (tune to your volume). Today these are **manual reviews** of the
run summary / `TRACKER.md`; automation is roadmap:

| Alert | Condition | Action |
|---|---|---|
| Eval regression | precision or severity-agreement drops below SLO on a candidate | Block rollout; investigate |
| Escalation spike | fallback-escalations (pipeline errors) > 5% of a batch | Suspect API outage/auth; see IR runbook |
| Ticket-volume spike | tickets in a run ≫ historical mean | Suspect mass-FP or an over-broad scan target |
| Cost spike | run spend ≫ mean cost/finding × findings | Kill run; scope target; check model |
| Zero findings unexpectedly | `findings.json == []` where issues are expected | Suspect missing scanner binaries |

---

## On-call expectations

AutoTriage runs as discrete invocations (PR gate / scheduled batch / manual), not
a long-lived daemon, so "on-call" is about responding to **bad output** and
**pipeline failures**, not paging on uptime.

- **Primary responsibility:** respond to eval regressions blocking a rollout,
  and to incidents (mass FPs, wrong auto-action, cost/outage) per
  [incident-response.md](runbooks/incident-response.md).
- **Know the kill switch cold:** flip runs to `--dry-run`; disable the
  `triage.yml` workflow (`gh workflow disable triage.yml`). No new side effects
  after that.
- **Fail-closed is your friend:** when the agent cannot decide, it escalates. It
  is always safe to disable actions and let humans take over the backlog.
- **Handoff:** current model/prompt/package pins, any open incident, and eval
  baseline (`evals/report.md`).

---

## Cost management

Cost is dominated by **one Messages API call per finding**. Levers:

- **Scope the target.** Scan specific directories, exclude vendored/generated
  trees (e.g. `node_modules`). Findings count drives cost linearly.
- **Cap output.** `AUTOTRIAGE_MAX_TOKENS` (default `4096`) bounds per-decision
  output tokens.
- **Pin the model.** `AUTOTRIAGE_MODEL` / `--model` — an accidental swap to a
  pricier model is a common cost surprise.
- **Use the free paths for dev/CI hygiene.** `--dry-run` still calls the model
  (it triages, just skips side effects), but the eval **`--stub`** and unit tests
  need no API key and no spend — use them for smoke tests.
- **Batch deliberately.** Scheduled batch runs concentrate spend; size them and
  track mean cost/finding as an SLI over time.

For live model ids, limits, and pricing, consult the current Anthropic
documentation rather than hard-coding assumptions here — model ids are
configuration (`AUTOTRIAGE_MODEL`), not code.
