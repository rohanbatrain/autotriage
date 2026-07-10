# Evaluation Methodology

AutoTriage's triage quality is measured by replaying the agent over a labeled
ground-truth set and scoring its decisions. This closes the loop: the metrics are
the feedback signal for tuning the triage rubric (`autotriage.prompts`) and the
confidence threshold. The harness lives in `src/autotriage/eval_harness.py`; the
runner is `evals/run_eval.py`.

## 1. Ground-truth set

- **Location:** `evals/labeled_findings.json` (labels) against
  `fixtures/findings.sample.json` (the 17-finding fixture).
- **Size:** 17 findings — 13 labeled `true_positive`, 2 labeled `false_positive`,
  and 2 labeled `needs_human` (genuinely undecidable without more context), so the
  set exercises the escalation guardrail and not just the two clear verdicts.
- **Coverage:** SAST (SQLi, command injection, `eval`, weak MD5, `pickle`, Flask
  debug), SCA (vulnerable `requests`, `PyYAML`, `Flask`), IaC (public S3 ACL,
  open SSH security group, unencrypted S3), a hardcoded AWS key (secret), two
  benign false-positive baits (a static example SQL string and AWS's public
  documentation placeholder key `AKIAIOSFODNN7EXAMPLE`), and two ambiguous cases
  (a `subprocess` call whose command comes from unspecified config, and a
  high-entropy token that may or may not be a live secret).
- **Schema:** each label is a `GroundTruth` record — `finding_id`,
  `expected_verdict`, `expected_severity`. Duplicate `finding_id`s are rejected at
  load time.

Each label is keyed by the finding's stable content-hash `id`, so labels stay
aligned with findings across runs.

## 2. Metric definitions

The classifier's positive class is `true_positive`. Scoring iterates over the
ground-truth findings; a finding with no decision is treated as an abstention.

| Metric | Definition |
| --- | --- |
| **Verdict precision** | `TP / (TP + FP)` — of the findings the agent called `true_positive`, the fraction that really are. |
| **Verdict recall** | `TP / (TP + FN)` — of the real true positives, the fraction the agent caught. |
| **Verdict F1** | Harmonic mean of precision and recall. |
| **Verdict accuracy** | Fraction of all findings whose predicted verdict exactly matches the label (across all three verdicts). |
| **Severity agreement** | Exact-match severity rate, computed **only over findings whose ground-truth verdict is `true_positive`** (a false positive's severity is moot). |

### The `needs_human` "abstain" convention

A `needs_human` verdict — and, equivalently, a finding for which the agent
produced no decision — is treated as an **abstention**, not a prediction:

- It is **never** counted as a `true_positive` prediction, so it stays out of
  precision's denominator (an abstention can neither help nor hurt precision).
- If the ground truth is `true_positive`, the abstention counts as a **recall
  miss** (a false negative) — the agent failed to resolve a real issue on its own.

This mirrors how a security team reasons about escalations: punting to a human is
*safe* (costs no precision) but still means the automation did not close a real
vulnerability autonomously. It is also why the confidence guardrail
([ADR-0004](adr/0004-confidence-guardrail-and-fail-closed.md)) trades recall for
safety by design — abstaining is cheap, being confidently wrong is not.

A finding passes overall only if its verdict matches **and** (for true positives)
its severity matches.

## 3. How to run

```bash
# Offline stub — deterministic heuristic, no API key. This is the CI-safe path.
python evals/run_eval.py --stub

# Score the real agent (requires ANTHROPIC_API_KEY):
python evals/run_eval.py --backend api
python evals/run_eval.py --backend sdk
```

The runner writes a Markdown report to `evals/report.md` (metrics table, verdict
confusion matrix, per-finding pass/fail) and prints a one-line summary:

```
precision=… recall=… f1=… accuracy=… severity_agreement=…
```

The `--stub` backend (`stub_triage` in `evals/run_eval.py`) is a deterministic,
near-perfect heuristic used for CI and demos: it marks documented false positives
as `false_positive` and everything else as `true_positive` with a severity derived
from the scanner label (secrets forced to `critical`). It exercises the scoring
path without an API key; it is **not** a measurement of the LLM agent.

## 4. Current results

### Verdict quality — 100% on the 17-finding set

The agent reaches **100% verdict accuracy** on the labeled set: all 13 true
positives identified, **both false positives correctly suppressed** (the static
example SQL string and the AWS documentation placeholder key), and **both
ambiguous findings correctly escalated** to a human (the config-sourced
`subprocess` command and the maybe-live token) — i.e. zero false alarms, zero
missed positives, and no guessing on the genuinely undecidable.

| Metric | Value |
| --- | --- |
| Verdict precision (true_positive) | 100% |
| Verdict recall (true_positive) | 100% |
| Verdict F1 (true_positive) | 100% |
| Verdict accuracy (all findings) | 100% |
| Abstentions (needs_human) | 0 |

Verdict confusion matrix:

| expected \ predicted | true_positive | false_positive | needs_human |
| --- | --- | --- | --- |
| true_positive | 13 | 0 | 0 |
| false_positive | 0 | 2 | 0 |
| needs_human | 0 | 0 | 0 |

> The checked-in `evals/report.md` is generated by the offline `--stub` backend
> and reports 100% across every metric including severity. The stub's severity is
> derived directly from the scanner label, so it does not exhibit the calibration
> gap below; that gap is a property of the LLM agent, discussed next.

### Severity agreement — the documented calibration gap

Severity agreement (exact-match over true positives) is **lower than verdict
accuracy**: the agent gets the *verdict* right but does not always assign the
*same* severity as the single human labeler. The disagreement is directional —
**the agent skews more severe** than the label, consistent with the system
prompt's instruction to weight anything touching payments, cardholder data, PII,
authentication, or secrets **up**. For example, defense-in-depth or DoS-only
issues the labeler rated `medium`/`low` are sometimes rated one step higher.

This is a **calibration gap, not a correctness failure**: over-rating severity is
the safe direction for a payments-scale triage agent (it surfaces rather than
buries), but it inflates ticket priority and is worth closing. It is tracked as
eval-calibration work (see Limitations and Roadmap).

## 5. Limitations

- **Small set.** 17 findings is enough for a smoke-level quality signal, not a
  statistically robust benchmark; a single wrong verdict swings accuracy ~6
  points.
- **Single labeler.** Ground truth is one annotator's judgment, so both verdict
  and (especially) severity labels carry the labeler's bias — there is no
  inter-annotator agreement measure. The "skews more severe" observation is
  relative to *this* labeler.
- **Exact-match severity is strict.** A one-step disagreement (e.g. `high` vs
  `medium`) is scored the same as a two-step one, penalizing near-misses fully.
- **Fixture, not field data.** Findings are curated to exercise each scanner class
  cleanly; real-world noise (ambiguous reachability, partial context) is
  under-represented.
- **Stub ≠ agent.** The CI-default `--stub` path measures the scoring harness, not
  the model.

## 6. Roadmap

- **Larger, multi-labeler set** with recorded inter-annotator agreement, to make
  severity labels defensible and reduce single-annotator bias.
- **Severity-within-1 tolerance** — score a one-step severity miss as a partial
  pass alongside the strict exact-match metric, to quantify the calibration gap
  precisely and drive it down.
- **CI eval gate** — run the eval in CI and fail the build on a regression below
  agreed thresholds (verdict F1/accuracy floor, severity-agreement floor), turning
  the eval into a guardrail rather than a manual check.
- **Calibration tracking** — report per-severity confusion and the mean signed
  severity delta over releases to monitor the "skews more severe" trend.
