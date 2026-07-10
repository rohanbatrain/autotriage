# Live demo & the AutoTriage GitHub Action

AutoTriage ships as a **composite GitHub Action**, so any repository can adopt the
full scan → triage → act → comment pipeline in one workflow block. This document
is the reference for that action and for the end-to-end live demo that exercises
it.

- **Action definition:** [`action.yml`](../action.yml)
- **Live demo repo:** [`rohanbatrain/nimbuspay-web`](https://github.com/rohanbatrain/nimbuspay-web) — a fictional payments app that consumes the action.
- **Live pipeline run:** [nimbuspay-web PR #1](https://github.com/rohanbatrain/nimbuspay-web/pull/1) — a real pull request where the agent scans, triages, and comments its verdicts inline.

---

## What the demo shows

Opening a pull request on `nimbuspay-web` triggers one workflow step. That step:

1. **Scans** the checked-out code with **Semgrep** (SAST), **Trivy** (SCA + IaC)
   and **Gitleaks** (secrets), normalizing everything to one `Finding` schema.
2. **Triages** each finding with the Claude agent → a `TriageDecision` (verdict,
   severity, confidence, business impact, owner, proposed fix).
3. **Acts**: files tickets, drafts remediation PRs, and **escalates** anything
   below the confidence guardrail to a human.
4. **Reports**: writes the verdict table to the job summary and **upserts a
   single pull-request comment**, and uploads the tickets / fix drafts as a run
   artifact.

Because the target is a realistic (if deliberately vulnerable) payments service,
the PR reads like a genuine security pipeline catching genuine issues before
merge — not a toy.

---

## Consuming the action

Add this to `.github/workflows/security.yml` in any repository:

```yaml
name: Security triage
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write        # required so the action can comment
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rohanbatrain/autotriage@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          codeowners: "CODEOWNERS"
```

That is the entire integration. The action installs the scanners and the tool,
runs the pipeline, and posts the results.

### Inputs

| Input | Default | Description |
|---|---|---|
| `scan-path` | `.` | Directory to scan. |
| `anthropic-api-key` | `""` | Key for live Claude triage. Empty → offline backend (see below). |
| `model` | tool default (`claude-sonnet-5`) | Model id for the triage agent. |
| `max-findings` | `80` | Cost guardrail: triage at most this many findings, most severe first. |
| `codeowners` | `""` | Path to a `CODEOWNERS` file used to assign an owner to each finding. |
| `comment` | `true` | Post/update a PR comment with the triage table. |
| `github-token` | `${{ github.token }}` | Token used to comment (needs `pull-requests: write`). |
| `python-version` | `3.12` | Python version to run the agent on. |

---

## Backend selection & security posture

The action **degrades gracefully instead of failing the build**:

- **Trusted PR (same-repo branch)** — the `ANTHROPIC_API_KEY` secret is
  available, so the action uses the live **Claude** backend (`api`).
- **Untrusted PR (from a fork)** — GitHub deliberately withholds repository
  secrets from fork pull requests. The action detects the missing key and falls
  back to a deterministic **offline `stub` backend**, so every PR still gets a
  triage summary and the check stays green. No secret is ever exposed to
  untrusted code.

The scanners treat all finding content as untrusted data, and the agent's system
prompt hard-refuses any instruction embedded in scanner output (prompt-injection
defense). See [security-posture.md](security-posture.md) and
[threat-model.md](threat-model.md).

---

## Cost & guardrails

Live triage makes one model call per finding (plus one per drafted fix), so cost
scales with finding count. Two controls bound it:

- **`max-findings`** caps how many findings are triaged in a run; the rest are
  reported as skipped in the summary. The most severe findings are kept.
- **`AUTOTRIAGE_MAX_TOKENS`** (default 4096) caps output tokens per decision.

For the `nimbuspay-web` target (~46 findings) a full live run is a few US cents.
Fork PRs cost nothing (offline backend).

---

## Confidence calibration

The agent reports a calibrated confidence per decision and a hard guardrail
(`confidence < 0.6` → `needs_human` → escalate) prevents it from auto-acting when
unsure. The rubric is tuned to be **well-calibrated, not timid**: unambiguous,
textbook findings (SQL injection via string-formatting on request data, `eval` /
`os.system` / `pickle` on request data, hardcoded credentials, world-open buckets
or SSH, a dependency with a published CVE and a fix) get high confidence and are
auto-actioned; only genuinely ambiguous findings (unclear reachability, missing
context, possibly benign) fall below the line and are escalated to a human. See
the rubric in [`prompts.py`](../src/autotriage/prompts.py) and the
[eval methodology](eval-methodology.md).

---

## Running the demo locally (no CI, no key required)

From the AutoTriage repo:

```bash
make demo                 # scan → triage → tickets/PRs + summary on the bundled
                          # target, using the OFFLINE backend (no API key needed)
make demo BACKEND=api     # same, but with live Claude triage (needs ANTHROPIC_API_KEY)
```

`make demo` writes the triage summary to `demo-out/summary.md` and prints it, and
drops tickets and fix drafts under `demo-out/`. This is the fully-offline
fallback for a demo where you cannot rely on the network.
