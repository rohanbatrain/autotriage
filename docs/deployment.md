# Deployment

How to deploy and operate AutoTriage across environments. AutoTriage is a Python
package that runs as **discrete invocations** (not a long-lived service): scan →
triage → act. That shape drives every deployment model below.

Related: [configuration.md](configuration.md) ·
[operations.md](operations.md) · [rollback.md](runbooks/rollback.md).

---

## Deployment models

### 1. GitHub Actions PR gate (implemented)

The `triage.yml` workflow runs on every pull request: it installs the scanners,
runs `python -m autotriage.scanners . -o findings.json`, then
`python -m autotriage --findings findings.json --dry-run`, and uploads
`findings.json`, `TRACKER.md`, and `tickets/` as the `triage-summary` artifact.
`ANTHROPIC_API_KEY` is injected from repository secrets.

- **Today it runs in `--dry-run`** — report-only, no side effects. This is the
  safe default for a PR gate.
- **To promote to a live/enforcing gate:** drop `--dry-run` (so tickets/PRs/
  tracker rows are written and committed/uploaded) and/or add a step that fails
  the job on `CRITICAL` findings. Roll this out gradually: watch the dry-run
  summaries first, then enable actions. See the rollout note below.

### 2. Scheduled batch (roadmap pattern)

Run the same pipeline on a cron (`on: schedule:` in a workflow, or an external
scheduler) to sweep the whole repo/monorepo periodically rather than per-PR:

```bash
python -m autotriage.scanners . -o findings.json
python -m autotriage --findings findings.json \
    --tickets-dir out/tickets --tracker out/TRACKER.md --pr-dir out/prs
```

Batch runs concentrate cost — size them and track mean cost/finding
([operations.md](operations.md#cost-management)). Scope the target to control
both cost and noise.

### 3. Container (Dockerfile — created by a sibling workstream)

A container gives you a reproducible image with the scanner binaries baked in —
the cleanest way to pin scanner versions ([rollback.md](runbooks/rollback.md#3-pin-package--scanner-versions-for-reproducibility)).

```bash
# Build (Dockerfile provided by the sibling workstream)
docker build -t autotriage:0.1.0 .

# Scan + triage a mounted repo; pass the key via env, never bake it in
docker run --rm \
  -e ANTHROPIC_API_KEY \
  -e AUTOTRIAGE_MODEL=claude-sonnet-5 \
  -v "$PWD":/workspace -w /workspace \
  autotriage:0.1.0 \
  sh -c 'python -m autotriage.scanners . -o findings.json && \
         python -m autotriage --findings findings.json --dry-run'
```

Principles for the image:

- **Never bake secrets into layers.** Pass `ANTHROPIC_API_KEY` at runtime (`-e`).
- **Pin everything** — base image, Python deps, and the Semgrep/Trivy/Gitleaks
  versions — so the findings (and therefore the triage) are reproducible.
- **Run as non-root** with a read-only mount of the code under review where
  possible.

---

## Secrets management

`ANTHROPIC_API_KEY` is the one secret AutoTriage needs. Handle it per
environment:

| Environment | Mechanism | Notes |
|---|---|---|
| Local dev | Environment variable (`export ANTHROPIC_API_KEY=...`) | `.env`, `*.pem`, `*.key` are git-ignored; a `detect-private-key` pre-commit hook guards against leaks |
| GitHub Actions | **Repository / environment secret** → injected as `env:` | This is what `triage.yml` uses today |
| Production / container | **Secrets manager** (Vault, AWS/GCP secret store) injected as env at runtime | **Roadmap** — pattern only; not wired in code |

Rules:

- Never commit the key; never bake it into a Docker layer or log it.
- Scope the key to least privilege and rotate on a schedule (and immediately on
  suspected exposure — see [incident-response.md](runbooks/incident-response.md#incident-2--anthropic-api-outage--auth-failure)).
- All other configuration is non-secret and lives in env vars / flags
  ([configuration.md](configuration.md)).

---

## Least privilege

- **Scanners run read-only** over the target and shell out with **fixed argv
  lists** (never `shell=True`); a missing/failed scanner degrades to an empty
  result rather than aborting.
- **The agent treats scanner output as untrusted input** — code snippets,
  descriptions, and dependency metadata are evidence to reason about, never
  instructions to obey (prompt-injection defense lives in the system prompt).
- **Side effects are bounded and local:** AutoTriage today writes Markdown files
  (`tickets/`, `pull_requests/`) and appends to `TRACKER.md`. It does **not**
  open real GitHub PRs, merge code, or call external systems. `CRITICAL`
  findings require human sign-off before remediation
  ([escalation-policy.md](escalation-policy.md)).
- **CI token scope:** give the workflow only the permissions it needs
  (`contents: read`, plus `pull-requests: write` *only* if you later post
  summaries as PR comments). Keep `ANTHROPIC_API_KEY` in secrets, not in code.
- **Guardrail in code, not just prompt:** any decision below the confidence
  threshold is coerced to `needs_human` / `escalate` by a schema validator.

---

## Rollout / rollback

**Rollout (any model, prompt, or version change):**

1. Run the eval on the candidate (`python evals/run_eval.py --backend api`) and
   confirm no regression vs the baseline in `evals/report.md` — this is the
   gate.
2. Deploy to a **`--dry-run`** posture first (PR gate is already there). Inspect
   the run summaries and a few tickets.
3. Enable actions (drop `--dry-run`) once the dry-run output looks right.
4. **Pin an explicit `AUTOTRIAGE_MODEL`** in the environment so the model can't
   silently float.

**Rollback:** a model change is a one-line revert (`AUTOTRIAGE_MODEL` /
`--model`, no redeploy); a package/prompt change reverts to a pinned tag/SHA.
Full procedure and cleanup steps in [rollback.md](runbooks/rollback.md).

**Kill switch:** `--dry-run` (manual runs) or `gh workflow disable triage.yml`
(CI). Neither destroys state.
