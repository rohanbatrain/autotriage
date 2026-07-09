# Runbook: troubleshooting

**Audience:** anyone running AutoTriage who hits an error or a surprising result.
Format: **symptom → cause → fix**. For behavioral incidents (mass FPs, cost,
outages) see [incident-response.md](incident-response.md).

---

## Quick triage table

| Symptom | Likely cause | Fix |
|---|---|---|
| `RuntimeError: ANTHROPIC_API_KEY is not set` | No API key in env for a live run | `export ANTHROPIC_API_KEY=sk-ant-...`, or run with `--dry-run` / eval `--stub` |
| HTTP `401 Unauthorized` from the API | Invalid / rotated key | Re-issue the key and re-export it; check no stray whitespace |
| HTTP `429 Too Many Requests` | Rate limit / large batch | Reduce batch size, back off and retry, scan a narrower target |
| `<tool> binary not found on PATH; skipping ... scan` (warning) | Scanner not installed | Install the scanner ([running.md](running.md#2-install-the-scanners)); or ignore if that scanner is intentionally absent |
| `findings.json` is `[]` (empty) | Nothing found, or all scanners skipped | See [Empty findings](#empty-findings) below |
| `<tool> emitted invalid JSON` / `produced no output` (warning) | Scanner errored or version mismatch | Run the scanner manually to see stderr; pin a known-good scanner version |
| `pydantic ... ValidationError` loading findings | `--findings` file is not a valid `Finding[]` | Regenerate via `python -m autotriage.scanners`; do not hand-edit |
| `Model did not call 'submit_triage' ...` (RuntimeError) | Model returned no tool call (api backend) | Retry; check the model id is valid; that finding auto-escalates in batch mode |
| `Claude Agent SDK produced no structured output ...` | sdk backend returned no `structured_output` | Retry; or use `--backend api` (most reliable) |
| `ValueError: Unknown backend '...'` | `--backend` not `api`/`sdk` | Use `--backend api` or `--backend sdk` |
| `ModuleNotFoundError: anthropic` / `claude_agent_sdk` | `agent` extra not installed | `pip install -e ".[agent]"` |
| Low `severity_agreement` in the eval | Rubric drift / model change | See [Low severity-agreement](#low-severity-agreement) |
| Low `precision` / `recall` in the eval | Verdict regression | See [Eval regressions](#eval-regressions) |
| Owner shows as `unassigned` on tickets | CODEOWNERS miss | See [Owner not assigned](#owner-not-assigned) |
| Ticket free-text ends abruptly / looks truncated | Leaked-markup scrubber cut the field | Expected safety behavior; see [Truncated ticket text](#truncated-ticket-text) |
| Scanner run hangs then stops | 600s per-scanner subprocess timeout | Scope the target smaller; the run degrades to an empty result for that tool |

---

## Details

### Auth 401 / missing key

Live triage (both `api` and `sdk` backends) reads `ANTHROPIC_API_KEY` from the
environment and fails fast if it is unset. A `401` after it *is* set means the
key is wrong or revoked.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m autotriage --findings findings.json --backend api
```

No key available? Everything except live triage still works:
`--dry-run` and `python evals/run_eval.py --stub`.

### Scanner not found

Each adapter checks for its binary with `shutil.which` and, if missing, logs a
warning and returns no findings — **it never aborts the scan**. So a warning is
informational. Install the tool only if you actually want that scan class:

```bash
command -v semgrep trivy gitleaks   # see what's missing
pip install semgrep                 # SAST
brew install trivy gitleaks         # SCA/IaC + secrets
```

### Empty findings

An empty `findings.json` (`[]`) is a **valid** result, not an error. Common
causes:

- All three scanners are absent (check for the "binary not found" warnings).
- The target genuinely has no matching issues.
- You scanned the wrong path.

Confirm the scanners are present and point at a directory known to contain
issues (the bundled `target/` app is deliberately vulnerable):

```bash
python -m autotriage.scanners target/ -o findings.json
```

### Schema validation errors

`--findings` must be a JSON **array** of `Finding` objects matching
`autotriage.schema.Finding`. A `ValidationError` means the file was hand-edited
or produced by something other than the scanner layer. Regenerate it:

```bash
python -m autotriage.scanners <target> -o findings.json
```

Do not hand-author findings; the `id` is a deterministic content hash the
tracker and eval rely on.

### Backend errors (no tool call / no structured output)

- **api backend** forces a `submit_triage` tool call; if the model returns none,
  a single `triage_finding` call raises `RuntimeError`. In a batch
  (`triage_all` / the CLI), that finding is caught and **escalated to a human**
  rather than aborting the batch — look for `[triage] <id>: ...; escalating` on
  stderr.
- **sdk backend** raises if no `structured_output` comes back. If you hit this
  repeatedly, switch to `--backend api`, which is the most reliable path.

Either way, retrying is safe and idempotent (finding ids are stable).

### Low severity-agreement

`severity_agreement` measures how often the agent's severity matches the label
on genuinely true-positive findings. A drop usually means the **rubric or model
changed**:

1. Diff `src/autotriage/prompts.py` (the severity rubric lives in
   `SYSTEM_PROMPT`).
2. Confirm the pinned model (`AUTOTRIAGE_MODEL` / `--model`).
3. Re-run `python evals/run_eval.py --backend api` and read `evals/report.md`
   for the per-finding severity mismatches.

If a change caused it, roll back per [rollback.md](rollback.md).

### Eval regressions

`precision` / `recall` / `f1` score verdict quality (detecting `true_positive`).
Remember: `needs_human` is an **abstention** — it never hurts precision, but on a
true-positive label it is a recall miss. A precision drop → the agent is calling
benign findings real; a recall drop → it is missing or over-escalating real
ones. Compare against the deterministic `--stub` baseline to isolate agent vs
harness issues.

### Owner not assigned

Owners come from a CODEOWNERS file (`--codeowners`, default `target/CODEOWNERS`).
`unassigned` means no pattern matched the finding's file path. Check:

- The `--codeowners` path is correct and the file exists.
- A pattern actually matches the finding's `file` (CODEOWNERS uses **last match
  wins**; a broad later line can override a specific earlier one).

Owner assignment is deterministic — fix the CODEOWNERS file and re-run.

### Truncated ticket text

The agent scrubs free-text fields (`reasoning`, `remediation`,
`business_impact`) of any leaked tool-call/prompt markup (e.g. a stray
`<parameter` or `</reasoning>`), cutting the field at the first marker. If a
ticket's prose ends abruptly, this scrubber fired — it is a **safety feature**
(a leaked-markup ticket looks broken), not data loss of anything meaningful.

### Scanner timeout

Each scanner invocation has a 600-second subprocess timeout. On a very large
target a tool may hit it; the adapter logs a warning and returns an empty result
for that tool while the others continue. Scope the target to a smaller path to
stay under the limit.

---

## Still stuck?

- Re-read [running.md](running.md) for the expected happy path.
- Reproduce with the offline stub to isolate agent vs pipeline:
  `python evals/run_eval.py --stub`.
- Open an issue with the failing command, the summary output, and any warnings —
  see [SUPPORT.md](../../SUPPORT.md).
