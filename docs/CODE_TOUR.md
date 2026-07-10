# AutoTriage — Code Tour (understand this codebase in 20 minutes)

**AutoTriage reads raw security-scanner output, reasons about each finding with
Claude, and acts on it — filing tickets, assigning owners, drafting fixes —
while escalating anything it is not sure about to a human.**

This is the newcomer's map. For the operator's command reference see
[USAGE.md](USAGE.md); for the C4 diagrams and trust boundaries see
[architecture.md](architecture.md).

---

## The mental model: an ER triage nurse

If you have ever seen how an emergency room works, you already understand
AutoTriage:

| ER | AutoTriage | Where in the code |
|---|---|---|
| Patients arrive at **intake** | Scanners (Semgrep/Trivy/Gitleaks) surface findings | `scanners.py` |
| Everyone fills the **same intake form** | `Finding` — one normalized shape for every tool | `schema.py` |
| The **triage nurse** assesses each patient | The agent turns a `Finding` into a decision | `agent.py` (+ `prompts.py`) |
| The written **assessment** (acuity, disposition) | `TriageDecision` — verdict, severity, confidence, action | `schema.py` |
| The nurse's **actions** (admit, discharge, order labs) | file a ticket, draft a PR, suppress, escalate | `tools.py` |
| "**If unsure, call a doctor**" | confidence guardrail → `needs_human` / escalate | `schema.py` validator |
| A monthly **quality audit** of the nurse's calls | eval harness scores decisions vs. labels | `eval_harness.py`, `evals/` |

Intake normalizes wildly different inputs into one form; the nurse never invents
authority beyond that form; and a hard rule (not a suggestion) forces a human
review whenever confidence is low.

---

## Everything flows through two contracts

Two Pydantic models in `src/autotriage/schema.py` are the **single source of
truth**. Every layer — scanners, agent, action layer, eval — depends only on
these, which is what let the pieces be built independently.

### `Finding` — scan output → triage input

The standardized intake form. Scanner adapters map each tool's native JSON onto
this shape so nothing downstream cares which tool produced it.

| Field | Meaning |
|---|---|
| `id` | Stable 12-char content hash (`Finding.make_id(tool, rule_id, file, line)`); lets the tracker and eval dedupe deterministically. |
| `tool` | `ScannerTool` enum: `semgrep` / `trivy` / `gitleaks`. |
| `type` | `FindingType` enum: `SAST` / `SCA` / `IAC` / `SECRET`. |
| `rule_id` | The scanner's rule/check identifier. |
| `title` | Short human title. |
| `severity_raw` | The scanner's own severity label (re-assessed later; never trusted verbatim). |
| `cwe`, `owasp` | Normalized weakness/category tokens, e.g. `["CWE-89"]`, `["A03:2021"]`. |
| `file`, `line` | Location. |
| `code_snippet` | The offending source. |
| `description` | The scanner's description. |
| `package`, `installed_version`, `fixed_version` | SCA-only dependency fields (empty otherwise). |
| `raw` | The untouched scanner record, kept for audit. |

### `TriageDecision` — triage output → act + eval input

The nurse's assessment. The agent produces exactly one per finding.

| Field | Meaning |
|---|---|
| `finding_id` | Which finding this decides (pinned to the finding by the agent). |
| `verdict` | `Verdict` enum: `true_positive` / `false_positive` / `needs_human`. |
| `severity` | `Severity` enum re-assessed for this codebase: `critical`…`info`. |
| `confidence` | `0.0`–`1.0`. The load-bearing field for the guardrail. |
| `business_impact` | One-line impact in business terms. |
| `reasoning` | The security rationale. |
| `recommended_action` | `Action` enum: `open_ticket` / `draft_pr` / `suppress` / `escalate`. |
| `suggested_owner` | Owner handle(s), or `None` (then CODEOWNERS resolves it). |
| `remediation` | Suggested fix text (used in tickets/PRs). |
| `cwe` | Weakness tokens carried into the ticket. |

**The guardrail lives in the type.** A `model_validator(mode="after")` coerces
any decision with `confidence < GUARDRAIL_CONFIDENCE_THRESHOLD` (0.6) to
`verdict = needs_human` / `recommended_action = escalate`. No prompt or backend
can bypass it — "if unsure, call a doctor" is enforced at construction time.

---

## File-by-file map

### `src/autotriage/` — the package

| File | What it is / why it exists |
|---|---|
| `schema.py` | The two contracts (`Finding`, `TriageDecision`) + enums + the confidence guardrail. Start here. |
| `scanners.py` | Subprocess adapters for Semgrep/Trivy/Gitleaks + their small CLI. Defensive: a broken tool degrades to an empty result. Intake. |
| `prompts.py` | The frozen `SYSTEM_PROMPT` (persona, severity rubric, action mapping, prompt-injection guardrail) and `render_finding_prompt` (fences untrusted finding text). |
| `agent.py` | The triage nurse. `triage_finding` / `triage_all` with two backends (`api` = forced-tool Messages API, `sdk` = Agent SDK json_schema), `_finalize` (scrub markup, default action), and fail-closed `_escalation_fallback`. |
| `tools.py` | Deterministic, offline action layer: `assign_owner` (CODEOWNERS), `file_ticket`, `draft_pr`, `escalate`, and the `dispatch` router. Optional `build_action_mcp_server` exposes the writes as SDK tools. No LLM/network. |
| `config.py` | Centralized `Settings` (Pydantic-settings): every env var in one validated place; `get_settings()` caches it. |
| `observability.py` | Structured JSON/text logging, `run_id` generation, and best-effort decision/action telemetry. |
| `eval_harness.py` | Scoring logic: `load_ground_truth`, `score` (precision/recall/F1/accuracy/severity agreement), `render_report`. |
| `__main__.py` | The `python -m autotriage` CLI: load findings → triage → assign owner → dispatch (or `--dry-run`) → print summary. |
| `__init__.py`, `py.typed` | Package marker and PEP 561 typing marker (ships our type hints to consumers). |

### Supporting directories

| Path | What it is / why it exists |
|---|---|
| `fixtures/findings.sample.json` | The 17-finding curated contract fixture; default input for the CLI and eval. |
| `target/` | A deliberately vulnerable demo app (Python SQLi/secrets in `app.py`, insecure Terraform in `infra/main.tf`, vulnerable `requirements.txt`, a `CODEOWNERS`). **Do not deploy.** Excluded from lint/typecheck. |
| `evals/` | `run_eval.py` (the scorer CLI + offline stub), `labeled_findings.json` (ground truth), and `report.md` (last output). The self-audit. |
| `tests/` | Unit (`test_schema`, `test_scanners`, `test_agent`, `test_eval`), `test_golden` (ticket/PR snapshots), `test_cli`, `integration/` (full flow with a mocked LLM), and `property/` (Hypothesis invariants). |
| `docs/` | Architecture, ADRs, threat model, runbooks, operations, configuration, eval methodology — plus this tour, [USAGE.md](USAGE.md), and the VHS `tapes/` + rendered `media/` GIFs. |
| `examples/` | Real committed output (tickets, PRs, TRACKER, eval report, a live 44-finding scan) so reviewers see results without running anything. |
| `.github/` | `workflows/ci.yml` (lint/type/test/security matrix), `workflows/triage.yml` (PR scan→triage dry-run), issue/PR templates, `dependabot.yml`, `CODEOWNERS`. |
| `Dockerfile` · `Makefile` · `pyproject.toml` | Container image · dev-task shortcuts · packaging + all tooling config (ruff/mypy/pytest/coverage/bandit). |

---

## Suggested reading order

1. **`src/autotriage/schema.py`** — the two contracts and the guardrail. Nothing
   else makes sense until you know the shapes.
2. **[`../README.md`](../README.md)** — the one-page pitch and the JD coverage map.
3. **[`architecture.md`](architecture.md)** — the C4 views, trust boundaries, and
   failure modes.
4. **`src/autotriage/prompts.py`** — the exact instructions the nurse follows
   (rubric + injection guardrail).
5. **`src/autotriage/agent.py`** — how a `Finding` becomes a `TriageDecision`
   across the two backends, with fail-closed handling.
6. **`src/autotriage/tools.py`** — how a decision becomes durable artifacts.

---

## See it, don't just read it

Observe each stage directly (full flags in [USAGE.md](USAGE.md)):

```bash
# Intake: run the scanners, print normalized findings.
python -m autotriage.scanners target/ -o findings.json

# The nurse at work: triage, preview only (no writes).
python -m autotriage --findings findings.json --dry-run

# The actions: a real run that files tickets / drafts PRs / appends TRACKER.md.
python -m autotriage --findings findings.json \
    --tickets-dir out/tickets --tracker out/TRACKER.md --pr-dir out/prs

# The quality audit: score decisions offline (no API key).
python evals/run_eval.py --stub
```

Prefer to read the outputs? They are committed under
[`../examples/`](../examples/).

---

## Where to go next

- **Run it:** [USAGE.md](USAGE.md) — every command, flag, and flow.
- **Design rationale:** [architecture.md](architecture.md) and the
  [ADRs](adr/README.md).
- **How quality is measured:** [eval-methodology.md](eval-methodology.md).
