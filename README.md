# AutoTriage

**An autonomous vulnerability-triage agent: it ingests Semgrep/Trivy/Gitleaks findings, reasons about severity and business impact, and acts — filing tickets, assigning owners, drafting remediation PRs — while escalating anything it is not sure about to a human.**

Built with the Claude Agent SDK. AutoTriage turns a raw pile of scanner output into an owned, prioritized, and partly self-remediating backlog, and it ships with an **eval harness** that scores its own triage quality against a labeled set — the part most agent demos skip.

---

## JD coverage map

| JD requirement | Covered by |
|---|---|
| Claude Code / Agent SDK, not just chat | `agent/` harness + this parallel build |
| Read SAST/DAST/scanner output | Semgrep (SAST) + Trivy (SCA/IaC) + Gitleaks (secrets) |
| Reason about severity & business impact | LLM triage rubric → verdict + business_impact |
| Take action autonomously | tickets, owner assignment, draft PRs, `TRACKER.md` |
| **Eval + guardrails (most applicants skip!)** | `evals/` labeled set + precision/recall scorer |
| Beyond triage: auto-PR, auto-validate, summarize | remediation diff, re-scan validation, risk summary |
| Safe-to-act vs escalate to human | confidence threshold → `needs_human` escalation |
| Python + REST + Git + CI/CD | GitHub Action runs scan→triage on every PR |
| Terraform / IaC (plus) | Trivy scans planted insecure `.tf` |
| Structured output + tool calling | pydantic schemas + forced tool use |

---

## Architecture

AutoTriage is a three-stage pipeline over two typed contracts (`Finding` and `TriageDecision`, defined once in `autotriage.schema`), with an evaluation loop and a human-in-the-loop escalation path.

```mermaid
flowchart LR
    subgraph scan["1 · Scan"]
        SG[Semgrep · SAST]
        TR[Trivy · SCA / IaC]
        GL[Gitleaks · secrets]
        SG --> N[normalize]
        TR --> N
        GL --> N
        N --> F["Finding[]<br/>findings.json"]
    end

    subgraph triage["2 · Triage"]
        F --> A{{"Claude agent<br/>(SDK or API backend)"}}
        A --> D["TriageDecision<br/>verdict · severity · confidence"]
    end

    subgraph act["3 · Act"]
        D --> G{confidence ≥ 0.6<br/>and not needs_human?}
        G -- yes --> T[file ticket · assign owner · draft PR]
        G -- no --> H[[escalate to human]]
    end

    D -.-> E[["eval harness<br/>precision / recall"]]
    E -.->|tune rubric & threshold| A

    classDef human fill:#fde68a,stroke:#b45309,color:#111;
    class H human;
```

See [`docs/architecture.md`](docs/architecture.md) for the full data-flow write-up.

---

## Quickstart

```bash
# 1. Environment
python -m venv .venv
source .venv/bin/activate
pip install -e ".[agent,dev]"

# 2. Install the scanners (macOS/Homebrew shown; see each tool's docs for Linux)
pip install semgrep
brew install trivy gitleaks

# 3. Scan a target into normalized findings
python -m autotriage.scanners target/ -o findings.json

# 4. Triage the findings (choose the SDK or the raw Messages API backend)
python -m autotriage --findings findings.json --backend sdk

#    Preview without writing tickets or PRs:
python -m autotriage --findings findings.json --dry-run

# 5. Score triage quality against the labeled set (offline stub — no API key)
python evals/run_eval.py --stub
```

The agent needs an `ANTHROPIC_API_KEY` in the environment for live triage; `--dry-run` and `run_eval.py --stub` run without one.

---

## Standards & quality

The code targets professional Python engineering standards, enforced automatically rather than by convention:

- **PEP 8** style and **PEP 257** docstrings — checked by `ruff check` (with the `D` pydocstyle rules).
- **PEP 484** type hints on every public interface — checked by `mypy --strict` (`mypy src`).
- **Formatting** — `ruff format` (single source of truth, no drift).
- **Tests** — `pytest` over the schema, scanner normalization, and eval harness.
- **Pre-commit** — `pre-commit install` wires ruff + mypy + hygiene hooks to run on every commit.
- **CI** — GitHub Actions runs the exact same gate on every push and pull request (`.github/workflows/ci.yml`), and a second workflow (`.github/workflows/triage.yml`) runs a full scan→triage on each PR and uploads the summary as an artifact.

---

## Guardrails & safety

AutoTriage is designed to act autonomously *only* where it is safe to, and to fail toward human review everywhere else. The rules are enforced in code, not just in the prompt:

- **Confidence threshold → human escalation.** Any `TriageDecision` with `confidence < 0.6` is coerced by a pydantic validator to `verdict = needs_human` and `recommended_action = escalate`. The agent can never silently auto-action something it is unsure about.
- **Prompt-injection defense.** Scanner output — code snippets, finding descriptions, dependency metadata — is treated as **untrusted input**. The system prompt instructs the model to never follow instructions embedded in that data; it is evidence to reason about, never a command to obey.
- **Human-in-the-loop.** Every side effect goes through a validated **tool call** (no free-text actions). `CRITICAL` findings auto-open a ticket but require human sign-off before any remediation PR is merged. See [`docs/escalation-policy.md`](docs/escalation-policy.md) for the full decision table.

---

## Sample output

Triaging the 15-finding sample set produces structured decisions like this:

```json
{
  "finding_id": "sast-sqli-001",
  "verdict": "true_positive",
  "severity": "critical",
  "confidence": 0.97,
  "business_impact": "Unauthenticated SQL injection on the user lookup path could expose the full customer/payments datastore.",
  "reasoning": "User-controlled `username` is interpolated into the query via an f-string with no parameterization; directly exploitable.",
  "recommended_action": "draft_pr",
  "suggested_owner": "@payments-backend",
  "remediation": "Use a parameterized query: cursor.execute(\"SELECT * FROM users WHERE name = %s\", (username,))",
  "cwe": ["CWE-89"]
}
```

and, for the two planted false positives, a suppression instead of a ticket:

```json
{
  "finding_id": "secret-fp-015",
  "verdict": "false_positive",
  "severity": "info",
  "confidence": 0.93,
  "business_impact": "None — AKIAIOSFODNN7EXAMPLE is AWS's public documentation placeholder, not a live credential.",
  "reasoning": "The match is a well-known AWS docs example key inside a comment; no real secret is exposed.",
  "recommended_action": "suppress",
  "cwe": ["CWE-798"]
}
```

A stakeholder-facing roll-up of a full run is in [`docs/risk-summary-sample.md`](docs/risk-summary-sample.md).

---

## Repository layout

```
src/autotriage/     schema (contracts) · scanners · agent · action tools · __main__ CLI
fixtures/           findings.sample.json — the 15-finding contract fixture
evals/              labeled ground truth + run_eval.py precision/recall scorer
target/             deliberately vulnerable app (SQLi, secrets, insecure Terraform)
docs/               architecture · escalation policy · sample risk summary
.github/workflows/  ci.yml (lint/type/test) · triage.yml (scan→triage on PRs)
```

---

*Built with [Claude Code](https://claude.com/claude-code) and orchestrated as parallel Claude agents — the contracts in `autotriage.schema` let five workstreams (target, scanners, agent, eval, docs/CI) be built concurrently and integrated without conflicts. AutoTriage builds agents; it doesn't just chat with them.*
