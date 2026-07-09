# Data Contracts

AutoTriage is built around two Pydantic v2 models defined in
`src/autotriage/schema.py`. They are the **single source of truth** for the two
payloads that move through the pipeline and are the reason the scan, triage, act,
and eval layers can be developed and tested independently
([ADR-0002](adr/0002-normalized-finding-contract.md)).

- **`Finding`** — a normalized security finding produced by the scan layer and
  consumed by the triage agent.
- **`TriageDecision`** — the agent's structured verdict for one finding, consumed
  by the action layer and the eval harness.

All enums are `StrEnum`, so their JSON representation is the lowercase/label
string shown below.

## Enumerations

| Enum | Values (wire form) |
| --- | --- |
| `ScannerTool` | `semgrep`, `trivy`, `gitleaks` |
| `FindingType` | `SAST`, `SCA`, `IAC`, `SECRET` |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` |
| `Verdict` | `true_positive`, `false_positive`, `needs_human` |
| `Action` | `open_ticket`, `draft_pr`, `suppress`, `escalate` |

Module constant: `GUARDRAIL_CONFIDENCE_THRESHOLD = 0.6`.

## `Finding`

Scanner adapters map their native JSON onto this shape so downstream consumers
never depend on a specific tool's output format.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | `str` | — | Stable 12-char content hash; see `make_id`. Used for dedupe, tracking, and labeling. |
| `tool` | `ScannerTool` | — | Which scanner produced the finding. |
| `type` | `FindingType` | — | Class of weakness (`SAST`/`SCA`/`IAC`/`SECRET`). |
| `rule_id` | `str` | — | The scanner's rule/check identifier (e.g. a Semgrep `check_id`, CVE, or Trivy AVD id). |
| `title` | `str` | — | Short human-readable title. |
| `severity_raw` | `str` | — | The scanner's own severity label (un-normalized). |
| `cwe` | `list[str]` | `[]` | Normalized CWE tokens, e.g. `["CWE-89"]`. |
| `owasp` | `list[str]` | `[]` | Normalized OWASP tokens, e.g. `["A03:2021"]`. |
| `file` | `str` | — | Path the finding refers to (repo-relative). |
| `line` | `int` | `0` | Line within `file`. |
| `code_snippet` | `str` | `""` | Offending source excerpt. **Untrusted content.** |
| `description` | `str` | `""` | Longer description. **Untrusted content.** |
| `package` | `str \| None` | `None` | SCA only: affected package name. |
| `installed_version` | `str \| None` | `None` | SCA only: currently installed version. |
| `fixed_version` | `str \| None` | `None` | SCA only: first fixed version, if published. |
| `raw` | `dict[str, Any]` | `{}` | The untouched scanner record, preserved for auditability. |

**`Finding.make_id(tool, rule_id, file, line) -> str`** returns a deterministic
12-char hex digest (`sha1` of `"{tool}:{rule_id}:{file}:{line}"`, `usedforsecurity=False`).
Determinism is what lets the tracker and eval harness deduplicate reliably across
runs.

> Trust note: `title`, `description`, `code_snippet`, and every other field are
> attacker-influenceable data, never instructions to the agent
> ([ADR-0006](adr/0006-treat-scanner-output-as-untrusted.md)).

### Example `Finding`

```json
{
  "id": "sast-sqli-001",
  "tool": "semgrep",
  "type": "SAST",
  "rule_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
  "title": "SQL injection via f-string in query",
  "severity_raw": "ERROR",
  "cwe": ["CWE-89"],
  "owasp": ["A03:2021"],
  "file": "target/app.py",
  "line": 44,
  "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")",
  "description": "User-controlled input is interpolated directly into a SQL query, allowing injection.",
  "package": null,
  "installed_version": null,
  "fixed_version": null,
  "raw": {}
}
```

An SCA example additionally populates the dependency fields:

```json
{
  "id": "sca-pyyaml-009",
  "tool": "trivy",
  "type": "SCA",
  "rule_id": "CVE-2020-1747",
  "title": "PyYAML 5.1 arbitrary code execution via full_load",
  "severity_raw": "CRITICAL",
  "cwe": ["CWE-502"],
  "owasp": ["A06:2021"],
  "file": "target/requirements.txt",
  "line": 2,
  "code_snippet": "PyYAML==5.1",
  "description": "PyYAML before 5.3.1 allows code execution through the FullLoader.",
  "package": "PyYAML",
  "installed_version": "5.1",
  "fixed_version": "5.3.1",
  "raw": {}
}
```

## `TriageDecision`

The agent's structured verdict for one `Finding`. A `model_validator(mode="after")`
enforces the confidence guardrail on every construction/validation
([ADR-0004](adr/0004-confidence-guardrail-and-fail-closed.md)).

| Field | Type | Default | Constraints | Meaning |
| --- | --- | --- | --- | --- |
| `finding_id` | `str` | — | — | Id of the finding this decision is for. Pinned to the real finding in `_finalize`. |
| `verdict` | `Verdict` | — | — | `true_positive` / `false_positive` / `needs_human`. |
| `severity` | `Severity` | — | — | Severity re-assessed for this codebase/business, not the raw scanner label. |
| `confidence` | `float` | — | `0.0 ≤ x ≤ 1.0` | The agent's probability its verdict is correct. Below `0.6` forces escalation. |
| `business_impact` | `str` | — | — | One-line impact in business terms. |
| `reasoning` | `str` | — | — | Security rationale for the verdict. |
| `recommended_action` | `Action` | — | — | `open_ticket` / `draft_pr` / `suppress` / `escalate`. |
| `suggested_owner` | `str \| None` | `None` | — | Owner handle(s); may be filled from `CODEOWNERS` if the model omits it. |
| `remediation` | `str` | `""` | — | Suggested fix; used in ticket and PR-draft bodies. |
| `cwe` | `list[str]` | `[]` | — | CWE tokens carried into the ticket. |

### Guardrail invariant

```python
@model_validator(mode="after")
def _enforce_confidence_guardrail(self) -> TriageDecision:
    if self.confidence < GUARDRAIL_CONFIDENCE_THRESHOLD:  # 0.6
        self.verdict = Verdict.NEEDS_HUMAN
        self.recommended_action = Action.ESCALATE
    return self
```

Any `TriageDecision` with `confidence < 0.6` is **structurally** a `needs_human`
escalation, regardless of what the model returned or which backend produced it.

### Example `TriageDecision`

```json
{
  "finding_id": "sast-sqli-001",
  "verdict": "true_positive",
  "severity": "high",
  "confidence": 0.94,
  "business_impact": "Attacker can read or modify arbitrary user records in the payments user store.",
  "reasoning": "User-controlled `username` is interpolated into the SQL string with no parameterization; reachable from an authenticated request handler. Classic CWE-89.",
  "recommended_action": "draft_pr",
  "suggested_owner": "@payments-appsec",
  "remediation": "Use a parameterized query: cursor.execute(\"SELECT * FROM users WHERE name = ?\", (username,)).",
  "cwe": ["CWE-89"]
}
```

Example of a decision that the guardrail rewrites — a model reply with
`confidence = 0.4` and `verdict = false_positive` is coerced on validation to:

```json
{
  "finding_id": "sast-eval-004",
  "verdict": "needs_human",
  "severity": "high",
  "confidence": 0.4,
  "business_impact": "Possible remote code execution via eval() on request data.",
  "reasoning": "Reachability from untrusted input is unclear from the snippet alone.",
  "recommended_action": "escalate",
  "suggested_owner": null,
  "remediation": "",
  "cwe": ["CWE-95"]
}
```

## Consumers

- **Scan layer** (`autotriage.scanners`) constructs `Finding` objects.
- **Triage layer** (`autotriage.agent`) consumes `Finding`, produces
  `TriageDecision` (schema also used verbatim as the tool `input_schema` /
  `json_schema` output format).
- **Act layer** (`autotriage.tools`) consumes `TriageDecision` to write tickets,
  PR drafts, tracker rows, and escalations.
- **Eval harness** (`autotriage.eval_harness`) compares `TriageDecision` against
  `GroundTruth` labels.
