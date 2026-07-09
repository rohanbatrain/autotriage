# 5. Support both the Claude Agent SDK and the Anthropic Messages API

- Status: Accepted
- Date: 2026-07-09
- Deciders: AutoTriage maintainers

## Context

The triage step needs a Claude backend. Two reasonable options exist, with
different trade-offs:

- The **Claude Agent SDK** (`claude_agent_sdk.query`) manages the agent loop,
  tool orchestration, and — via `build_action_mcp_server` — an optional fully
  autonomous mode where the model itself invokes the write actions as MCP tools.
- The **Anthropic Messages API** (`anthropic`) is lower level: one call, a single
  forced tool, deterministic and dependency-light.

Committing to only the SDK couples the whole pipeline to one runtime that may be
unavailable in a given environment (CI, air-gapped, minimal installs). Committing
to only the Messages API forgoes the SDK's agent-loop and tool ergonomics that are
central to the project's purpose. Neither dependency should be mandatory just to
import the package.

## Decision

Support both backends behind one interface, `triage_finding(finding, *, backend,
model)` in `src/autotriage/agent.py`, selected with `--backend {api,sdk}`.

- Both consume the same `Finding` and emit the same validated `TriageDecision`
  (ADR-0002, ADR-0003), so the rest of the pipeline is backend-agnostic.
- `api` is the **default** and the most reliable structured-output path: a single
  forced `submit_triage` tool call.
- `sdk` uses `output_format={"type": "json_schema", ...}` and the primary
  agent-loop-oriented path.
- Both read `ANTHROPIC_API_KEY` from the environment and **import their heavy
  third-party dependency lazily**, so `autotriage.agent` imports cleanly even when
  neither `anthropic` nor `claude_agent_sdk` is installed. The agent runtimes live
  in the optional `agent` extra; the core install (schema / scanners / eval) has
  no LLM dependency.
- The model id is resolved uniformly via `AUTOTRIAGE_MODEL` or `DEFAULT_MODEL`
  (`claude-sonnet-5`).

## Consequences

- Positive: portability and robustness — the demo still runs if one runtime is
  missing; the core package installs without either SDK.
- Positive: the Messages API path is a deterministic reference/robustness check
  for the SDK path, and vice versa.
- Positive: lazy imports keep import-time side effects and the dependency surface
  minimal.
- Negative: two code paths to maintain and test; mitigated by funneling both
  through the shared `_finalize()` validation.
- Neutral: subtle behavioral differences between backends are possible; the eval
  harness can be run against either to compare.
