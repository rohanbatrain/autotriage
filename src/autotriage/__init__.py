"""AutoTriage — autonomous vulnerability triage & remediation agent.

The package is organized around a small set of well-typed contracts
(:mod:`autotriage.schema`) that flow through three layers:

1. **Scan** (:mod:`autotriage.scanners`) — run Semgrep/Trivy/Gitleaks and
   normalize their output into :class:`~autotriage.schema.Finding` objects.
2. **Triage** (:mod:`autotriage.agent`) — an LLM agent reasons about each
   finding and emits a validated :class:`~autotriage.schema.TriageDecision`.
3. **Act** (:mod:`autotriage.tools`) — file tickets, assign owners, draft
   remediation PRs, or escalate to a human.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
