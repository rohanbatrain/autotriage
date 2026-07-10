"""Shared data contracts for the AutoTriage pipeline.

This module is the **single source of truth** for the two structured payloads
that move through the system:

* :class:`Finding` — a normalized security finding produced by the scanner
  layer (Semgrep / Trivy / Gitleaks) and consumed by the triage agent.
* :class:`TriageDecision` — the agent's structured verdict for one finding,
  consumed by the action layer and the evaluation harness.

Every scanner adapter, the agent, and the eval harness build against these
models, which is what lets the workstreams be developed independently.

All models are Pydantic v2 and follow PEP 8, PEP 257, and PEP 484.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator

#: Findings the agent triages with a confidence below this threshold are never
#: acted on automatically; they are downgraded to a human-in-the-loop review.
GUARDRAIL_CONFIDENCE_THRESHOLD: float = 0.6


class ScannerTool(StrEnum):
    """Supported security scanners."""

    SEMGREP = "semgrep"
    TRIVY = "trivy"
    GITLEAKS = "gitleaks"


class FindingType(StrEnum):
    """Class of weakness a finding represents."""

    SAST = "SAST"
    SCA = "SCA"
    IAC = "IAC"
    SECRET = "SECRET"  # nosec B105 - enum member name, not a credential


class Severity(StrEnum):
    """Normalized severity ladder used across the pipeline."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(StrEnum):
    """The agent's triage decision for a finding."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_HUMAN = "needs_human"


class Action(StrEnum):
    """The action the agent recommends taking on a finding."""

    OPEN_TICKET = "open_ticket"
    DRAFT_PR = "draft_pr"
    SUPPRESS = "suppress"
    ESCALATE = "escalate"


class Finding(BaseModel):
    """A single normalized security finding.

    Scanner adapters map their native JSON onto this shape so that downstream
    consumers never depend on a specific tool's output format.
    """

    id: str = Field(description="Stable identifier; see :meth:`make_id`.")
    tool: ScannerTool
    type: FindingType
    rule_id: str = Field(description="Scanner rule/check identifier.")
    title: str
    severity_raw: str = Field(description="The scanner's own severity label.")
    cwe: list[str] = Field(default_factory=list, description="e.g. ['CWE-89'].")
    owasp: list[str] = Field(default_factory=list, description="e.g. ['A03:2021'].")
    file: str
    line: int = 0
    code_snippet: str = ""
    description: str = ""
    # Software-composition (dependency) fields; empty for non-SCA findings.
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    #: The untouched scanner record, preserved for auditability.
    raw: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def make_id(tool: str, rule_id: str, file: str, line: int) -> str:
        """Return a stable 12-char id for a finding.

        Using a content hash keeps ids deterministic across runs, which lets
        the tracker and eval harness deduplicate reliably.

        Args:
            tool: Scanner name.
            rule_id: Rule/check identifier.
            file: Path the finding refers to.
            line: Line number within ``file``.

        Returns:
            A 12-character hex digest.
        """
        digest = hashlib.sha1(
            f"{tool}:{rule_id}:{file}:{line}".encode(), usedforsecurity=False
        )
        return digest.hexdigest()[:12]


class TriageDecision(BaseModel):
    """The agent's structured verdict for a single :class:`Finding`.

    A :func:`pydantic.model_validator` enforces the core guardrail: any
    low-confidence decision is coerced to a human escalation so the agent can
    never silently auto-action something it is unsure about.
    """

    finding_id: str
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    business_impact: str = Field(description="One-line impact in business terms.")
    reasoning: str
    recommended_action: Action
    suggested_owner: str | None = None
    remediation: str = ""
    cwe: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enforce_confidence_guardrail(self) -> TriageDecision:
        """Downgrade low-confidence decisions to a human escalation."""
        if self.confidence < GUARDRAIL_CONFIDENCE_THRESHOLD:
            self.verdict = Verdict.NEEDS_HUMAN
            self.recommended_action = Action.ESCALATE
        return self


# ---------------------------------------------------------------------------
# Fix-validation contracts
#
# A triage decision that recommends a fix is only *proposed*; it is not trusted
# until the fix has been applied to an isolated copy of the code and the scanner
# re-run to prove the finding is actually gone. These three models carry a
# machine-applicable patch (:class:`FixPatch`) and the outcome of re-scanning it
# (:class:`FixValidation`).
# ---------------------------------------------------------------------------
class ValidationStatus(StrEnum):
    """Outcome of re-scanning a finding after a proposed fix is applied."""

    #: The finding's signature is gone after the fix and no new finding appeared.
    RESOLVED = "resolved"
    #: The finding's signature still fires after the fix; the fix did not work.
    UNRESOLVED = "unresolved"
    #: The finding is gone but the fix introduced one or more *new* findings.
    REGRESSED = "regressed"
    #: The patch could not be applied or the re-scan could not be run.
    ERROR = "error"
    #: There was no patch to validate (e.g. the decision proposed no fix).
    SKIPPED = "skipped"


class FileEdit(BaseModel):
    """A single exact-substring edit to one file (``str_replace`` semantics).

    ``search`` must occur **exactly once** in the target file; an absent or
    ambiguous match fails the whole patch closed rather than guessing, which
    keeps fix application deterministic and auditable.
    """

    file: str = Field(description="Path to edit, relative to the target root.")
    search: str = Field(description="Exact text to replace; must occur once.")
    replace: str = Field(description="Replacement text.")


class FixPatch(BaseModel):
    """A machine-applicable remediation for a single :class:`Finding`.

    The agent proposes this alongside its human-readable ``remediation`` text;
    the fix-validation loop applies these edits to an isolated copy of the code
    and re-scans to confirm the fix closes the finding.
    """

    finding_id: str
    edits: list[FileEdit] = Field(default_factory=list)
    rationale: str = Field(default="", description="Why this change fixes the issue.")


class FixValidation(BaseModel):
    """The result of re-scanning a finding after applying its :class:`FixPatch`.

    ``resolved`` is the single boolean the action layer gates on: a fix is only
    trusted (and its PR marked validated) when the finding's signature is gone
    *and* no regression was introduced. Anything else fails closed to a human.
    """

    finding_id: str
    status: ValidationStatus
    resolved: bool = Field(description="True only when status is ``resolved``.")
    signatures_before: int = Field(
        default=0, description="Distinct finding signatures before the fix."
    )
    signatures_after: int = Field(
        default=0, description="Distinct finding signatures after the fix."
    )
    new_signatures: list[str] = Field(
        default_factory=list,
        description="Signatures present only after the fix (regressions).",
    )
    detail: str = Field(default="", description="Human-readable outcome summary.")

    @model_validator(mode="after")
    def _sync_resolved(self) -> FixValidation:
        """Keep ``resolved`` consistent with ``status`` (single source of truth)."""
        self.resolved = self.status is ValidationStatus.RESOLVED
        return self


__all__ = [
    "GUARDRAIL_CONFIDENCE_THRESHOLD",
    "Action",
    "FileEdit",
    "Finding",
    "FindingType",
    "FixPatch",
    "FixValidation",
    "ScannerTool",
    "Severity",
    "TriageDecision",
    "ValidationStatus",
    "Verdict",
]
