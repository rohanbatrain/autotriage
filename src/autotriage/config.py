"""Centralized runtime configuration for AutoTriage.

All tunables are read from the environment (or an optional ``.env`` file) into a
single validated :class:`Settings` model, so the rest of the package never
touches :data:`os.environ` directly. Every field maps to an explicit environment
variable via a validation alias:

* ``ANTHROPIC_API_KEY`` is provider-standard and therefore *unprefixed*.
* Every AutoTriage tunable is namespaced with the ``AUTOTRIAGE_`` prefix.

:func:`get_settings` returns a process-wide cached instance so configuration is
parsed exactly once.

All models are Pydantic v2 and follow PEP 8, PEP 257, and PEP 484.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated runtime settings sourced from the environment or ``.env``.

    Field values resolve, in order of precedence, from an explicit environment
    variable, then the ``.env`` file, then the documented default. Unknown
    environment variables are ignored so the process can run in a busy shell.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    #: Anthropic API credential. Unprefixed to match the provider convention.
    anthropic_api_key: str | None = Field(
        default=None,
        validation_alias="ANTHROPIC_API_KEY",
        description="Anthropic API key; required by the live triage backends.",
    )
    #: Model id used by the triage agent.
    model: str = Field(
        default="claude-sonnet-5",
        validation_alias="AUTOTRIAGE_MODEL",
        description="Model id passed to the triage backend.",
    )
    #: Triage backend implementation to use.
    backend: Literal["api", "sdk"] = Field(
        default="api",
        validation_alias="AUTOTRIAGE_BACKEND",
        description="Triage backend: 'api' (Messages API) or 'sdk' (Agent SDK).",
    )
    #: Confidence guardrail; decisions below this are escalated to a human.
    confidence_threshold: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        validation_alias="AUTOTRIAGE_CONFIDENCE_THRESHOLD",
        description="Minimum confidence before an action may be auto-taken.",
    )
    #: Directory into which ticket Markdown files are written.
    tickets_dir: Path = Field(
        default=Path("tickets"),
        validation_alias="AUTOTRIAGE_TICKETS_DIR",
        description="Directory for generated ticket files.",
    )
    #: Path to the append-only ``TRACKER.md`` ledger.
    tracker_path: Path = Field(
        default=Path("TRACKER.md"),
        validation_alias="AUTOTRIAGE_TRACKER_PATH",
        description="Path to the append-only tracker ledger.",
    )
    #: Directory into which remediation PR drafts are written.
    pr_dir: Path = Field(
        default=Path("pull_requests"),
        validation_alias="AUTOTRIAGE_PR_DIR",
        description="Directory for remediation PR drafts.",
    )
    #: Path to the CODEOWNERS file used for owner assignment.
    codeowners: Path = Field(
        default=Path("target/CODEOWNERS"),
        validation_alias="AUTOTRIAGE_CODEOWNERS",
        description="Path to a CODEOWNERS file for owner assignment.",
    )
    #: Output-token ceiling for a single triage decision.
    max_tokens: int = Field(
        default=4096,
        gt=0,
        validation_alias="AUTOTRIAGE_MAX_TOKENS",
        description="Output-token ceiling for a single triage decision.",
    )
    #: Logging verbosity (a standard :mod:`logging` level name).
    log_level: str = Field(
        default="INFO",
        validation_alias="AUTOTRIAGE_LOG_LEVEL",
        description="Logging level name, e.g. DEBUG/INFO/WARNING.",
    )
    #: Structured-log rendering format.
    log_format: Literal["json", "text"] = Field(
        default="json",
        validation_alias="AUTOTRIAGE_LOG_FORMAT",
        description="Log rendering format: machine-readable 'json' or 'text'.",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide cached :class:`Settings` instance.

    The settings are parsed from the environment (and ``.env``) on first call
    and memoized thereafter, so configuration is read exactly once per process.

    Returns:
        The cached settings instance.
    """
    return Settings()


__all__ = ["Settings", "get_settings"]
