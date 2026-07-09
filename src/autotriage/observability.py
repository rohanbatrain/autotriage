"""Structured logging and observability for AutoTriage.

This module centralizes how the pipeline emits operational telemetry so that
runs are traceable in production without leaking sensitive material. It provides:

* :class:`JsonFormatter` — renders each record as a single JSON line.
* :func:`configure_logging` — installs a handler on the ``autotriage`` logger,
  honoring the requested level and format (``"json"`` or ``"text"``).
* :func:`get_logger` — returns a namespaced logger under ``autotriage``.
* A per-run correlation id carried in a :class:`contextvars.ContextVar`, with
  :func:`new_run_id` / :func:`bind_run_id` / :func:`get_run_id`.
* :func:`log_decision` / :func:`log_action` — emit structured records for the
  two auditable pipeline events.

Guardrail: these helpers deliberately record only identifiers and verdict
metadata. They never emit secrets (API keys) or full code snippets.

Everything here follows PEP 8, PEP 257, and PEP 484.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from autotriage.schema import Finding, TriageDecision

#: Name of the package-root logger that all AutoTriage loggers descend from.
_ROOT_LOGGER_NAME = "autotriage"

#: Correlation id shared by every log record emitted during a single run.
_run_id: ContextVar[str] = ContextVar("autotriage_run_id", default="-")

#: Standard :class:`logging.LogRecord` attributes; anything outside this set was
#: supplied via ``extra=`` and is promoted to a top-level JSON field.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()
) | {"taskName", "message", "asctime"}


def get_run_id() -> str:
    """Return the current run correlation id (``"-"`` if unbound).

    Returns:
        The active run id.
    """
    return _run_id.get()


def new_run_id() -> str:
    """Generate, bind, and return a fresh run correlation id.

    Returns:
        The newly generated 12-character run id.
    """
    run_id = uuid.uuid4().hex[:12]
    _run_id.set(run_id)
    return run_id


def bind_run_id(run_id: str) -> Token[str]:
    """Bind an explicit run id to the current context.

    Args:
        run_id: The correlation id to bind.

    Returns:
        A reset token that restores the previous value via
        :meth:`contextvars.ContextVar.reset`.
    """
    return _run_id.set(run_id)


class _RunIdFilter(logging.Filter):
    """Inject the active run id onto every record as ``run_id``."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Attach the current run id to ``record`` and keep it.

        Args:
            record: The record being emitted.

        Returns:
            Always ``True`` (the record is never dropped).
        """
        record.run_id = get_run_id()
        return True


class JsonFormatter(logging.Formatter):
    """Render a :class:`logging.LogRecord` as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize ``record`` to a compact JSON string.

        Standard fields (timestamp, level, logger, message, run_id) are always
        present; any ``extra=`` fields are merged in at the top level.

        Args:
            record: The record to serialize.

        Returns:
            A JSON-encoded log line.
        """
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "run_id": getattr(record, "run_id", get_run_id()),
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and key != "run_id":
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure the ``autotriage`` logger with a single stderr handler.

    Calling this is idempotent: existing handlers are cleared first so repeated
    invocations do not duplicate output. The logger does not propagate to the
    root logger, keeping AutoTriage's structured output isolated.

    Args:
        level: A standard logging level name (e.g. ``"INFO"``, ``"DEBUG"``);
            unrecognized values fall back to ``INFO``.
        fmt: ``"json"`` for machine-readable output or ``"text"`` for a
            human-readable line.
    """
    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    logger.setLevel(logging.getLevelNamesMapping().get(level.upper(), logging.INFO))
    for existing in list(logger.handlers):
        logger.removeHandler(existing)

    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(_RunIdFilter())
    if fmt == "text":
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s [run=%(run_id)s] %(message)s"
            )
        )
    else:
        handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a logger namespaced under ``autotriage``.

    Args:
        name: A logger name, typically ``__name__``. Names already under the
            ``autotriage`` namespace are returned unchanged.

    Returns:
        The namespaced logger.
    """
    if name == _ROOT_LOGGER_NAME or name.startswith(f"{_ROOT_LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")


#: Module logger used by the structured event helpers.
_EVENT_LOGGER = get_logger("autotriage.events")


def log_decision(finding: Finding, decision: TriageDecision) -> None:
    """Emit a structured record for one triage decision.

    Records only identifiers and verdict metadata — never code snippets or
    secrets.

    Args:
        finding: The finding that was triaged.
        decision: The agent's decision for the finding.
    """
    _EVENT_LOGGER.info(
        "triage decision",
        extra={
            "event": "triage.decision",
            "finding_id": finding.id,
            "tool": finding.tool.value,
            "verdict": decision.verdict.value,
            "severity": decision.severity.value,
            "confidence": round(decision.confidence, 4),
            "action": decision.recommended_action.value,
        },
    )


def log_action(finding: Finding, summary: str) -> None:
    """Emit a structured record for one dispatched action.

    Args:
        finding: The finding that was acted on.
        summary: A short, human-readable description of the action taken.
    """
    _EVENT_LOGGER.info(
        "action dispatched",
        extra={
            "event": "action.dispatch",
            "finding_id": finding.id,
            "tool": finding.tool.value,
            "action": summary,
        },
    )


__all__ = [
    "JsonFormatter",
    "bind_run_id",
    "configure_logging",
    "get_logger",
    "get_run_id",
    "log_action",
    "log_decision",
    "new_run_id",
]
