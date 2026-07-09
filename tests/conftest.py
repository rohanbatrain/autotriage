"""Shared pytest fixtures for the AutoTriage test suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from autotriage.schema import Finding

_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent / "fixtures" / "findings.sample.json"
)


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Load the canonical sample findings as validated ``Finding`` objects."""
    data = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    return [Finding.model_validate(item) for item in data]
