# AutoTriage developer workflow.
#
# Standards enforced: PEP 8 / PEP 257 (ruff), PEP 484 (mypy --strict), pytest
# for the test suite, and bandit + pip-audit for security.

PYTHON ?= python
PKG := autotriage
TARGET ?= target

.PHONY: install lint format typecheck test cov security scan triage eval docker-build demos all

install:  ## Install the package with agent + dev extras (editable).
	$(PYTHON) -m pip install -e ".[agent,dev]"

lint:  ## Lint with ruff.
	ruff check src tests

format:  ## Auto-format with ruff.
	ruff format src tests

typecheck:  ## Static type-check with mypy (strict).
	mypy src

test:  ## Run the test suite.
	pytest

cov:  ## Run tests with coverage and enforce the threshold.
	pytest --cov=$(PKG) --cov-fail-under=80

security:  ## Run bandit and pip-audit.
	bandit -c pyproject.toml -r src
	pip-audit

scan:  ## Run the scanners over the target and write findings.json.
	$(PYTHON) -m $(PKG).scanners $(TARGET) -o findings.json

triage:  ## Run the triage pipeline over findings.json.
	$(PYTHON) -m $(PKG) --findings findings.json

eval:  ## Run the offline eval harness with the stub backend.
	$(PYTHON) evals/run_eval.py --stub

docker-build:  ## Build the container image.
	docker build -t $(PKG):latest .

demos:  ## Render the terminal demo GIFs (requires: brew install vhs).
	@command -v vhs >/dev/null 2>&1 || { echo "vhs not found — install with: brew install vhs"; exit 1; }
	@mkdir -p docs/media
	@for tape in docs/tapes/*.tape; do echo "rendering $$tape"; vhs "$$tape"; done

all: lint typecheck test  ## Lint, type-check, and test.
