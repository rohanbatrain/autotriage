# syntax=docker/dockerfile:1
#
# Multi-stage image for AutoTriage.
#
# NOTE: the security scanners AutoTriage shells out to (semgrep / trivy /
# gitleaks) are NOT installed here. They are expected to be present on PATH,
# provided by the CI runner image, or mounted in at runtime. This image ships
# only the Python triage/action pipeline.

# --- Stage 1: build a wheel and its dependencies into a venv -----------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Create an isolated virtualenv we can copy wholesale into the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only what the build needs first, to maximize layer caching.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Install the package with the agent runtime extras.
RUN pip install --upgrade pip \
    && pip install ".[agent]"

# --- Stage 2: minimal, non-root runtime --------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# Create an unprivileged user to run the pipeline.
RUN groupadd --system autotriage \
    && useradd --system --gid autotriage --create-home --home-dir /home/autotriage autotriage

# Bring over the fully-built virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

WORKDIR /workspace
RUN chown autotriage:autotriage /workspace

USER autotriage

ENTRYPOINT ["python", "-m", "autotriage"]
CMD ["--help"]
