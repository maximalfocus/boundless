# syntax=docker/dockerfile:1
#
# One image serves every Compose service: the hardened secure runtime, the one-shot demo
# runner, and the verify (lint/type/test) job. It is a local development and teaching
# image only — never deploy it.
FROM python:3.13-slim-bookworm

# Pinned uv for fast, reproducible installs straight from the committed lockfile.
COPY --from=ghcr.io/astral-sh/uv:0.12.4 /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    BOUNDLESS_DATA_ROOT=/data

WORKDIR /app

# Install third-party dependencies only (not the project). Runtime services then get the
# source via COPY, and the verify service via a bind mount, both through PYTHONPATH.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

# Non-root runtime user. /data is a writable tmpfs mount, recreated on every start.
RUN useradd --create-home --uid 10001 demo \
    && mkdir -p /data \
    && chown -R demo:demo /data /app
USER demo

EXPOSE 8000
CMD ["uvicorn", "boundless.secure.app:create_secure_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]
