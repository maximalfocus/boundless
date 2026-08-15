#!/usr/bin/env sh
# The single verification boundary: lint, format check, type check, tests.
# Run inside the container via `docker compose run --rm verify`; CI runs the same thing.
set -eu

echo "== ruff check =="
ruff check src tests

echo "== ruff format --check =="
ruff format --check src tests

echo "== mypy =="
mypy src tests

echo "== pytest =="
pytest

echo "== OK =="
