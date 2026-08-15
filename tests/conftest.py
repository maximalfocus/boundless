"""Shared pytest fixtures: a secure app bound to a throwaway data root."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from boundless.config import Settings
from boundless.secure.app import create_secure_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """A data root under pytest's tmp_path — never the host's real filesystem."""
    return Settings(data_root=tmp_path / "data")


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """A TestClient whose lifespan builds fresh fixtures under the temp data root."""
    app = create_secure_app(settings)
    with TestClient(app) as test_client:
        yield test_client
