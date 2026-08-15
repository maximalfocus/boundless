"""Shared pytest fixtures: a secure app bound to a throwaway data root."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from boundless.config import Settings
from boundless.secure.app import create_secure_app
from boundless.vulnerable.app import create_vulnerable_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """A data root under pytest's tmp_path — never the host's real filesystem."""
    return Settings(data_root=tmp_path / "data")


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """A secure TestClient whose lifespan builds fresh fixtures under the temp data root."""
    app = create_secure_app(settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def vulnerable_client(settings: Settings) -> Iterator[TestClient]:
    """A vulnerable TestClient (explicitly acknowledged), same fixtures."""
    app = create_vulnerable_app(settings, acknowledged=True)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def both_clients(settings: Settings) -> Iterator[tuple[TestClient, TestClient]]:
    """Secure and vulnerable clients bound to the same deterministic data root.

    Suitable for read-only comparisons where shared, identical fixtures are convenient.
    """
    secure_app = create_secure_app(settings)
    vulnerable_app = create_vulnerable_app(settings, acknowledged=True)
    with TestClient(secure_app) as secure, TestClient(vulnerable_app) as vulnerable:
        yield secure, vulnerable


@pytest.fixture
def isolated_clients(tmp_path: Path) -> Iterator[tuple[TestClient, TestClient]]:
    """Secure and vulnerable clients with SEPARATE data roots, as in real deployment.

    Required for write demonstrations, where the vulnerable app must not mutate the
    secure app's fixture tree.
    """
    secure_app = create_secure_app(Settings(data_root=tmp_path / "secure-data"))
    vulnerable_app = create_vulnerable_app(
        Settings(data_root=tmp_path / "vulnerable-data"), acknowledged=True
    )
    with TestClient(secure_app) as secure, TestClient(vulnerable_app) as vulnerable:
        yield secure, vulnerable
