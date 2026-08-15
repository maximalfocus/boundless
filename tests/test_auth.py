"""Authentication returns a generic 401 for missing/malformed/unknown credentials."""

from __future__ import annotations

from fastapi.testclient import TestClient

from helpers import auth


def test_missing_credentials_401(client: TestClient) -> None:
    response = client.get("/documents", params={"name": "statement-2026-07.txt"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_malformed_credentials_401(client: TestClient) -> None:
    response = client.get(
        "/documents",
        params={"name": "statement-2026-07.txt"},
        headers={"Authorization": "Token abc"},
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_unknown_token_401(client: TestClient) -> None:
    response = client.get(
        "/documents",
        params={"name": "statement-2026-07.txt"},
        headers={"Authorization": "Bearer demo-token-not-issued"},
    )
    assert response.status_code == 401


def test_valid_token_200(client: TestClient) -> None:
    response = client.get(
        "/documents", params={"name": "statement-2026-07.txt"}, headers=auth("uma-aurora")
    )
    assert response.status_code == 200
    assert "Aurora Freight" in response.text
