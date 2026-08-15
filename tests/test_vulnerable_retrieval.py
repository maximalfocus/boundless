"""The vulnerable naive-join endpoint reproduces the full read ladder."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.fixtures import DEMO_SENTINEL
from helpers import auth

SENTINEL_VALUE = DEMO_SENTINEL.split("=", 1)[1]


def test_own_statement_ok(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents", params={"name": "statement-2026-07.txt"}, headers=auth("uma-aurora")
    )
    assert response.status_code == 200
    assert "Aurora Freight" in response.text


def test_cross_tenant_disclosure(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents",
        params={"name": "../northwind-mills/statement-2026-07.txt"},
        headers=auth("uma-aurora"),
    )
    assert response.status_code == 200
    assert "Northwind Mills" in response.text


def test_archive_root_escape_leaks_sentinel(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents", params={"name": "../../config/integration.key"}, headers=auth("uma-aurora")
    )
    assert response.status_code == 200
    assert SENTINEL_VALUE in response.text


def test_absolute_path_override(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents", params={"name": "/etc/passwd"}, headers=auth("uma-aurora")
    )
    assert response.status_code == 200
    assert "root:" in response.text


def test_symlink_escape(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents", params={"name": "vault-link"}, headers=auth("uma-aurora")
    )
    assert response.status_code == 200
    assert SENTINEL_VALUE in response.text


def test_opened_path_is_surfaced(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents", params={"name": "../../config/integration.key"}, headers=auth("uma-aurora")
    )
    assert "integration.key" in response.headers.get("x-boundless-opened", "")


def test_missing_name_is_404(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents", params={"name": "statement-2099-01.txt"}, headers=auth("uma-aurora")
    )
    assert response.status_code == 404
