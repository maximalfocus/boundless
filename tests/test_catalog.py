"""Catalog-id indirection: opaque id in, no path component anywhere."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.catalog import Catalog
from boundless.config import Settings
from helpers import auth


def test_known_id_returns_document(client: TestClient, settings: Settings) -> None:
    entry = Catalog.from_fixtures(settings).for_tenant("aurora-freight")[0]
    response = client.get(f"/documents/{entry.document_id}", headers=auth("uma-aurora"))
    assert response.status_code == 200
    assert "STATEMENT" in response.text


def test_unknown_id_generic_404(client: TestClient) -> None:
    response = client.get("/documents/doc-does-not-exist", headers=auth("uma-aurora"))
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_other_tenants_id_is_404(client: TestClient, settings: Settings) -> None:
    # A valid id belonging to another tenant must not be reachable across the boundary.
    other = Catalog.from_fixtures(settings).for_tenant("northwind-mills")[0]
    response = client.get(f"/documents/{other.document_id}", headers=auth("uma-aurora"))
    assert response.status_code == 404
