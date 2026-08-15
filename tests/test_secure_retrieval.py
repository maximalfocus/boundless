"""Secure retrieval: every unsafe name is an indistinguishable generic 404."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from boundless.fixtures import DEMO_SENTINEL
from helpers import read_document, read_document_raw

SENTINEL_VALUE = DEMO_SENTINEL.split("=", 1)[1]

ESCAPING_NAMES = [
    "../northwind-mills/statement-2026-07.txt",
    "../../config/integration.key",
    "/etc/passwd",
    "vault-link",
]


def test_own_statement_returned(client: TestClient) -> None:
    response = read_document(client, "uma-aurora", "statement-2026-07.txt")
    assert response.status_code == 200
    assert "Period : 2026-07" in response.text


@pytest.mark.parametrize("name", ESCAPING_NAMES)
def test_escaping_name_generic_404(client: TestClient, name: str) -> None:
    response = read_document(client, "uma-aurora", name)
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    assert SENTINEL_VALUE not in response.text
    assert "root:" not in response.text


def test_percent_encoded_names_404(client: TestClient) -> None:
    for raw in ("%2e%2e%2fintegration.key", "%252e%252e%252fintegration.key"):
        response = read_document_raw(client, "uma-aurora", raw)
        assert response.status_code == 404
        assert SENTINEL_VALUE not in response.text


def test_wellformed_missing_is_same_404(client: TestClient) -> None:
    response = read_document(client, "uma-aurora", "statement-2099-01.txt")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_rejection_and_missing_are_indistinguishable(client: TestClient) -> None:
    rejected = read_document(client, "uma-aurora", "../../config/integration.key")
    missing = read_document(client, "uma-aurora", "statement-2099-01.txt")
    assert rejected.status_code == missing.status_code == 404
    assert rejected.text == missing.text
    assert rejected.headers.get("content-type") == missing.headers.get("content-type")
