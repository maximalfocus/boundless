"""The vulnerable read paths disclose, but never write, delete, or mutate anything."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.config import Settings
from helpers import auth, snapshot_tree

READS = [
    "../northwind-mills/statement-2026-07.txt",
    "../../config/integration.key",
    "/etc/passwd",
    "vault-link",
    "statement-2026-07.txt",
]


def test_read_ladder_mutates_nothing(vulnerable_client: TestClient, settings: Settings) -> None:
    before = snapshot_tree(settings.data_root)
    for name in READS:
        vulnerable_client.get("/documents", params={"name": name}, headers=auth("uma-aurora"))
    vulnerable_client.get(
        "/documents/hardened?name=....//....//config/integration.key",
        headers=auth("uma-aurora"),
    )
    assert snapshot_tree(settings.data_root) == before
