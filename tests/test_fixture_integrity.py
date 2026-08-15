"""The fixture tree is byte-for-byte unchanged after every rejected path."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.config import Settings
from boundless.samples import traversing_archive
from helpers import (
    absolute_entry_archive,
    auth,
    read_document,
    snapshot_tree,
    symlink_entry_archive,
)

REJECTED_READS = [
    "../../config/integration.key",
    "/etc/passwd",
    "vault-link",
    "../northwind-mills/statement-2026-07.txt",
]


def test_tree_unchanged_after_all_rejections(client: TestClient, settings: Settings) -> None:
    before = snapshot_tree(settings.data_root)

    for name in REJECTED_READS:
        assert read_document(client, "uma-aurora", name).status_code == 404

    for payload in (traversing_archive(), absolute_entry_archive(), symlink_entry_archive()):
        response = client.post(
            "/documents/import",
            headers=auth("uma-aurora"),
            files={"file": ("bad.zip", payload, "application/zip")},
        )
        assert response.status_code == 400

    assert snapshot_tree(settings.data_root) == before
