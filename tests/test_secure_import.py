"""Secure import: well-formed accepted, any unsafe archive rejected as a whole."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from fastapi.testclient import TestClient

from boundless.config import Settings
from boundless.samples import WELL_FORMED_MEMBER, traversing_archive, well_formed_archive
from helpers import (
    absolute_entry_archive,
    auth,
    directory_entry_archive,
    snapshot_tree,
    symlink_entry_archive,
)


def _import(client: TestClient, user_id: str, data: bytes) -> httpx.Response:
    response: httpx.Response = client.post(
        "/documents/import",
        headers=auth(user_id),
        files={"file": ("archive.zip", data, "application/zip")},
    )
    return response


def test_wellformed_archive_accepted(client: TestClient) -> None:
    response = _import(client, "uma-aurora", well_formed_archive())
    assert response.status_code == 200
    assert WELL_FORMED_MEMBER in response.json()["imported"]
    fetched = client.get(
        "/documents", params={"name": WELL_FORMED_MEMBER}, headers=auth("uma-aurora")
    )
    assert fetched.status_code == 200


MALICIOUS: list[Callable[[], bytes]] = [
    traversing_archive,
    absolute_entry_archive,
    symlink_entry_archive,
    directory_entry_archive,
]


@pytest.mark.parametrize("builder", MALICIOUS)
def test_malicious_archive_rejected_whole(
    client: TestClient, settings: Settings, builder: Callable[[], bytes]
) -> None:
    before = snapshot_tree(settings.data_root)
    response = _import(client, "uma-aurora", builder())
    assert response.status_code == 400
    assert response.json() == {"detail": "Bad Request"}
    # Not one byte written from a rejected archive.
    assert snapshot_tree(settings.data_root) == before


def test_non_zip_payload_rejected(client: TestClient, settings: Settings) -> None:
    before = snapshot_tree(settings.data_root)
    response = _import(client, "uma-aurora", b"definitely not a zip archive")
    assert response.status_code == 400
    assert snapshot_tree(settings.data_root) == before
