"""The write escape is confined to the two documented targets, and never persists."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from boundless.config import Settings
from boundless.fixtures import branding_footer
from boundless.samples import ATTACKER_FOOTER, zip_slip_write_archive
from boundless.secure.app import create_secure_app
from boundless.vulnerable.app import create_vulnerable_app
from helpers import auth, snapshot_tree

DOCUMENTED_TARGETS = {
    "config/branding.conf",
    "archive/northwind-mills/statement-2026-07.txt",
}


def _import_slip(client: TestClient, user_id: str) -> httpx.Response:
    response: httpx.Response = client.post(
        "/documents/import",
        headers=auth(user_id),
        files={"file": ("slip.zip", zip_slip_write_archive(), "application/zip")},
    )
    return response


def _archive_of(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in entries.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def test_only_the_two_documented_targets_change(
    vulnerable_client: TestClient, settings: Settings
) -> None:
    before = snapshot_tree(settings.data_root)
    response = _import_slip(vulnerable_client, "uma-aurora")
    assert response.status_code == 200
    after = snapshot_tree(settings.data_root)

    assert set(after) - set(before) == set(), "no new paths created"
    assert set(before) - set(after) == set(), "nothing deleted"
    changed = {path for path in after if after[path] != before[path]}
    assert changed == DOCUMENTED_TARGETS


def test_fresh_state_recreated_each_run(settings: Settings) -> None:
    # First run tampers the branding config.
    app1 = create_vulnerable_app(settings, acknowledged=True)
    with TestClient(app1) as first:
        _import_slip(first, "uma-aurora")
        tampered = first.get("/statements/summary", headers=auth("uma-aurora")).json()
        assert tampered["footer"] == ATTACKER_FOOTER

    # A second run on the same data root rebuilds fixtures from scratch — no persistence.
    app2 = create_vulnerable_app(settings, acknowledged=True)
    with TestClient(app2) as second:
        fresh = second.get("/statements/summary", headers=auth("uma-aurora")).json()
        assert ATTACKER_FOOTER not in fresh["footer"]
        assert "shared demo archive" in fresh["footer"]
    # And the footer read directly from the rebuilt fixture agrees.
    assert ATTACKER_FOOTER not in branding_footer(settings)


def test_secure_rejects_the_same_archive_whole(settings: Settings) -> None:
    app = create_secure_app(settings)
    with TestClient(app) as secure:
        before = snapshot_tree(settings.data_root)
        response = _import_slip(secure, "uma-aurora")
        assert response.status_code == 400
        assert snapshot_tree(settings.data_root) == before


def test_demo_safety_rail_refuses_out_of_fixture_write_before_any_member(
    vulnerable_client: TestClient, settings: Settings, tmp_path: Path
) -> None:
    before = snapshot_tree(settings.data_root)
    footer_before = branding_footer(settings)
    outside_probe = tmp_path / "outside-fixture-probe.txt"
    archive = _archive_of(
        {
            "../../config/branding.conf": b"[branding]\nfooter = should-not-land\n",
            str(outside_probe): b"must not be written",
        }
    )

    response = vulnerable_client.post(
        "/documents/import",
        headers=auth("uma-aurora"),
        files={"file": ("unsafe.zip", archive, "application/zip")},
    )

    assert response.status_code == 400
    assert not outside_probe.exists()
    assert branding_footer(settings) == footer_before
    assert snapshot_tree(settings.data_root) == before
