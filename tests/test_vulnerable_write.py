"""The vulnerable Zip-Slip import writes outside the extraction directory."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from boundless.comparison import all_passed, run_write_demo
from boundless.samples import ATTACKER_FOOTER, zip_slip_write_archive
from helpers import auth


def _import_slip(client: TestClient) -> httpx.Response:
    response: httpx.Response = client.post(
        "/documents/import",
        headers=auth("uma-aurora"),
        files={"file": ("slip.zip", zip_slip_write_archive(), "application/zip")},
    )
    return response


def test_zip_slip_tampers_footer_seen_via_legitimate_summary(
    vulnerable_client: TestClient,
) -> None:
    before = vulnerable_client.get("/statements/summary", headers=auth("uma-aurora")).json()
    assert ATTACKER_FOOTER not in before["footer"]

    imported = _import_slip(vulnerable_client)
    assert imported.status_code == 200

    after = vulnerable_client.get("/statements/summary", headers=auth("uma-aurora")).json()
    # The write escaped to branding.conf; a later *legitimate* summary returns the tamper.
    assert after["footer"] == ATTACKER_FOOTER


def test_zip_slip_overwrites_another_tenants_document(vulnerable_client: TestClient) -> None:
    victim_before = vulnerable_client.get(
        "/documents", params={"name": "statement-2026-07.txt"}, headers=auth("nils-northwind")
    )
    assert victim_before.status_code == 200
    assert "Northwind Mills" in victim_before.text

    _import_slip(vulnerable_client)

    victim_after = vulnerable_client.get(
        "/documents", params={"name": "statement-2026-07.txt"}, headers=auth("nils-northwind")
    )
    assert victim_after.status_code == 200
    assert "OVERWRITTEN" in victim_after.text
    assert victim_after.text != victim_before.text


def test_write_demo_all_pass(isolated_clients: tuple[TestClient, TestClient]) -> None:
    secure, vulnerable = isolated_clients
    rows = run_write_demo(secure, vulnerable)
    failed = [f"{r.name}: {r.vulnerable_observed}" for r in rows if not r.passed]
    assert not failed, failed
    assert all_passed(rows)
    assert {r.group for r in rows} == {"write"}
