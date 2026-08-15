"""Statement summary renders the branding footer read at request time."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.config import Settings
from helpers import auth


def test_summary_lists_statements_and_footer(client: TestClient) -> None:
    response = client.get("/statements/summary", headers=auth("uma-aurora"))
    assert response.status_code == 200
    body = response.json()
    assert body["tenant"] == "aurora-freight"
    assert body["count"] == 3
    assert body["statements"] == [
        "statement-2026-05.txt",
        "statement-2026-06.txt",
        "statement-2026-07.txt",
    ]
    assert "shared demo archive" in body["footer"]


def test_footer_read_at_request_time(client: TestClient, settings: Settings) -> None:
    first = client.get("/statements/summary", headers=auth("uma-aurora")).json()
    assert "shared demo archive" in first["footer"]
    # Rewriting the config changes the very next summary — the footer is not cached.
    # (A later slice reaches this file through the vulnerable Zip-Slip write instead.)
    settings.branding_conf_path.write_text(
        "[branding]\nfooter = CHANGED-FOOTER\n", encoding="utf-8"
    )
    second = client.get("/statements/summary", headers=auth("uma-aurora")).json()
    assert second["footer"] == "CHANGED-FOOTER"
