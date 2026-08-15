"""The rejection audit event: emitted once, and free of sensitive content."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from boundless.samples import traversing_archive
from helpers import auth, read_document


def _events(captured: str) -> list[dict[str, str]]:
    return [json.loads(line) for line in captured.splitlines() if line.startswith("{")]


def test_one_event_per_read_rejection(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    response = read_document(client, "uma-aurora", "../../config/integration.key")
    assert response.status_code == 404
    events = _events(capsys.readouterr().out)
    assert len(events) == 1
    event = events[0]
    assert event["event"] == "boundless.rejection"
    assert event["operation"] == "retrieve"
    assert event["outcome"] == "rejected"
    assert event["actor"] == "uma-aurora"
    assert event["tenant"] == "aurora-freight"
    assert event["request_id"]


def test_one_event_per_import_rejection(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    response = client.post(
        "/documents/import",
        headers=auth("uma-aurora"),
        files={"file": ("bad.zip", traversing_archive(), "application/zip")},
    )
    assert response.status_code == 400
    events = _events(capsys.readouterr().out)
    assert len(events) == 1
    assert events[0]["operation"] == "import"


def test_no_event_for_benign_missing(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    # A confined-but-missing name is an ordinary not-found, not a security rejection.
    response = read_document(client, "uma-aurora", "statement-2099-01.txt")
    assert response.status_code == 404
    assert _events(capsys.readouterr().out) == []


def test_audit_leaks_nothing_sensitive(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    read_document(client, "uma-aurora", "../../config/integration.key")
    read_document(client, "uma-aurora", "/etc/passwd")
    client.post(
        "/documents/import",
        headers=auth("uma-aurora"),
        files={"file": ("bad.zip", traversing_archive(), "application/zip")},
    )
    lowered = capsys.readouterr().out.lower()
    forbidden = [
        "integration",  # the traversal target filename
        "config/",  # the escape directory
        "branding",  # the write target
        "/etc",  # absolute target
        "passwd",
        "/data",  # base / absolute path
        "/archive",
        "sentinel",
        "demo-token",  # bearer token material
        "authorization",
        "bearer",
    ]
    for needle in forbidden:
        assert needle not in lowered, f"audit output leaked {needle!r}"
