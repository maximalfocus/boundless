"""Legitimate parity: the two apps return identical results for benign inputs."""

from __future__ import annotations

from fastapi.testclient import TestClient

from helpers import auth


def test_benign_retrieval_is_identical(both_clients: tuple[TestClient, TestClient]) -> None:
    secure, vulnerable = both_clients
    params = {"name": "statement-2026-07.txt"}
    s = secure.get("/documents", params=params, headers=auth("uma-aurora"))
    v = vulnerable.get("/documents", params=params, headers=auth("uma-aurora"))
    assert s.status_code == v.status_code == 200
    assert s.text == v.text


def test_summary_is_identical(both_clients: tuple[TestClient, TestClient]) -> None:
    secure, vulnerable = both_clients
    s = secure.get("/statements/summary", headers=auth("uma-aurora"))
    v = vulnerable.get("/statements/summary", headers=auth("uma-aurora"))
    assert s.status_code == v.status_code == 200
    assert s.json() == v.json()
