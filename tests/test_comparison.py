"""The read-comparison engine (which the `compare` CLI drives) passes end-to-end."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.comparison import all_passed, run_comparison


def test_read_comparison_all_pass(both_clients: tuple[TestClient, TestClient]) -> None:
    secure, vulnerable = both_clients
    rows = run_comparison(secure, vulnerable)
    failed = [
        f"{r.group}/{r.name}: secure={r.secure_observed} vulnerable={r.vulnerable_observed}"
        for r in rows
        if not r.passed
    ]
    assert not failed, failed
    assert all_passed(rows)
    assert {r.group for r in rows} == {"traversal", "parity"}
    # 6 traversal rungs + 2 parity rows.
    assert len(rows) == 8


def test_secure_refuses_every_traversal_row(
    both_clients: tuple[TestClient, TestClient],
) -> None:
    secure, vulnerable = both_clients
    rows = run_comparison(secure, vulnerable)
    for row in rows:
        if row.group == "traversal":
            assert "refused" in row.secure_observed
            assert "crossed=True" in row.vulnerable_observed
