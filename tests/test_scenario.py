"""The scenario engine (which the CLI drives) passes end-to-end against the secure app."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.scenario import all_passed, run_secure_baseline


def test_secure_baseline_scenario_all_pass(client: TestClient) -> None:
    checks = run_secure_baseline(client)
    failed = [f"{c.group}/{c.name}: {c.observed}" for c in checks if not c.passed]
    assert not failed, failed
    assert all_passed(checks)
    # Sanity: the walkthrough actually exercised every group.
    groups = {c.group for c in checks}
    assert groups == {"legitimate", "secure-read", "secure-import", "auth"}
