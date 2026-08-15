"""A directly testable scenario engine for the secure baseline.

The engine takes an ``httpx.Client`` (real network or in-process transport) and exercises
the secure and legitimate behaviour, returning structured, checkable results. It performs
no terminal input, so tests drive it exactly as the CLI does.

Each :class:`Check` records what was submitted, what the boundary did, and whether the
observed outcome matched the security expectation.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from .fixtures import DEMO_SENTINEL
from .identity import USERS_BY_ID
from .samples import TRAVERSING_MEMBER, WELL_FORMED_MEMBER, traversing_archive, well_formed_archive

ATTACKER = USERS_BY_ID["uma-aurora"]


@dataclass(frozen=True)
class Check:
    """One observed step of the walkthrough."""

    group: str
    name: str
    submitted: str
    expectation: str
    observed: str
    passed: bool


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _get_document(client: httpx.Client, token: str, name: str) -> httpx.Response:
    # Pass the raw name straight into the query string so encoded payloads reach the app
    # exactly as written rather than being re-encoded by the client helper.
    return client.get(f"/documents?name={name}", headers=_auth(token))


def run_secure_baseline(client: httpx.Client) -> list[Check]:
    """Run the secure + legitimate walkthrough and return per-step results."""
    checks: list[Check] = []

    def record(
        group: str, name: str, submitted: str, expectation: str, observed: str, passed: bool
    ) -> None:
        checks.append(Check(group, name, submitted, expectation, observed, passed))

    # --- Legitimate behaviour ------------------------------------------------------
    own = _get_document(client, ATTACKER.token, "statement-2026-07.txt")
    record(
        "legitimate",
        "own statement",
        "statement-2026-07.txt",
        "200 with the caller's own statement",
        f"{own.status_code}",
        own.status_code == 200 and "Aurora Freight" in own.text,
    )

    summary = client.get("/statements/summary", headers=_auth(ATTACKER.token))
    footer_before = summary.json().get("footer", "") if summary.status_code == 200 else ""
    record(
        "legitimate",
        "statement summary",
        "GET /statements/summary",
        "200, footer read from branding.conf",
        f"{summary.status_code} footer={footer_before!r}",
        summary.status_code == 200 and footer_before != "" and "OWNED" not in footer_before,
    )

    # --- Secure rejections (all indistinguishable 404) -----------------------------
    rejections = [
        ("cross-tenant", "../northwind-mills/statement-2026-07.txt"),
        ("archive-root escape", "../../config/integration.key"),
        ("absolute path", "/etc/passwd"),
        ("planted symlink", "vault-link"),
        ("percent-encoded", "%2e%2e%2fintegration.key"),
        ("double-encoded", "%252e%252e%252fintegration.key"),
        ("well-formed but missing", "statement-2099-01.txt"),
    ]
    for name, payload in rejections:
        response = _get_document(client, ATTACKER.token, payload)
        leaked = DEMO_SENTINEL.split("=", 1)[1] in response.text or "root:" in response.text
        record(
            "secure-read",
            name,
            payload,
            "generic 404, nothing disclosed",
            f"{response.status_code}",
            response.status_code == 404 and not leaked,
        )

    # --- Catalog-id indirection ----------------------------------------------------
    unknown = client.get("/documents/doc-does-not-exist", headers=_auth(ATTACKER.token))
    record(
        "secure-read",
        "catalog id unknown",
        "GET /documents/doc-does-not-exist",
        "generic 404",
        f"{unknown.status_code}",
        unknown.status_code == 404,
    )

    # --- Secure import: well-formed accepted, traversing rejected as a whole --------
    good = client.post(
        "/documents/import",
        headers=_auth(ATTACKER.token),
        files={"file": ("good.zip", well_formed_archive(), "application/zip")},
    )
    record(
        "secure-import",
        "well-formed import",
        WELL_FORMED_MEMBER,
        "200, member imported into own directory",
        f"{good.status_code} {good.json() if good.status_code == 200 else ''}",
        good.status_code == 200 and WELL_FORMED_MEMBER in good.json().get("imported", []),
    )

    bad = client.post(
        "/documents/import",
        headers=_auth(ATTACKER.token),
        files={"file": ("bad.zip", traversing_archive(), "application/zip")},
    )
    record(
        "secure-import",
        "traversing import rejected",
        TRAVERSING_MEMBER,
        "generic 400, no entry written",
        f"{bad.status_code}",
        bad.status_code == 400,
    )

    after = client.get("/statements/summary", headers=_auth(ATTACKER.token))
    footer_after = after.json().get("footer", "") if after.status_code == 200 else ""
    record(
        "secure-import",
        "footer unchanged after rejection",
        "GET /statements/summary",
        "footer identical to before the rejected import",
        f"footer={footer_after!r}",
        footer_after == footer_before and "OWNED" not in footer_after,
    )

    # --- Authentication ------------------------------------------------------------
    for name, headers in (
        ("missing", {}),
        ("malformed", {"Authorization": "Token nope"}),
        ("unknown", {"Authorization": "Bearer demo-token-unknown"}),
    ):
        response = client.get("/documents?name=statement-2026-07.txt", headers=headers)
        record(
            "auth",
            name,
            f"Authorization={headers.get('Authorization', '<none>')}",
            "generic 401 with bearer challenge",
            f"{response.status_code}",
            response.status_code == 401 and response.headers.get("www-authenticate") == "Bearer",
        )

    return checks


def all_passed(checks: list[Check]) -> bool:
    """True when every recorded check met its expectation."""
    return all(check.passed for check in checks)
