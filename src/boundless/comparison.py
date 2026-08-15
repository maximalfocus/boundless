"""Directly testable vulnerable-vs-secure read comparison.

Given a secure client and a vulnerable client (real network or in-process transport), run
the traversal ladder against both and record the contrast: the vulnerable app crosses the
boundary while the secure app refuses with an indistinguishable 404, and both apps agree
on legitimate requests. The CLI renders these rows; tests assert over them.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from .fixtures import DEMO_SENTINEL
from .identity import USERS_BY_ID
from .samples import ATTACKER_FOOTER, zip_slip_write_archive

ATTACKER = USERS_BY_ID["uma-aurora"]
VICTIM = USERS_BY_ID["nils-northwind"]
SENTINEL_VALUE = DEMO_SENTINEL.split("=", 1)[1]


@dataclass(frozen=True)
class Row:
    """One comparison row: what each app did with the same input."""

    group: str  # "traversal" | "parity"
    name: str
    submitted: str
    secure_observed: str
    vulnerable_observed: str
    verdict: str
    passed: bool


@dataclass(frozen=True)
class _Rung:
    name: str
    endpoint: str  # "naive" | "hardened"
    submitted: str
    marker: str  # out-of-bounds content proving the boundary was crossed


LADDER: tuple[_Rung, ...] = (
    _Rung("cross-tenant", "naive", "../northwind-mills/statement-2026-07.txt", "Northwind Mills"),
    _Rung("archive-root escape", "naive", "../../config/integration.key", SENTINEL_VALUE),
    _Rung("absolute-path override", "naive", "/etc/passwd", "root:"),
    _Rung("symlink escape", "naive", "vault-link", SENTINEL_VALUE),
    _Rung(
        "broken sanitizer ....//",
        "hardened",
        "....//....//config/integration.key",
        SENTINEL_VALUE,
    ),
    _Rung(
        "broken sanitizer %2e%2e (encoded)",
        "hardened",
        "%2e%2e%2f%2e%2e%2fconfig%2fintegration.key",
        SENTINEL_VALUE,
    ),
)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {ATTACKER.token}"}


def _secure_read(secure: httpx.Client, submitted: str) -> httpx.Response:
    return secure.get(f"/documents?name={submitted}", headers=_auth())


def _vulnerable_read(vulnerable: httpx.Client, endpoint: str, submitted: str) -> httpx.Response:
    path = "/documents" if endpoint == "naive" else "/documents/hardened"
    return vulnerable.get(f"{path}?name={submitted}", headers=_auth())


def run_comparison(secure: httpx.Client, vulnerable: httpx.Client) -> list[Row]:
    """Run the traversal ladder and the legitimate-parity checks against both apps."""
    rows: list[Row] = []

    for rung in LADDER:
        secure_response = _secure_read(secure, rung.submitted)
        vuln_response = _vulnerable_read(vulnerable, rung.endpoint, rung.submitted)
        crossed = vuln_response.status_code == 200 and rung.marker in vuln_response.text
        landed = vuln_response.headers.get("x-boundless-opened", "")
        secure_refused = secure_response.status_code == 404
        secure_observed = (
            f"{secure_response.status_code} (refused)"
            if secure_refused
            else f"{secure_response.status_code} (LEAK!)"
        )
        vuln_observed = f"{vuln_response.status_code} crossed={crossed} landed={landed}"
        rows.append(
            Row(
                group="traversal",
                name=f"{rung.name} [{rung.endpoint}]",
                submitted=rung.submitted,
                secure_observed=secure_observed,
                vulnerable_observed=vuln_observed,
                verdict="secure refuses; vulnerable crosses the boundary",
                passed=secure_refused and crossed,
            )
        )

    rows.extend(_parity_rows(secure, vulnerable))
    return rows


def _parity_rows(secure: httpx.Client, vulnerable: httpx.Client) -> list[Row]:
    rows: list[Row] = []

    benign = "statement-2026-07.txt"
    s_doc = _secure_read(secure, benign)
    v_doc = _vulnerable_read(vulnerable, "naive", benign)
    same_doc = s_doc.status_code == 200 and v_doc.status_code == 200 and s_doc.text == v_doc.text
    rows.append(
        Row(
            group="parity",
            name="benign retrieval",
            submitted=benign,
            secure_observed=f"{s_doc.status_code}",
            vulnerable_observed=f"{v_doc.status_code}",
            verdict="both apps return identical content",
            passed=same_doc,
        )
    )

    s_sum = secure.get("/statements/summary", headers=_auth())
    v_sum = vulnerable.get("/statements/summary", headers=_auth())
    same_sum = (
        s_sum.status_code == 200 and v_sum.status_code == 200 and s_sum.json() == v_sum.json()
    )
    rows.append(
        Row(
            group="parity",
            name="statement summary",
            submitted="GET /statements/summary",
            secure_observed=f"{s_sum.status_code}",
            vulnerable_observed=f"{v_sum.status_code}",
            verdict="both apps return identical summary",
            passed=same_sum,
        )
    )
    return rows


def _victim_auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {VICTIM.token}"}


def _summary_footer(client: httpx.Client, headers: dict[str, str]) -> str:
    response = client.get("/statements/summary", headers=headers)
    return response.json().get("footer", "") if response.status_code == 200 else ""


def _read_text(client: httpx.Client, headers: dict[str, str], name: str) -> str:
    response = client.get(f"/documents?name={name}", headers=headers)
    return response.text if response.status_code == 200 else ""


def run_write_demo(secure: httpx.Client, vulnerable: httpx.Client) -> list[Row]:
    """Zip-Slip write escape, observed through the normal boundary, both apps.

    Requires the two apps to have independent state (as they do as separate containers);
    tests pass isolated clients. The write escape overwrites the branding config (seen via
    a later legitimate summary) and one other tenant's statement (seen via that tenant's
    own read); the secure app rejects the identical archive whole and stays intact.
    """
    rows: list[Row] = []
    footer_before = _summary_footer(vulnerable, _auth())
    victim_before = _read_text(vulnerable, _victim_auth(), "statement-2026-07.txt")

    imported = vulnerable.post(
        "/documents/import",
        headers=_auth(),
        files={"file": ("slip.zip", zip_slip_write_archive(), "application/zip")},
    )
    count = len(imported.json().get("imported", [])) if imported.status_code == 200 else 0
    rows.append(
        Row(
            group="write",
            name="vulnerable Zip-Slip import",
            submitted="../../config/branding.conf + ../northwind-mills/statement-2026-07.txt",
            secure_observed="n/a",
            vulnerable_observed=f"{imported.status_code} wrote {count} entries outside the dir",
            verdict="entries written outside the extraction directory",
            passed=imported.status_code == 200 and count == 2,
        )
    )

    footer_after = _summary_footer(vulnerable, _auth())
    rows.append(
        Row(
            group="write",
            name="branding footer tampered (via legitimate summary)",
            submitted="GET /statements/summary",
            secure_observed="footer unchanged",
            vulnerable_observed=f"before={footer_before!r} after={footer_after!r}",
            verdict="the overwrite returns through a later legitimate request",
            passed=ATTACKER_FOOTER in footer_after and ATTACKER_FOOTER not in footer_before,
        )
    )

    victim_after = _read_text(vulnerable, _victim_auth(), "statement-2026-07.txt")
    rows.append(
        Row(
            group="write",
            name="cross-tenant document overwritten",
            submitted="northwind-mills reads its own statement-2026-07.txt",
            secure_observed="untouched",
            vulnerable_observed=f"changed={victim_before != victim_after}",
            verdict="another tenant's document was overwritten",
            passed=victim_before != victim_after and "OVERWRITTEN" in victim_after,
        )
    )

    secure_import = secure.post(
        "/documents/import",
        headers=_auth(),
        files={"file": ("slip.zip", zip_slip_write_archive(), "application/zip")},
    )
    secure_footer = _summary_footer(secure, _auth())
    rows.append(
        Row(
            group="write",
            name="secure rejects the same archive",
            submitted="POST /documents/import (same Zip-Slip archive)",
            secure_observed=f"{secure_import.status_code} (rejected whole)",
            vulnerable_observed="200 (wrote the entries)",
            verdict="secure: all-or-nothing 400, nothing written, footer intact",
            passed=secure_import.status_code == 400 and ATTACKER_FOOTER not in secure_footer,
        )
    )
    return rows


def all_passed(rows: list[Row]) -> bool:
    return all(row.passed for row in rows)
