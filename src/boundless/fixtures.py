"""Deterministic, fictional fixture tree, recreated fresh on every start.

The content, counts, and ordering are stable across runs so the walkthrough is
reproducible. Every "secret" is a conspicuously fake demonstration value. Building the
tree only ever touches paths beneath ``settings.data_root``.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .config import Settings
from .identity import TENANTS

#: Marker planted in the out-of-root integration key. Seeing it in a response proves a
#: traversal reached outside the archive root.
DEMO_SENTINEL = "DEMO_SENTINEL=boundless-out-of-root-reach-CWE22"

#: The three monthly statements every tenant starts with.
STATEMENT_MONTHS = ("2026-05", "2026-06", "2026-07")

#: Tenant directory that carries the planted symlink escaping the archive root.
SYMLINK_TENANT = "aurora-freight"
SYMLINK_NAME = "vault-link"


def _statement_body(tenant_name: str, month: str, filename: str) -> str:
    return (
        "STATEMENT (synthetic demonstration data)\n"
        f"Tenant : {tenant_name}\n"
        f"Period : {month}\n"
        f"File   : {filename}\n"
        "Balance: 12,340.00 (fictional)\n"
        "No real account, person, or organization is represented.\n"
    )


def _integration_key_body() -> str:
    return (
        "# boundless demo integration key — FICTIONAL, not a real credential.\n"
        "INTEGRATION_KEY=demo-int-key-0000-1111-2222-boundless\n"
        f"{DEMO_SENTINEL}\n"
    )


def _branding_body() -> str:
    return "[branding]\nfooter = Statements provided by the shared demo archive.\n"


def statement_filename(month: str) -> str:
    """Canonical statement filename for a month, e.g. ``statement-2026-07.txt``."""
    return f"statement-{month}.txt"


def build_fixtures(settings: Settings) -> None:
    """Recreate the archive and config trees from scratch under the data root.

    Existing ``archive/`` and ``config/`` directories are removed first so no state
    persists between runs. This is confined to ``settings.data_root`` and never deletes
    anything outside it.
    """
    data_root = settings.data_root
    data_root.mkdir(parents=True, exist_ok=True)

    for subtree in (settings.archive_root, settings.config_dir):
        if subtree.exists() or subtree.is_symlink():
            shutil.rmtree(subtree)

    settings.archive_root.mkdir(parents=True)
    settings.config_dir.mkdir(parents=True)

    for tenant in TENANTS:
        tenant_dir = settings.tenant_base(tenant.id)
        tenant_dir.mkdir(parents=True)
        for month in STATEMENT_MONTHS:
            filename = statement_filename(month)
            (tenant_dir / filename).write_text(
                _statement_body(tenant.name, month, filename), encoding="utf-8"
            )

    settings.integration_key_path.write_text(_integration_key_body(), encoding="utf-8")
    settings.branding_conf_path.write_text(_branding_body(), encoding="utf-8")

    # A planted symlink inside a tenant directory whose target is outside the archive
    # root. Every textual component of "vault-link" stays inside the base; only after
    # following the link does the path escape (CWE-59). The secure app rejects it; the
    # vulnerable app (a later slice) follows it.
    link = settings.tenant_base(SYMLINK_TENANT) / SYMLINK_NAME
    target = os.path.relpath(settings.integration_key_path, link.parent)
    link.symlink_to(target)


def branding_footer(settings: Settings) -> str:
    """Read the branding footer from ``branding.conf`` at call time.

    Reading at request time is what makes a successful write escape (a later slice)
    observable through a subsequent *legitimate* statement-summary request.
    """
    for line in settings.branding_conf_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("footer") and "=" in stripped:
            return stripped.split("=", 1)[1].strip()
    return ""


def statement_names(base: Path) -> list[str]:
    """Sorted statement filenames directly inside a tenant base (symlinks excluded)."""
    return sorted(
        p.name for p in base.glob("statement-*.txt") if p.is_file() and not p.is_symlink()
    )
