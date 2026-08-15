"""Unit tests for resolve-and-confine, the primary fix."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from boundless.config import Settings
from boundless.fixtures import build_fixtures
from boundless.safepath import ArchiveEntry, ConfinementError, confine, confine_entry


@pytest.fixture
def base(settings: Settings) -> Path:
    build_fixtures(settings)
    return settings.tenant_base("aurora-freight")


def test_confine_allows_own_file(base: Path) -> None:
    target = confine(base, "statement-2026-07.txt")
    assert target.is_relative_to(base.resolve())
    assert target.name == "statement-2026-07.txt"


def test_confine_allows_missing_but_inside(base: Path) -> None:
    # Location proof only: a confined-but-missing name still resolves inside the base.
    target = confine(base, "statement-2099-01.txt")
    assert target.is_relative_to(base.resolve())


@pytest.mark.parametrize(
    "name",
    [
        "../northwind-mills/statement-2026-07.txt",
        "../../config/integration.key",
        "/etc/passwd",
        "vault-link",
        "./../../config/integration.key",
    ],
)
def test_confine_rejects_escapes(base: Path, name: str) -> None:
    with pytest.raises(ConfinementError):
        confine(base, name)


def test_confine_rejects_nul(base: Path) -> None:
    with pytest.raises(ConfinementError):
        confine(base, "statement\x00.txt")


def test_confine_entry_rejects_symlink(base: Path) -> None:
    entry = ArchiveEntry(name="evil", mode=stat.S_IFLNK | 0o777, is_dir=False)
    with pytest.raises(ConfinementError):
        confine_entry(base, entry)


def test_confine_entry_rejects_directory(base: Path) -> None:
    with pytest.raises(ConfinementError):
        confine_entry(base, ArchiveEntry(name="nested/", mode=0, is_dir=True))


def test_confine_entry_rejects_traversing_name(base: Path) -> None:
    with pytest.raises(ConfinementError):
        confine_entry(base, ArchiveEntry(name="../../config/branding.conf", mode=0, is_dir=False))


def test_confine_entry_allows_regular_file(base: Path) -> None:
    target = confine_entry(base, ArchiveEntry(name="statement-2026-08.txt", mode=0, is_dir=False))
    assert target.is_relative_to(base.resolve())
