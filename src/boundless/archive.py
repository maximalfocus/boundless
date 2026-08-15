"""Zip parsing and the secure, all-or-nothing extraction planner.

The secure importer validates **every** entry before a single byte is written, so a
rejected archive leaves the tenant directory byte-for-byte unchanged. The realistic
vulnerable pattern — a hand-rolled per-entry write loop that joins and writes without
this check — is introduced in a later slice; keeping the secure planner here makes the
contrast a matter of which function the app calls.

Note that Python's high-level ``ZipFile.extractall`` already sanitizes member names; the
teaching point of the vulnerable variant is precisely the hand-rolled loop that skips
that sanitization.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from .safepath import ArchiveEntry, confine_entry


def entry_of(info: zipfile.ZipInfo) -> ArchiveEntry:
    """Describe a zip member by name and its stored unix mode."""
    mode = (info.external_attr >> 16) & 0xFFFF
    return ArchiveEntry(name=info.filename, mode=mode, is_dir=info.is_dir())


def plan_secure_extraction(base: Path, raw: bytes) -> list[tuple[Path, bytes]]:
    """Validate all members and return the writes to perform, or raise.

    Raises :class:`~boundless.safepath.ConfinementError` if any entry is absolute,
    traversing, a link, or otherwise not a regular file, and :class:`zipfile.BadZipFile`
    if the payload is not a valid archive. Because nothing is written here, a raised
    exception guarantees an unchanged directory.
    """
    planned: list[tuple[Path, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            target = confine_entry(base, entry_of(info))
            planned.append((target, archive.read(info)))
    return planned


def apply_extraction(base: Path, planned: list[tuple[Path, bytes]]) -> list[str]:
    """Write already-validated entries and return their names relative to ``base``."""
    base_resolved = base.resolve(strict=True)
    written: list[str] = []
    for target, content in planned:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        written.append(str(target.relative_to(base_resolved)))
    return sorted(written)
