"""The primary fix: **resolve, then confine**.

Joining a user-supplied name to a base directory proves nothing about where the joined
path *lands*. The only reliable question is: after the candidate path is fully resolved
(``.`` and ``..`` collapsed, symlinks followed), is it still inside the *resolved* base?

:func:`confine` answers exactly that question and is applied identically to a read lookup
and to every archive entry before it is written. The contrast this demo teaches is that
the vulnerable code (added in later slices) joins and opens without ever calling this.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class ConfinementError(Exception):
    """A candidate path could not be safely confined to its base directory.

    The message names a coarse *category* only. Callers must translate this into a
    generic response (a 404 for reads, a 400 for imports) so it never becomes an oracle
    that distinguishes "outside the base" from "does not exist".
    """


@dataclass(frozen=True)
class ArchiveEntry:
    """A single archive member, described by name and its stored unix mode.

    ``mode`` is the high 16 bits of the zip ``external_attr`` field, i.e. the unix
    ``st_mode``. It is ``0`` for archives written without explicit permissions, which we
    treat as an ordinary regular file.
    """

    name: str
    mode: int
    is_dir: bool


def _reject_absolute_or_nul(name: str) -> None:
    if "\x00" in name:
        raise ConfinementError("nul-byte")
    if name.startswith("/") or PurePosixPath(name).is_absolute():
        raise ConfinementError("absolute")
    # A Windows-style drive or backslash root is meaningless here but still refused.
    if "\\" in name and name.split("\\", 1)[0].endswith(":"):
        raise ConfinementError("absolute")


def confine(base: Path, name: str) -> Path:
    """Resolve ``name`` under ``base`` and require the result to stay inside it.

    Steps, in order:

    1. reject an absolute or NUL-bearing name outright;
    2. resolve ``base`` to a real location (it must exist);
    3. join the decoded ``name`` and resolve the result, collapsing ``.``/``..`` and
       following symlinks;
    4. require the resolved target to be inside the resolved base.

    Returns the resolved, confined path. Raises :class:`ConfinementError` on any failure.
    Note this proves only *location*; the caller still handles a confined-but-missing
    file as an ordinary not-found, with the same generic response.
    """
    _reject_absolute_or_nul(name)

    base_resolved = base.resolve(strict=True)
    target_resolved = (base_resolved / name).resolve(strict=False)

    if target_resolved != base_resolved and not target_resolved.is_relative_to(base_resolved):
        raise ConfinementError("outside-base")
    return target_resolved


def confine_entry(base: Path, entry: ArchiveEntry) -> Path:
    """Validate a single archive entry for a secure, all-or-nothing extraction.

    Beyond :func:`confine`, an archive member must also be a *regular file*: symbolic
    and hard links and every other special type are refused, since a link entry is the
    filesystem equivalent of a traversal that ``confine`` alone would not catch once
    written. Directory entries are refused as non-regular-file structure; the shipped
    well-formed archives carry flat regular-file members only.
    """
    if entry.is_dir or entry.name.endswith("/"):
        raise ConfinementError("directory-entry")
    # The stored mode's *type* bits decide regularity. Many tools (including Python's
    # own ``writestr``) record permission bits only, leaving the type field zero; that
    # absence means an ordinary file. Only explicit link/dir/device/special type bits —
    # a symlink entry, most dangerously — are refused.
    file_type = stat.S_IFMT(entry.mode)
    if file_type not in (0, stat.S_IFREG):
        raise ConfinementError("non-regular-entry")
    return confine(base, entry.name)
