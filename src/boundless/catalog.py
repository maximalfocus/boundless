"""Opaque catalog-id indirection — the strongest control.

Addressing a document by an opaque identifier that the server maps to a stored location
means **no user-supplied path component participates in locating the file at all**. This
removes the traversal class rather than checking for it. Resolve-and-confine
(:mod:`boundless.safepath`) is what you do when a filename genuinely must be accepted.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .config import Settings
from .fixtures import statement_names
from .identity import TENANTS


@dataclass(frozen=True)
class CatalogEntry:
    """A stored document location addressed by an opaque id."""

    document_id: str
    tenant_id: str
    filename: str


def _document_id(tenant_id: str, filename: str) -> str:
    digest = hashlib.sha256(f"{tenant_id}/{filename}".encode()).hexdigest()
    return f"doc-{digest[:16]}"


class Catalog:
    """An in-memory map of opaque document id to stored location.

    Built by scanning the freshly created fixture tree. Because ids are derived from a
    stable hash of ``tenant/filename`` they are deterministic across runs yet carry no
    traversable path component.
    """

    def __init__(self, entries: tuple[CatalogEntry, ...]) -> None:
        self._by_id: dict[str, CatalogEntry] = {e.document_id: e for e in entries}

    @classmethod
    def from_fixtures(cls, settings: Settings) -> Catalog:
        entries: list[CatalogEntry] = []
        for tenant in TENANTS:
            base = settings.tenant_base(tenant.id)
            for filename in statement_names(base):
                entries.append(
                    CatalogEntry(
                        document_id=_document_id(tenant.id, filename),
                        tenant_id=tenant.id,
                        filename=filename,
                    )
                )
        return cls(tuple(entries))

    def get(self, document_id: str) -> CatalogEntry | None:
        """Return the entry for an id, or ``None`` when the id is unknown."""
        return self._by_id.get(document_id)

    def for_tenant(self, tenant_id: str) -> list[CatalogEntry]:
        """Entries owned by a tenant, sorted by filename (for documentation/tests)."""
        return sorted(
            (e for e in self._by_id.values() if e.tenant_id == tenant_id),
            key=lambda e: e.filename,
        )
