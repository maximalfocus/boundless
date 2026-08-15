"""Test helpers: auth headers, malicious archive builders, and a tree snapshot.

Building archives with absolute, traversing, symlink, and directory entries is
demonstration payload construction, not an exploit against any real system.
"""

from __future__ import annotations

import hashlib
import io
import stat
import zipfile
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from boundless.identity import USERS_BY_ID


def auth(user_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {USERS_BY_ID[user_id].token}"}


def read_document(client: TestClient, user_id: str, name: str) -> httpx.Response:
    response: httpx.Response = client.get(
        "/documents", params={"name": name}, headers=auth(user_id)
    )
    return response


def read_document_raw(client: TestClient, user_id: str, raw_query_value: str) -> httpx.Response:
    response: httpx.Response = client.get(
        f"/documents?name={raw_query_value}", headers=auth(user_id)
    )
    return response


def _zip(members: list[tuple[zipfile.ZipInfo | str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for info, body in members:
            archive.writestr(info, body)
    return buffer.getvalue()


def absolute_entry_archive() -> bytes:
    return _zip([(zipfile.ZipInfo("/etc/evil.txt"), b"absolute entry")])


def symlink_entry_archive(target: str = "../../config/integration.key") -> bytes:
    info = zipfile.ZipInfo("evil-link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return _zip([(info, target.encode())])


def directory_entry_archive() -> bytes:
    return _zip([("nested/", b""), ("nested/ok.txt", b"data")])


def snapshot_tree(root: Path) -> dict[str, str]:
    """Map every path under ``root`` to a content/type fingerprint.

    Symlinks are recorded by their target (not followed); files by a content hash; and
    directories by a marker. Comparing two snapshots proves byte-for-byte stability.
    """
    fingerprint: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            fingerprint[rel] = "symlink:" + str(path.readlink())
        elif path.is_dir():
            fingerprint[rel] = "dir"
        else:
            fingerprint[rel] = "file:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return fingerprint
