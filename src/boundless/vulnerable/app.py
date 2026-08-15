"""The intentionally vulnerable statement-archive API (read direction).

Two retrieval endpoints demonstrate the class:

- ``GET /documents`` joins the user-supplied name to the tenant base and opens the
  result — no resolution, no confinement (FR-010).
- ``GET /documents/hardened`` pretends to defend by stripping ``../`` once from the raw,
  undecoded input before joining — a blocklist that is *not* a boundary check, defeated by
  ``....//`` (which collapses back into ``../``) and by ``%2e%2e%2f`` (which is only
  decoded after the check) (FR-011).

Both surface the absolute path they opened via ``X-Boundless-Opened`` so the "joined,
never checked" mechanism is legible. The app refuses to start unless the caller has
explicitly acknowledged running deliberately insecure code.
"""

from __future__ import annotations

import os
import urllib.parse
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

from ..config import Settings, load_settings
from ..identity import User
from ..webcommon import app_state, build_app_state, require_user, statements_summary_payload

ACK_ENV = "ALLOW_VULNERABLE_DEMO"


def _acknowledged(explicit: bool | None) -> bool:
    if explicit is not None:
        return explicit
    return os.environ.get(ACK_ENV) == "true"


def raw_query_value(request: Request, key: str) -> str:
    """Return the *raw, undecoded* value of a query key (or empty string).

    Reading the undecoded query is exactly what lets the broken sanitizer inspect a string
    before it is percent-decoded — the flaw the ``hardened`` endpoint demonstrates.
    """
    prefix = f"{key}="
    for pair in request.url.query.split("&"):
        if pair.startswith(prefix):
            return pair[len(prefix) :]
    return ""


def _open_by_join(base: Path, name: str) -> tuple[bytes, str]:
    """Join ``name`` to ``base`` and open it — the vulnerable primitive.

    ``os.path.join`` discards the base entirely when ``name`` is absolute (CWE-36), and the
    open follows ``..`` and symlinks straight out of the base (CWE-23/CWE-59). Returns the
    bytes read and the joined path that was opened.
    """
    joined = os.path.join(str(base), name)  # the vulnerable join: no resolution, no check
    return Path(joined).read_bytes(), joined


def create_vulnerable_app(
    settings: Settings | None = None, *, acknowledged: bool | None = None
) -> FastAPI:
    """Build the vulnerable app, refusing to start without explicit acknowledgement."""
    if not _acknowledged(acknowledged):
        raise RuntimeError(
            "Refusing to start the intentionally vulnerable boundless app. "
            f"Set {ACK_ENV}=true to acknowledge you are running deliberately insecure "
            "educational code locally."
        )
    resolved_settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.boundless = build_app_state(resolved_settings)
        yield

    app = FastAPI(
        title="boundless (VULNERABLE — do not deploy)",
        summary="Intentionally vulnerable statement archive — naive join, no confinement.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "app": "vulnerable"}

    @app.get("/documents", response_class=PlainTextResponse)
    def get_document(
        request: Request,
        name: str,
        user: Annotated[User, Depends(require_user)],
    ) -> PlainTextResponse:
        """Naive base-join retrieval — no resolution, no confinement check."""
        base = app_state(request).settings.tenant_base(user.tenant_id)
        try:
            data, joined = _open_by_join(base, name)
        except OSError:
            raise HTTPException(status_code=404, detail="Not Found") from None
        return PlainTextResponse(content=data, headers={"X-Boundless-Opened": joined})

    @app.get("/documents/hardened", response_class=PlainTextResponse)
    def get_document_hardened(
        request: Request,
        user: Annotated[User, Depends(require_user)],
    ) -> PlainTextResponse:
        """The 'hardened' retrieval — single-pass ``../`` strip on raw undecoded input."""
        raw = raw_query_value(request, "name")
        sanitized = raw.replace("../", "")  # the broken "fix": one pass, before decoding
        decoded = urllib.parse.unquote(sanitized)
        base = app_state(request).settings.tenant_base(user.tenant_id)
        try:
            data, joined = _open_by_join(base, decoded)
        except OSError:
            raise HTTPException(status_code=404, detail="Not Found") from None
        return PlainTextResponse(
            content=data,
            headers={"X-Boundless-Opened": joined, "X-Boundless-Sanitized": sanitized},
        )

    @app.get("/statements/summary")
    def statements_summary(
        request: Request,
        user: Annotated[User, Depends(require_user)],
    ) -> dict[str, object]:
        """Identical to the secure app — proves legitimate parity."""
        return statements_summary_payload(app_state(request).settings, user)

    return app
