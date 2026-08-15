"""The secure statement-archive API.

Every endpoint that accepts a user-supplied name funnels it through
:func:`boundless.safepath.confine`; the catalog endpoint accepts no path component at
all. Failures are reported generically so no response distinguishes "outside the base"
from "does not exist".
"""

from __future__ import annotations

import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse

from ..archive import apply_extraction, plan_secure_extraction
from ..audit import emit_rejection
from ..config import Settings, load_settings
from ..identity import User
from ..safepath import ConfinementError, confine
from ..webcommon import (
    app_state,
    build_app_state,
    get_request_id,
    require_user,
    statements_summary_payload,
)


def create_secure_app(settings: Settings | None = None) -> FastAPI:
    """Build the secure FastAPI application.

    Fixtures are rebuilt and the catalog reconstructed on startup so every process boots
    from fresh, deterministic state.
    """
    resolved_settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.boundless = build_app_state(resolved_settings)
        yield

    app = FastAPI(
        title="boundless (secure)",
        summary="Secure statement archive — resolve-and-confine path handling.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "app": "secure"}

    @app.get("/documents", response_class=PlainTextResponse)
    def get_document(
        request: Request,
        name: str,
        user: Annotated[User, Depends(require_user)],
        request_id: Annotated[str, Depends(get_request_id)],
    ) -> PlainTextResponse:
        """Retrieve a document by name, resolving and confining before opening."""
        base = app_state(request).settings.tenant_base(user.tenant_id)
        try:
            target = confine(base, name)
        except ConfinementError:
            emit_rejection(
                request_id=request_id,
                actor=user.id,
                tenant=user.tenant_id,
                operation="retrieve",
            )
            raise HTTPException(status_code=404, detail="Not Found") from None
        try:
            data = target.read_bytes()
        except OSError:
            # Confined but missing (or not a file): an ordinary not-found. Same generic
            # 404, and — because this is not a security rejection — no audit event.
            raise HTTPException(status_code=404, detail="Not Found") from None
        return PlainTextResponse(content=data)

    @app.get("/documents/{document_id}", response_class=PlainTextResponse)
    def get_document_by_id(
        request: Request,
        document_id: str,
        user: Annotated[User, Depends(require_user)],
    ) -> PlainTextResponse:
        """Retrieve a document by opaque catalog id — no path component is accepted."""
        state = app_state(request)
        entry = state.catalog.get(document_id)
        if entry is None or entry.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Not Found")
        location = state.settings.tenant_base(entry.tenant_id) / entry.filename
        try:
            data = location.read_bytes()
        except OSError:
            raise HTTPException(status_code=404, detail="Not Found") from None
        return PlainTextResponse(content=data)

    @app.post("/documents/import")
    async def import_archive(
        request: Request,
        file: Annotated[UploadFile, File()],
        user: Annotated[User, Depends(require_user)],
        request_id: Annotated[str, Depends(get_request_id)],
    ) -> dict[str, list[str]]:
        """Import a zip into the caller's tenant directory, all-or-nothing."""
        base = app_state(request).settings.tenant_base(user.tenant_id)
        raw = await file.read()
        try:
            planned = plan_secure_extraction(base, raw)
        except (ConfinementError, zipfile.BadZipFile):
            emit_rejection(
                request_id=request_id,
                actor=user.id,
                tenant=user.tenant_id,
                operation="import",
            )
            raise HTTPException(status_code=400, detail="Bad Request") from None
        imported = apply_extraction(base, planned)
        return {"imported": imported}

    @app.get("/statements/summary")
    def statements_summary(
        request: Request,
        user: Annotated[User, Depends(require_user)],
    ) -> dict[str, object]:
        """Render the tenant's statement summary; footer read at request time."""
        return statements_summary_payload(app_state(request).settings, user)

    return app
