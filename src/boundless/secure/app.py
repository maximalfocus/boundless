"""The secure statement-archive API.

Every endpoint that accepts a user-supplied name funnels it through
:func:`boundless.safepath.confine`; the catalog endpoint accepts no path component at
all. Failures are reported generically so no response distinguishes "outside the base"
from "does not exist".
"""

from __future__ import annotations

import uuid
import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse

from ..archive import apply_extraction, plan_secure_extraction
from ..audit import emit_rejection
from ..catalog import Catalog
from ..config import Settings, load_settings
from ..fixtures import branding_footer, build_fixtures, statement_names
from ..identity import User, user_for_token
from ..safepath import ConfinementError, confine

_BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}


@dataclass
class AppState:
    """Objects shared across requests, rebuilt on startup."""

    settings: Settings
    catalog: Catalog


def _state(request: Request) -> AppState:
    return request.app.state.boundless  # type: ignore[no-any-return]


def get_request_id(request: Request) -> str:
    """Correlation id from the caller's header, or a fresh one."""
    return request.headers.get("x-request-id") or uuid.uuid4().hex


def require_user(authorization: Annotated[str | None, Header()] = None) -> User:
    """Authenticate a demo bearer token to exactly one user, or fail generically."""
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized", headers=_BEARER_CHALLENGE)
    user = user_for_token(authorization.removeprefix("Bearer ").strip())
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized", headers=_BEARER_CHALLENGE)
    return user


def create_secure_app(settings: Settings | None = None) -> FastAPI:
    """Build the secure FastAPI application.

    Fixtures are rebuilt and the catalog reconstructed on startup so every process boots
    from fresh, deterministic state.
    """
    resolved_settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        build_fixtures(resolved_settings)
        app.state.boundless = AppState(
            settings=resolved_settings,
            catalog=Catalog.from_fixtures(resolved_settings),
        )
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
        base = _state(request).settings.tenant_base(user.tenant_id)
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
        state = _state(request)
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
        base = _state(request).settings.tenant_base(user.tenant_id)
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
        state = _state(request)
        base = state.settings.tenant_base(user.tenant_id)
        names = statement_names(base)
        return {
            "tenant": user.tenant_id,
            "count": len(names),
            "statements": names,
            "footer": branding_footer(state.settings),
        }

    return app
