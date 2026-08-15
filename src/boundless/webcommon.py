"""Shared web plumbing used by both the secure and the vulnerable applications.

Authentication, request correlation, fixture lifespan, and the statement-summary payload
are identical across the two apps — the *only* intended difference is how each locates a
file from a user-supplied name. Keeping the shared parts here makes that contrast the
single visible variable and guarantees legitimate parity (FR-009).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Header, HTTPException, Request

from .catalog import Catalog
from .config import Settings
from .fixtures import branding_footer, build_fixtures, statement_names
from .identity import User, user_for_token

BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}


@dataclass
class AppState:
    """Per-process objects, rebuilt on startup."""

    settings: Settings
    catalog: Catalog


def app_state(request: Request) -> AppState:
    return request.app.state.boundless  # type: ignore[no-any-return]


def get_request_id(request: Request) -> str:
    """Correlation id from the caller's header, or a fresh one."""
    return request.headers.get("x-request-id") or uuid.uuid4().hex


def require_user(authorization: Annotated[str | None, Header()] = None) -> User:
    """Authenticate a demo bearer token to exactly one user, or fail generically.

    Missing, malformed, and unknown credentials all receive the same generic 401 with the
    standard bearer challenge; tokens are never logged.
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized", headers=BEARER_CHALLENGE)
    user = user_for_token(authorization.removeprefix("Bearer ").strip())
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized", headers=BEARER_CHALLENGE)
    return user


def build_app_state(settings: Settings) -> AppState:
    """Recreate fixtures and the catalog, returning fresh application state.

    Called from each app's lifespan on startup so every process boots from fresh,
    deterministic state.
    """
    build_fixtures(settings)
    return AppState(settings=settings, catalog=Catalog.from_fixtures(settings))


def statements_summary_payload(settings: Settings, user: User) -> dict[str, object]:
    """The statement summary, identical for both apps; footer read at request time."""
    base = settings.tenant_base(user.tenant_id)
    names = statement_names(base)
    return {
        "tenant": user.tenant_id,
        "count": len(names),
        "statements": names,
        "footer": branding_footer(settings),
    }
