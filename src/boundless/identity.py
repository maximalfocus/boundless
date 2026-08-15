"""Fictional tenants, users, and demo-only bearer tokens.

None of these values are real. The tokens are unmistakably demonstration strings; they
map one-to-one to a user and thereby to exactly one tenant.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tenant:
    """A fictional organization renting the statement-archive service."""

    id: str
    name: str


@dataclass(frozen=True)
class User:
    """A fictional user belonging to exactly one tenant."""

    id: str
    display_name: str
    tenant_id: str
    token: str


TENANTS: tuple[Tenant, ...] = (
    Tenant(id="aurora-freight", name="Aurora Freight Collective"),
    Tenant(id="northwind-mills", name="Northwind Mills"),
    Tenant(id="borealis-supply", name="Borealis Supply Co."),
)

USERS: tuple[User, ...] = (
    # The "attacker tenant" actor in the walkthrough is Uma of Aurora Freight.
    User(
        id="uma-aurora",
        display_name="Uma Restrepo",
        tenant_id="aurora-freight",
        token="demo-token-aurora-uma-NOT-A-REAL-SECRET",
    ),
    User(
        id="nils-northwind",
        display_name="Nils Overgaard",
        tenant_id="northwind-mills",
        token="demo-token-northwind-nils-NOT-A-REAL-SECRET",
    ),
    User(
        id="bex-borealis",
        display_name="Bex Alanguyen",
        tenant_id="borealis-supply",
        token="demo-token-borealis-bex-NOT-A-REAL-SECRET",
    ),
)

TENANTS_BY_ID: dict[str, Tenant] = {t.id: t for t in TENANTS}
USERS_BY_TOKEN: dict[str, User] = {u.token: u for u in USERS}
USERS_BY_ID: dict[str, User] = {u.id: u for u in USERS}


def user_for_token(token: str) -> User | None:
    """Return the user a demo bearer token maps to, or ``None`` if unknown."""
    return USERS_BY_TOKEN.get(token)
