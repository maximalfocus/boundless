"""The intentionally vulnerable boundless application — read direction.

This package exists only to demonstrate what the secure baseline refuses. It is opt-in
(a Compose profile plus an explicit ``ALLOW_VULNERABLE_DEMO=true`` acknowledgement), runs
in a hardened, egress-blocked container, and must never be deployed.
"""

from .app import create_vulnerable_app

__all__ = ["create_vulnerable_app"]
