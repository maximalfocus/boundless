"""Runtime configuration for the boundless demo.

Every path lives inside the container's data root (a disposable tmpfs in the shipped
Compose setup, a temporary directory under test). Nothing here reads or writes the host
filesystem.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

#: Default in-container data root. Overridden by ``BOUNDLESS_DATA_ROOT`` and by tests.
DEFAULT_DATA_ROOT = Path("/data")

#: Environment variable that relocates the data root (used by the test suite).
DATA_ROOT_ENV = "BOUNDLESS_DATA_ROOT"


@dataclass(frozen=True)
class Settings:
    """Resolved runtime paths for one demo process.

    The layout is deliberately shaped so the classic traversal ladder is expressible::

        <data_root>/
          archive/                 <- the common archive root
            <tenant>/              <- a tenant base directory (the join target)
              statement-*.txt
              vault-link           <- planted symlink, target outside the archive root
          config/                  <- outside the archive root, inside the data tree
            integration.key        <- fictional; carries DEMO_SENTINEL
            branding.conf          <- footer read when rendering a statement summary
    """

    data_root: Path

    @property
    def archive_root(self) -> Path:
        """The common root that holds every tenant's archive directory."""
        return self.data_root / "archive"

    @property
    def config_dir(self) -> Path:
        """Non-tenant configuration directory, a sibling of the archive root."""
        return self.data_root / "config"

    @property
    def integration_key_path(self) -> Path:
        """Fictional integration key no tenant operation legitimately reads."""
        return self.config_dir / "integration.key"

    @property
    def branding_conf_path(self) -> Path:
        """Branding config whose footer the statement summary reads at request time."""
        return self.config_dir / "branding.conf"

    def tenant_base(self, tenant_id: str) -> Path:
        """The archive directory a given tenant's requests are joined against."""
        return self.archive_root / tenant_id


def load_settings() -> Settings:
    """Build :class:`Settings` from the environment, defaulting to ``/data``."""
    root = os.environ.get(DATA_ROOT_ENV, str(DEFAULT_DATA_ROOT))
    return Settings(data_root=Path(root))
