"""boundless — a container-only path-traversal (CWE-22 / Zip Slip) teaching demo.

This package holds the *secure baseline*: a fully fictional multi-tenant statement
archive that handles user-supplied filenames safely by **resolving the candidate path
and then confining it to its base directory**, for both reads and archive imports.

Everything here is synthetic demonstration material. It ships no exploit against any
real system, executes no command, and confines every write to a disposable in-container
fixture tree. Do not deploy it.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
