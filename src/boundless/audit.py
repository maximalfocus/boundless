"""Generic rejection audit event.

When the secure application rejects a retrieval or an import it emits exactly one
structured JSON line to standard output. The event supports request correlation and
identifies the actor, tenant, attempted operation, and rejected outcome — and nothing
else. It never echoes the submitted name, never reveals or confirms the base directory
or any absolute path, and never contains tokens, authorization headers, or secrets.
"""

from __future__ import annotations

import json
import sys
from typing import Literal, TextIO

Operation = Literal["retrieve", "import"]

#: Stable event name so log consumers can select rejection events.
EVENT_NAME = "boundless.rejection"


def emit_rejection(
    *,
    request_id: str,
    actor: str,
    tenant: str,
    operation: Operation,
    stream: TextIO | None = None,
) -> dict[str, str]:
    """Write one generic rejection event as a JSON line and return the payload.

    The returned dict is the exact object serialized, which the test suite asserts over
    to prove no sensitive field is ever present.
    """
    event: dict[str, str] = {
        "event": EVENT_NAME,
        "request_id": request_id,
        "actor": actor,
        "tenant": tenant,
        "operation": operation,
        "outcome": "rejected",
    }
    out = stream if stream is not None else sys.stdout
    out.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")
    out.flush()
    return event
