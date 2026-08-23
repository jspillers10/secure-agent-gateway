"""INERT MOCK TOOL. No real ticketing system, no network I/O.

Generates a plausible-looking ticket record in memory and returns it. No
state is persisted beyond the response.
"""

from __future__ import annotations

import uuid
from typing import Any

from gateway.registry.schemas import TicketsCreateArgs


def tickets_create(args: TicketsCreateArgs) -> dict[str, Any]:
    return {
        "ticket_id": f"TCK-{uuid.uuid4().hex[:8]}",
        "title": args.title,
        "priority": args.priority,
        "status": "open",
    }
