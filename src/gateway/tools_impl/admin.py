"""INERT MOCK TOOL: NEVER PERFORMS A REAL KEY OPERATION.

This handler does not contact any key-management system, does not rotate
any real credential, and makes no network or filesystem call. It exists
only to exercise the high-risk, approval-required path through the
gateway. It always returns a simulated result.
"""

from __future__ import annotations

from typing import Any

from gateway.registry.schemas import AdminRotateKeyArgs


def admin_rotate_key(args: AdminRotateKeyArgs) -> dict[str, Any]:
    return {
        "key_id": args.key_id,
        "status": "simulated_rotation_recorded",
        "note": "MOCK ONLY: no real key was rotated.",
    }
