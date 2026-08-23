"""Risk classification.

Risk is a static, server-defined property of each tool in the registry
(see registry/tools.py). It is never accepted as client input: the tool
invocation request schema has no risk field, and `extra="forbid"` on that
schema means any attempt to smuggle one in is rejected outright rather than
silently ignored. See tests/test_tool_invocation.py::test_client_risk_override_rejected.
"""

from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
