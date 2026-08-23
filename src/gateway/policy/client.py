"""Policy client contract.

The gateway never makes an allow/deny/approval-required decision itself,
and it never decides which scope or risk level a tool carries either;
OPA owns that mapping (see policy/gateway/authz.rego). The gateway only
sends verified identity, the requested tool name, and the approval state;
it asks the policy engine for both a decision AND the metadata (required
scope, risk, approval requirement) OPA used to reach it, then cross-checks
that metadata against its own fixed tool registry before trusting the
decision at all (see src/gateway/api/routes.py).

PolicyDecision is a closed schema (`extra="forbid"`): an OPA response
carrying an unexpected field, a missing field, an empty policy version, or
a decision string outside the known set is rejected by Pydantic and
surfaces as a PolicyError, which the API layer treats as a hard deny.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

Decision = Literal["allow", "deny", "approval-required"]


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    policy_version: str = Field(min_length=1)
    required_scope: str
    risk: str
    approval_required: bool


class PolicyError(Exception):
    """Raised when the policy engine cannot be reached or returns a
    response that cannot be trusted. Callers must treat this as deny."""


class PolicyClient(Protocol):
    async def evaluate(self, policy_input: Mapping[str, object]) -> PolicyDecision: ...
