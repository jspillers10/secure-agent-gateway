"""HTTP request/response models for the public API.

`extra="forbid"` on ToolInvocationRequest is a deliberate control: it is
the mechanism that rejects a client attempt to smuggle in fields the
server does not expect, including a client-supplied `risk` field, since
risk has no place in this schema at all.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolInvocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=200)
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = Field(default=None, max_length=256)
    correlation_id: str | None = Field(default=None, max_length=256)


class ToolInvocationResponse(BaseModel):
    request_id: str
    correlation_id: str
    decision: Literal["allow", "deny", "approval-required"]
    tool: str
    risk_level: str
    policy_version: str | None = None
    result: dict[str, Any] | None = None
    message: str | None = None


class ApprovalCreateRequest(BaseModel):
    """No `granted_by` field: the approver identity is never client-
    controlled. It is derived server-side from trusted configuration (see
    Settings.approver_identity) after the caller has already authenticated
    via the separate X-Approver-Key credential (require_approver_key)."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=200)
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = Field(min_length=1, max_length=256)
    delegated_user_id: str = Field(min_length=1, max_length=256)
    ttl_seconds: int = Field(default=300, ge=1, le=3600)


class ApprovalCreateResponse(BaseModel):
    approval_id: str
    tool: str
    expires_at: datetime
