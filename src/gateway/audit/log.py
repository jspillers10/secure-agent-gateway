"""Structured, redacted audit events.

Both event types below are closed schemas (`extra="forbid"`): it is
structurally impossible to attach a raw token, raw argument, raw tool
result, or approval credential to an audit record, because neither model
has a field for one. Only hashes (argument_hash, result_hash) are
recorded, never raw values. This is enforced by the type system, not by
convention.

AuditEvent covers the tool-invocation lifecycle. ApprovalAuditEvent
covers the approval lifecycle (creation, rejection at creation, the final
atomic consumption immediately before execution, and any binding failure,
including replay). Neither schema has an `approval_id` field: per the
approval-provenance correction, the audit trail deliberately never
records the approval id, the approver credential, or the approver's
raw key; only what tool it was for, whose it was for, and what happened.

Denied and approved attempts are always distinguishable via the
combination of `outcome` and `approval_state` / `scope_decision` (for
AuditEvent) or `event` / `reason` (for ApprovalAuditEvent); see
docs/threat-model.md for the full state table.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

AUDIT_LOGGER_NAME = "gateway.audit"

_logger = logging.getLogger(AUDIT_LOGGER_NAME)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    correlation_id: str
    timestamp: datetime
    agent_id: str
    delegated_user_id: str
    tool_name: str
    scope_decision: Literal["granted", "denied", "unknown"]
    policy_decision: Literal["allow", "deny", "approval-required", "error"]
    policy_version: str | None
    risk_level: str | None
    approval_state: str
    argument_hash: str | None
    result_hash: str | None
    outcome: Literal["executed", "denied", "approval_required", "error"]
    error_code: str | None = None


class ApprovalAuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    correlation_id: str
    timestamp: datetime
    event: Literal["created", "rejected", "consumed", "binding_failed"]
    tool_name: str
    agent_id: str
    delegated_user_id: str
    granted_by: str | None
    argument_hash: str | None
    reason: str | None = None


def emit_audit_event(event: AuditEvent) -> None:
    _logger.info(json.dumps(event.model_dump(mode="json"), sort_keys=True))


def emit_approval_audit_event(event: ApprovalAuditEvent) -> None:
    _logger.info(json.dumps(event.model_dump(mode="json"), sort_keys=True))
