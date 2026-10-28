"""Redacted JSONL audit trail for the MCP proxy.

Same rule as gateway.audit.log: the event schema is closed
(`extra="forbid"`) and has no field for a raw argument, tool result, or
matched secret, so recording one is a type error rather than a
convention someone has to remember. Arguments appear only as
`argument_hash` (gateway.hashing.sha256_hex over the canonical JSON), and
`reason` is built by gateway.proxy.policy from policy text and argument
names only.

Unlike the gateway audit, `approval_id` is recorded: in the proxy it is a
handle for correlating request, grant, and consumption, never something a
caller presents to gain access (see gateway.proxy.approvals).
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ProxyAuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    event: Literal[
        "tool_call",
        "tools_list_filtered",
        "approval_requested",
        "approval_granted",
        "approval_consumed",
    ]
    server: str
    server_id: str | None = None
    request_id: str | None = None
    tool_name: str | None = None
    decision: Literal["allow", "deny", "ask"] | None = None
    code: str | None = None
    rule: str | None = None
    reason: str | None = None
    argument_hash: str | None = None
    approval_id: str | None = None
    hidden_tools: list[str] | None = None
    approved_by: str | None = None


class JsonlAuditLog:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: ProxyAuditEvent) -> None:
        if self.path is None:
            return
        line = json.dumps(event.model_dump(mode="json", exclude_none=True), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
