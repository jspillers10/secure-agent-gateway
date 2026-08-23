"""The fixed, server-side tool registry.

This is the single source of truth for which tools exist, what they cost
in risk, what scope they require, whether they require approval, and which
handler executes them. A tool name from a client request is used only to
index into this dict; it is never passed to `getattr`, `importlib`, or any
other dynamic-dispatch mechanism, so a client cannot name an arbitrary
Python function or module and have it invoked.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from gateway.registry.schemas import AdminRotateKeyArgs, DocumentsReadArgs, TicketsCreateArgs
from gateway.risk import RiskLevel
from gateway.tools_impl.admin import admin_rotate_key
from gateway.tools_impl.documents import documents_read
from gateway.tools_impl.tickets import tickets_create


class UnknownToolError(Exception):
    """Raised when a client requests a tool name not present in the registry."""


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    risk: RiskLevel
    required_scope: str
    approval_required: bool
    args_model: type[BaseModel]
    handler: Callable[[BaseModel], dict[str, Any]]


TOOL_REGISTRY: Mapping[str, ToolSpec] = {
    "documents.read": ToolSpec(
        name="documents.read",
        risk=RiskLevel.LOW,
        required_scope="documents.read",
        approval_required=False,
        args_model=DocumentsReadArgs,
        handler=documents_read,  # type: ignore[arg-type]
    ),
    "tickets.create": ToolSpec(
        name="tickets.create",
        risk=RiskLevel.MEDIUM,
        required_scope="tickets.write",
        approval_required=False,
        args_model=TicketsCreateArgs,
        handler=tickets_create,  # type: ignore[arg-type]
    ),
    "admin.rotate_key": ToolSpec(
        name="admin.rotate_key",
        risk=RiskLevel.HIGH,
        required_scope="admin.rotate_key",
        approval_required=True,
        args_model=AdminRotateKeyArgs,
        handler=admin_rotate_key,  # type: ignore[arg-type]
    ),
}


def resolve_tool(name: str) -> ToolSpec:
    try:
        return TOOL_REGISTRY[name]
    except KeyError as exc:
        raise UnknownToolError(name) from exc
