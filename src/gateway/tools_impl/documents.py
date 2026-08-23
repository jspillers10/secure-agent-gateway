"""INERT MOCK TOOL. No real document store, no filesystem or network I/O.

Reads are served from a fixed in-memory dictionary. This file exists purely
to demonstrate the low-risk, read-scoped path through the gateway.
"""

from __future__ import annotations

from typing import Any

from gateway.registry.schemas import DocumentsReadArgs
from gateway.tools_impl.errors import ToolExecutionError

_MOCK_DOCUMENTS: dict[str, str] = {
    "doc-001": "Q3 planning notes (mock content).",
    "doc-002": "Onboarding checklist (mock content).",
}


def documents_read(args: DocumentsReadArgs) -> dict[str, Any]:
    content = _MOCK_DOCUMENTS.get(args.document_id)
    if content is None:
        raise ToolExecutionError(f"document not found: {args.document_id}")
    return {"document_id": args.document_id, "content": content}
