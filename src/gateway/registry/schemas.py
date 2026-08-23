"""Per-tool argument schemas.

Every schema forbids unknown fields (`extra="forbid"`). Combined with the
fixed tool registry, this means a client can never pass an argument, or a
tool name, that the server did not explicitly define ahead of time.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DocumentsReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_\-]+$")


class TicketsCreateArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    priority: Literal["low", "normal", "high"] = "normal"


class AdminRotateKeyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_\-]+$")
    reason: str = Field(min_length=1, max_length=500)
