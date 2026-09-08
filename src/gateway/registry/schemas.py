"""Per-tool argument schemas.

Every schema forbids unknown fields (`extra="forbid"`). Combined with the
fixed tool registry, this means a client can never pass an argument, or a
tool name, that the server did not explicitly define ahead of time.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from gateway.egress.url_policy import DestinationPolicyError, canonicalize_https_url


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


class WebFetchTextArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def canonical_url(cls, value: str) -> str:
        try:
            return canonicalize_https_url(value).value
        except DestinationPolicyError as exc:
            raise ValueError(exc.code) from exc
