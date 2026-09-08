"""Closed Worker-to-egress-broker request and response protocol."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gateway.execution.protocol import ExecutionGrant

MAX_RESOLVED_ADDRESSES = 32


class ClosedEgressModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BrokerFetchRequest(ClosedEgressModel):
    protocol_version: Literal["1.0"] = "1.0"
    operation: Literal["https_get_text"] = "https_get_text"
    worker_id: str = Field(min_length=1, max_length=128)
    grant: ExecutionGrant


class HopDecision(ClosedEgressModel):
    timestamp: datetime
    invocation_id: str
    worker_id: str
    hop: int = Field(ge=0, le=16)
    destination_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    origin: str | None
    decision: Literal["allow", "deny"]
    reason: str = Field(min_length=1, max_length=64)
    resolved_address_hashes: tuple[str, ...] = ()
    resolved_address_count: int = Field(default=0, ge=0, le=65_535)
    dns_duration_ms: float = Field(ge=0)
    broker_duration_ms: float = Field(ge=0)

    @field_validator("resolved_address_hashes")
    @classmethod
    def validate_address_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) > MAX_RESOLVED_ADDRESSES or any(
            not re_match_digest(value) for value in values
        ):
            raise ValueError("invalid resolved-address digest")
        return values

    @model_validator(mode="after")
    def validate_address_count(self) -> HopDecision:
        hashed = len(self.resolved_address_hashes)
        if self.resolved_address_count <= MAX_RESOLVED_ADDRESSES:
            if self.resolved_address_count != hashed:
                raise ValueError("resolved-address count does not match hashes")
        elif hashed:
            raise ValueError("excessive address sets must not be partially represented")
        return self


def re_match_digest(value: str) -> bool:
    if not value.startswith("sha256:") or len(value) != 71:
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


class BrokerFetchResult(ClosedEgressModel):
    protocol_version: Literal["1.0"] = "1.0"
    status: Literal["succeeded", "denied", "failed"]
    text: str | None = None
    final_url: str | None = None
    content_type: str | None = None
    byte_count: int = Field(ge=0)
    error_code: str | None = Field(default=None, max_length=64)
    decisions: tuple[HopDecision, ...] = Field(max_length=12)

    @model_validator(mode="after")
    def validate_result_shape(self) -> BrokerFetchResult:
        if self.status == "succeeded":
            if (
                self.text is None
                or self.final_url is None
                or self.content_type is None
                or self.error_code is not None
            ):
                raise ValueError("successful broker result is incomplete")
            if len(self.text.encode("utf-8")) != self.byte_count:
                raise ValueError("broker byte count does not match text")
        elif (
            self.text is not None
            or self.final_url is not None
            or self.content_type is not None
            or self.error_code is None
            or self.byte_count != 0
        ):
            raise ValueError("denied or failed broker result has an invalid shape")
        return self
