"""Closed, versioned schemas crossing the Gateway/Launcher/Worker boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gateway.hashing import sha256_hex

PROTOCOL_VERSION: Literal["1.0"] = "1.0"
GRANT_ISSUER = "secure-agent-gateway"
GRANT_AUDIENCE = "secure-agent-worker-launcher"
RESULT_SIGNING_ALGORITHM = "RS256"

Digest = str


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value


class ToolIdentity(ClosedModel):
    name: str = Field(min_length=1, max_length=200)
    artifact_digest: Digest = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ApprovalBinding(ClosedModel):
    required: bool
    state: Literal["not_required", "consumed"]
    digest: Digest | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_binding(self) -> ApprovalBinding:
        if self.required and (self.state != "consumed" or self.digest is None):
            raise ValueError("approval-required actions need a consumed approval digest")
        if not self.required and (self.state != "not_required" or self.digest is not None):
            raise ValueError("approval-free actions cannot carry an approval digest")
        return self


class ActionEnvelope(ClosedModel):
    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    invocation_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    delegated_user_id: str = Field(min_length=1, max_length=256)
    tool: ToolIdentity
    arguments: dict[str, Any]
    argument_digest: Digest = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approval: ApprovalBinding
    policy_version: str = Field(min_length=1, max_length=128)
    risk: Literal["low", "medium", "high"]
    created_at: datetime

    _created_at_aware = field_validator("created_at")(_require_aware)

    @model_validator(mode="after")
    def validate_argument_commitment(self) -> ActionEnvelope:
        if sha256_hex(self.arguments) != self.argument_digest:
            raise ValueError("argument digest does not match canonical validated arguments")
        return self

    def digest(self) -> Digest:
        return sha256_hex(self.model_dump(mode="json"))


class ExecutionGrant(ClosedModel):
    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    issuer: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=24, max_length=256)
    action: ActionEnvelope
    action_digest: Digest = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(min_length=32, max_length=2048)

    _issued_at_aware = field_validator("issued_at")(_require_aware)
    _expires_at_aware = field_validator("expires_at")(_require_aware)

    @model_validator(mode="after")
    def validate_claims(self) -> ExecutionGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("grant expiry must be after issuance")
        if self.action.digest() != self.action_digest:
            raise ValueError("action digest does not match action envelope")
        return self

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})


class ToolResultEnvelope(ClosedModel):
    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    invocation_id: str = Field(min_length=1, max_length=128)
    grant_nonce: str = Field(min_length=24, max_length=256)
    worker_id: str = Field(min_length=1, max_length=128)
    tool: ToolIdentity
    status: Literal["succeeded", "failed"]
    result: dict[str, Any] | None
    result_digest: Digest = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    error_code: Literal["tool_execution_failed", "worker_protocol_error"] | None = None
    started_at: datetime
    completed_at: datetime
    signature: str = Field(min_length=32, max_length=2048)

    _started_at_aware = field_validator("started_at")(_require_aware)
    _completed_at_aware = field_validator("completed_at")(_require_aware)

    @model_validator(mode="after")
    def validate_result(self) -> ToolResultEnvelope:
        if self.completed_at < self.started_at:
            raise ValueError("result completion precedes start")
        if self.status == "succeeded" and (self.result is None or self.error_code is not None):
            raise ValueError("successful result requires data and no error")
        if self.status == "failed" and (self.result is not None or self.error_code is None):
            raise ValueError("failed result requires an error and no data")
        committed: dict[str, Any] = (
            self.result if self.result is not None else {"error": self.error_code}
        )
        if sha256_hex(committed) != self.result_digest:
            raise ValueError("result digest does not match result envelope")
        return self

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})
