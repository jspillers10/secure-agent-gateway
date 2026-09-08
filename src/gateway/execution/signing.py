"""Signing and verification for short-lived execution grants and results."""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

from gateway.execution.protocol import (
    ActionEnvelope,
    EgressGrant,
    ExecutionGrant,
    ToolResultEnvelope,
)
from gateway.hashing import canonical_json_bytes


class GrantVerificationError(Exception):
    """A grant is malformed, untrusted, expired, replayed, or misbound."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ResultVerificationError(Exception):
    """A Worker result is unauthenticated or bound to another invocation."""


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding_bytes = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding_bytes)
    except (ValueError, TypeError) as exc:
        raise GrantVerificationError("signature_malformed") from exc


def _load_private_key(private_key_pem: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("execution signing key must be RSA")
    return key


def _load_public_key(public_key_pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("execution verification key must be RSA")
    return key


def _sign(payload: dict[str, Any], private_key_pem: str) -> str:
    signature = _load_private_key(private_key_pem).sign(
        canonical_json_bytes(payload),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return _b64url_encode(signature)


def _verify(payload: dict[str, Any], signature: str, public_key_pem: str) -> None:
    try:
        _load_public_key(public_key_pem).verify(
            _b64url_decode(signature),
            canonical_json_bytes(payload),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise GrantVerificationError("signature_invalid") from exc


class ExecutionGrantSigner:
    def __init__(
        self,
        private_key_pem: str,
        *,
        issuer: str,
        audience: str,
        ttl_seconds: int = 30,
    ) -> None:
        if ttl_seconds < 1 or ttl_seconds > 300:
            raise ValueError("grant TTL must be between 1 and 300 seconds")
        _load_private_key(private_key_pem)
        self._private_key_pem = private_key_pem
        self._issuer = issuer
        self._audience = audience
        self._ttl_seconds = ttl_seconds

    def issue(
        self,
        action: ActionEnvelope,
        *,
        egress: EgressGrant | None = None,
        now: datetime | None = None,
    ) -> ExecutionGrant:
        issued_at = now or datetime.now(tz=UTC)
        unsigned: dict[str, Any] = {
            "protocol_version": "1.0",
            "issuer": self._issuer,
            "audience": self._audience,
            "issued_at": issued_at.isoformat(),
            "expires_at": (issued_at + timedelta(seconds=self._ttl_seconds)).isoformat(),
            "nonce": secrets.token_urlsafe(32),
            "action": action.model_dump(mode="json"),
            "action_digest": action.digest(),
            "egress": egress.model_dump(mode="json") if egress is not None else None,
        }
        candidate = ExecutionGrant.model_validate({**unsigned, "signature": "0" * 32})
        return candidate.model_copy(
            update={"signature": _sign(candidate.signing_payload(), self._private_key_pem)}
        )


def verify_execution_grant(
    grant: ExecutionGrant,
    *,
    public_key_pem: str,
    issuer: str,
    audience: str,
    now: datetime | None = None,
    expected_tool_name: str | None = None,
    expected_artifact_digest: str | None = None,
    expected_argument_digest: str | None = None,
    expected_approval_digest: str | None = None,
) -> None:
    if grant.protocol_version != "1.0" or grant.action.protocol_version != "1.0":
        raise GrantVerificationError("version_unknown")
    _verify(grant.signing_payload(), grant.signature, public_key_pem)
    current = now or datetime.now(tz=UTC)
    if grant.issuer != issuer:
        raise GrantVerificationError("issuer_invalid")
    if grant.audience != audience:
        raise GrantVerificationError("audience_invalid")
    if current >= grant.expires_at:
        raise GrantVerificationError("grant_expired")
    if grant.issued_at > current + timedelta(seconds=5):
        raise GrantVerificationError("issued_in_future")
    if grant.expires_at - grant.issued_at > timedelta(seconds=300):
        raise GrantVerificationError("grant_ttl_invalid")
    if grant.action.digest() != grant.action_digest:
        raise GrantVerificationError("action_digest_mismatch")
    if expected_tool_name is not None and grant.action.tool.name != expected_tool_name:
        raise GrantVerificationError("tool_mismatch")
    if (
        expected_artifact_digest is not None
        and grant.action.tool.artifact_digest != expected_artifact_digest
    ):
        raise GrantVerificationError("artifact_digest_mismatch")
    if (
        expected_argument_digest is not None
        and grant.action.argument_digest != expected_argument_digest
    ):
        raise GrantVerificationError("argument_digest_mismatch")
    if expected_approval_digest != grant.action.approval.digest:
        raise GrantVerificationError("approval_binding_mismatch")


def generate_result_keypair() -> tuple[str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def sign_tool_result(unsigned: dict[str, Any], private_key_pem: str) -> ToolResultEnvelope:
    candidate = ToolResultEnvelope.model_validate({**unsigned, "signature": "0" * 32})
    signature = _sign(candidate.signing_payload(), private_key_pem)
    return candidate.model_copy(update={"signature": signature})


def verify_tool_result(
    result: ToolResultEnvelope,
    *,
    public_key_pem: str,
    expected_invocation_id: str,
    expected_grant_nonce: str,
    expected_worker_id: str,
    expected_tool_name: str,
    expected_artifact_digest: str,
) -> None:
    try:
        _verify(result.signing_payload(), result.signature, public_key_pem)
    except GrantVerificationError as exc:
        raise ResultVerificationError(exc.code) from exc
    expected = (
        expected_invocation_id,
        expected_grant_nonce,
        expected_worker_id,
        expected_tool_name,
        expected_artifact_digest,
    )
    actual = (
        result.invocation_id,
        result.grant_nonce,
        result.worker_id,
        result.tool.name,
        result.tool.artifact_digest,
    )
    if actual != expected:
        raise ResultVerificationError("result_binding_mismatch")


def parse_execution_grant(value: Any) -> ExecutionGrant:
    try:
        return ExecutionGrant.model_validate(value)
    except ValidationError as exc:
        raise GrantVerificationError("grant_schema_invalid") from exc
