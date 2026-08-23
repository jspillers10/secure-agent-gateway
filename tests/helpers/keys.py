"""Ephemeral test key material and token minting.

Every keypair generated here is created fresh in-process for the lifetime
of the test run and is never written to disk or committed. This is the
"generate ephemeral signing material in tests" requirement.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh, in-memory-only RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def mint_token(
    private_key: str,
    *,
    issuer: str,
    audience: str,
    agent_id: str = "agent-001",
    delegated_user_id: str = "user-001",
    scopes: list[str] | None = None,
    algorithm: str = "RS256",
    expires_in: int = 300,
    issued_offset: int = 0,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = int(time.time()) + issued_offset
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": agent_id,
        "agent_id": agent_id,
        "delegated_user": {"id": delegated_user_id},
        "scopes": scopes if scopes is not None else ["documents.read"],
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + expires_in,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, private_key, algorithm=algorithm)
