"""Unit tests for gateway.identity.tokens.verify_delegated_token.

These call the verifier directly (not through the HTTP API) so each
failure mode can be asserted precisely. The API layer intentionally
collapses all of these into a single generic 401 to avoid acting as a
validation oracle; see tests/test_tool_invocation.py and
src/gateway/api/deps.py.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest

from gateway.identity.tokens import (
    TokenClaimsInvalid,
    TokenExpired,
    TokenInvalidAudience,
    TokenInvalidIssuer,
    TokenInvalidSignature,
    TokenMalformed,
    TokenMissing,
    TokenSubjectMismatch,
    verify_delegated_token,
)
from tests.helpers.keys import generate_rsa_keypair, mint_token

ISSUER = "https://issuer.test"
AUDIENCE = "secure-agent-gateway"


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    return generate_rsa_keypair()


def _verify(token: str | None, public_key: str, **overrides: object):  # type: ignore[no-untyped-def]
    kwargs: dict[str, object] = {
        "public_key": public_key,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "algorithm": "RS256",
    }
    kwargs.update(overrides)
    return verify_delegated_token(token, **kwargs)  # type: ignore[arg-type]


def test_valid_token_verifies(keypair: tuple[str, str]) -> None:
    private, public = keypair
    token = mint_token(private, issuer=ISSUER, audience=AUDIENCE, scopes=["documents.read"])
    identity = _verify(token, public)
    assert identity.agent_id == "agent-001"
    assert identity.delegated_user.id == "user-001"
    assert identity.has_scope("documents.read")


def test_missing_token_rejected(keypair: tuple[str, str]) -> None:
    _private, public = keypair
    with pytest.raises(TokenMissing):
        _verify(None, public)
    with pytest.raises(TokenMissing):
        _verify("   ", public)


def test_expired_token_rejected(keypair: tuple[str, str]) -> None:
    private, public = keypair
    token = mint_token(
        private, issuer=ISSUER, audience=AUDIENCE, issued_offset=-1000, expires_in=1
    )
    with pytest.raises(TokenExpired):
        _verify(token, public)


def test_wrong_issuer_rejected(keypair: tuple[str, str]) -> None:
    private, public = keypair
    token = mint_token(private, issuer="https://attacker.example", audience=AUDIENCE)
    with pytest.raises(TokenInvalidIssuer):
        _verify(token, public)


def test_wrong_audience_rejected(keypair: tuple[str, str]) -> None:
    private, public = keypair
    token = mint_token(private, issuer=ISSUER, audience="some-other-service")
    with pytest.raises(TokenInvalidAudience):
        _verify(token, public)


def test_invalid_signature_rejected(keypair: tuple[str, str]) -> None:
    _private, public = keypair
    attacker_private, _attacker_public = generate_rsa_keypair()
    token = mint_token(attacker_private, issuer=ISSUER, audience=AUDIENCE)
    with pytest.raises(TokenInvalidSignature):
        _verify(token, public)


def test_malformed_token_rejected(keypair: tuple[str, str]) -> None:
    _private, public = keypair
    with pytest.raises(TokenMalformed):
        _verify("not-a-jwt-at-all", public)


def test_algorithm_confusion_none_rejected(keypair: tuple[str, str]) -> None:
    """alg=none must never be accepted, regardless of payload contents."""
    _private, public = keypair
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "agent-001",
        "agent_id": "agent-001",
        "delegated_user": {"id": "user-001"},
        "scopes": ["admin.rotate_key"],
        "jti": "forged",
        "iat": now,
        "exp": now + 300,
    }
    forged = jwt.encode(payload, key=None, algorithm="none")
    with pytest.raises((TokenInvalidSignature, TokenMalformed)):
        _verify(forged, public)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _forge_hs256_token(payload: dict[str, object], secret: str) -> str:
    """Hand-roll an HS256 JWT, bypassing PyJWT's own encode-time defense
    that refuses to treat a PEM-shaped key as an HMAC secret. A real
    attacker would not use PyJWT to forge this; they'd use any HMAC
    implementation. This isolates the test to what we actually control:
    the server's decode-time algorithm allow-list.
    """
    header_b64 = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def test_algorithm_confusion_hs256_with_public_key_rejected(keypair: tuple[str, str]) -> None:
    """Classic RS256->HS256 confusion attack: an attacker signs a forged
    token with HS256 using the server's own RSA *public* key (which is not
    secret) as the HMAC key. This must be rejected because the server only
    ever allows RS256 in its verification algorithm allow-list; it never
    lets the token's own header pick the verification method.
    """
    _private, public = keypair
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "agent-001",
        "agent_id": "agent-001",
        "delegated_user": {"id": "user-001"},
        "scopes": ["admin.rotate_key"],
        "jti": "forged",
        "iat": now,
        "exp": now + 300,
    }
    forged = _forge_hs256_token(payload, secret=public)
    with pytest.raises(TokenInvalidSignature):
        _verify(forged, public)


def test_missing_delegated_user_claim_rejected(keypair: tuple[str, str]) -> None:
    private, public = keypair
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "agent-001",
        "agent_id": "agent-001",
        "scopes": ["documents.read"],
        "jti": "x",
        "iat": now,
        "exp": now + 300,
    }
    token = jwt.encode(payload, private, algorithm="RS256")
    with pytest.raises(TokenClaimsInvalid):
        _verify(token, public)


def test_sub_agent_id_mismatch_rejected(keypair: tuple[str, str]) -> None:
    """This project's identity model defines `sub` and `agent_id` to be
    the same value (see the tokens.py module docstring). A token where an
    issuer set them to different values must be rejected outright, not
    silently trusted under the `agent_id` value."""
    private, public = keypair
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "agent-001",
        "agent_id": "agent-002",  # deliberately different from sub
        "delegated_user": {"id": "user-001"},
        "scopes": ["documents.read"],
        "jti": "x",
        "iat": now,
        "exp": now + 300,
    }
    token = jwt.encode(payload, private, algorithm="RS256")
    with pytest.raises(TokenSubjectMismatch):
        _verify(token, public)


def test_sub_equal_agent_id_verifies(keypair: tuple[str, str]) -> None:
    private, public = keypair
    token = mint_token(private, issuer=ISSUER, audience=AUDIENCE, agent_id="agent-007")
    identity = _verify(token, public)
    assert identity.agent_id == "agent-007"
