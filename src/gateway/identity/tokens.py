"""Delegated-identity token verification.

Identity model (explicit, since this is the one thing every other control
in the gateway is built on top of):

- A token represents an *agent* acting with a *delegated user*'s
  authority. The JWT subject (`sub`) is defined, for this project, to be
  the agent's own identity: the same value as the `agent_id` claim. This
  is a deliberate simplification for the vertical slice: a real deployment
  would more likely mint `sub` as a stable workload identity (e.g. a
  SPIFFE ID) distinct from a human-readable `agent_id`. Because the two
  are defined to be the same value here, `verify_delegated_token` requires
  `sub == agent_id` and rejects the token outright if they differ; that
  mismatch is either a malformed issuer or a sign the token was crafted
  to smuggle a different principal past `sub`-based checks. See
  TokenSubjectMismatch and docs/threat-model.md.
- The `delegated_user` claim is a nested object identifying the human on
  whose behalf the agent is acting. It is never used for cryptographic
  identity: only `sub`/`agent_id` is authenticated by the signature; the
  delegated user is *asserted* by the token issuer, exactly like any other
  claim.
- `scopes` is the delegated-identity's scope grant, checked against the
  fixed per-tool required scope that OPA resolves (never a value the
  gateway or the client supplies; see policy/gateway/authz.rego).
- `jti` is the token's own id, recorded (never logged raw with the token)
  for potential future replay-detection; this slice does not implement
  JWT-level revocation (see docs/threat-model.md's known limitations).

Security-critical properties enforced here:

- Algorithm allow-listing. `jwt.decode(..., algorithms=[settings.jwt_algorithm])`
  is called with a single, server-configured asymmetric algorithm: RS256,
  and only RS256 (see config.SUPPORTED_JWT_ALGORITHMS, which
  load_settings() enforces at startup, before this function is ever
  reachable). PyJWT only ever attempts verification using an algorithm
  drawn from this allow-list; it does not trust the token's own `alg`
  header to select the verification method. This is what prevents classic
  JWT algorithm-confusion attacks: an attacker cannot force the server to
  verify an RS256 token's signature using HMAC with the public key as the
  secret, and cannot use `alg: none` to skip verification, because neither
  "HS256" nor "none" is ever in the allow-list.
- Every verification failure mode (missing, malformed, expired, wrong
  issuer, wrong audience, bad signature, missing claims, subject/agent
  mismatch) raises a distinct exception type so callers can fail closed
  and audit precisely, without the HTTP-facing error message leaking which
  check failed (that mapping happens at the API boundary, not here).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import jwt
from pydantic import ValidationError

from gateway.identity.models import AgentIdentity, DelegatedUser

REQUIRED_CLAIMS = ("iss", "aud", "sub", "exp", "iat", "agent_id", "delegated_user", "scopes", "jti")


class TokenVerificationError(Exception):
    """Base class for all delegated-token verification failures."""

    code = "token_invalid"


class TokenMissing(TokenVerificationError):
    code = "token_missing"


class TokenMalformed(TokenVerificationError):
    code = "token_malformed"


class TokenExpired(TokenVerificationError):
    code = "token_expired"


class TokenInvalidIssuer(TokenVerificationError):
    code = "token_invalid_issuer"


class TokenInvalidAudience(TokenVerificationError):
    code = "token_invalid_audience"


class TokenInvalidSignature(TokenVerificationError):
    code = "token_invalid_signature"


class TokenClaimsInvalid(TokenVerificationError):
    code = "token_claims_invalid"


class TokenSubjectMismatch(TokenVerificationError):
    """Raised when `sub` does not equal `agent_id`.

    This project's identity model defines the two to be the same value
    (see module docstring). A token where they differ is rejected; it
    can never be treated as "verified for `sub` but let's use `agent_id`
    anyway", which would let a token assert one authenticated subject
    while acting under a different, unauthenticated agent identity.
    """

    code = "token_subject_mismatch"


def verify_delegated_token(
    token: str | None,
    *,
    public_key: str,
    issuer: str,
    audience: str,
    algorithm: str,
) -> AgentIdentity:
    """Verify a delegated-identity JWT and return a trusted AgentIdentity.

    Raises a TokenVerificationError subclass on any failure. Never returns
    a partially-trusted result.
    """
    if not token or not token.strip():
        raise TokenMissing("no bearer token presented")

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            key=public_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_signature": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpired(str(exc)) from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenInvalidIssuer(str(exc)) from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenInvalidAudience(str(exc)) from exc
    except (jwt.InvalidSignatureError, jwt.InvalidAlgorithmError, jwt.InvalidKeyError) as exc:
        raise TokenInvalidSignature(str(exc)) from exc
    except jwt.DecodeError as exc:
        raise TokenMalformed(str(exc)) from exc
    except jwt.PyJWTError as exc:
        # Any other PyJWT failure mode (missing required claim, etc.) is
        # treated as malformed rather than silently accepted.
        raise TokenMalformed(str(exc)) from exc

    missing_claims = [claim for claim in REQUIRED_CLAIMS if claim not in payload]
    if missing_claims:
        raise TokenClaimsInvalid(f"missing claims: {', '.join(missing_claims)}")

    if payload["sub"] != payload["agent_id"]:
        raise TokenSubjectMismatch("token subject (sub) does not match agent_id")

    try:
        scopes = payload["scopes"]
        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            raise TokenClaimsInvalid("scopes claim must be a list of strings")

        return AgentIdentity(
            agent_id=payload["agent_id"],
            delegated_user=DelegatedUser(**payload["delegated_user"]),
            scopes=tuple(scopes),
            token_id=payload["jti"],
            issued_at=datetime.fromtimestamp(payload["iat"], tz=UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise TokenClaimsInvalid(str(exc)) from exc
