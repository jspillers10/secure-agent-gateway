"""FastAPI dependencies.

All app-scoped collaborators (settings, policy client, approval store) are
read off `request.app.state` rather than constructed here, so tests can
substitute them via `app.dependency_overrides` without touching global
state.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import Header, HTTPException, Request, status

from gateway.approvals.store import ApprovalStore
from gateway.config import Settings
from gateway.identity.models import AgentIdentity
from gateway.identity.tokens import TokenVerificationError, verify_delegated_token
from gateway.policy.client import PolicyClient

_log = logging.getLogger("gateway.identity")


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_policy_client(request: Request) -> PolicyClient:
    policy_client: PolicyClient = request.app.state.policy_client
    return policy_client


def get_approval_store(request: Request) -> ApprovalStore:
    approval_store: ApprovalStore = request.app.state.approval_store
    return approval_store


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    value = value.strip()
    return value or None


async def get_verified_identity(
    request: Request,
    authorization: str | None = Header(default=None),
) -> AgentIdentity:
    settings = get_settings(request)
    token = _extract_bearer_token(authorization)

    try:
        identity = verify_delegated_token(
            token,
            public_key=settings.jwt_public_key,
            issuer=settings.issuer,
            audience=settings.audience,
            algorithm=settings.jwt_algorithm,
        )
    except TokenVerificationError as exc:
        # The specific failure reason is logged server-side only. The HTTP
        # response is deliberately generic so the API cannot be used as an
        # oracle to probe why a token was rejected.
        _log.warning("token rejected reason=%s", exc.code)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "invalid or missing bearer token"},
        ) from exc

    return identity


def require_approver_key(
    request: Request,
    x_approver_key: str | None = Header(default=None),
) -> None:
    settings = get_settings(request)
    if not x_approver_key or not hmac.compare_digest(x_approver_key, settings.approver_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "invalid approver credential"},
        )
