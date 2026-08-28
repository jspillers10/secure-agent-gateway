"""FastAPI application factory.

Settings, the policy client, and the approval store are attached to
`app.state` at creation time. Tests build their own app via
`create_app(settings=..., policy_client=...)` rather than importing the
module-level `app`, so they never depend on real environment variables or
a live OPA instance.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from gateway.api.routes import router
from gateway.approvals.store import ApprovalStore
from gateway.config import Settings, load_settings
from gateway.execution.client import (
    LauncherClient,
    LauncherHttpClient,
    create_mtls_client_context,
)
from gateway.execution.signing import ExecutionGrantSigner
from gateway.policy.client import PolicyClient
from gateway.policy.opa_client import OPAHttpPolicyClient

logging.basicConfig(level=logging.INFO)


def create_app(
    *,
    settings: Settings | None = None,
    policy_client: PolicyClient | None = None,
    approval_store: ApprovalStore | None = None,
    launcher_client: LauncherClient | None = None,
    grant_signer: ExecutionGrantSigner | None = None,
) -> FastAPI:
    resolved_settings = settings or load_settings()

    app = FastAPI(title="Secure Agent Gateway", version="0.1.0")
    app.state.settings = resolved_settings
    if policy_client is None or launcher_client is None:
        mtls_context = create_mtls_client_context(
            ca_file=resolved_settings.internal_ca_cert_file,
            cert_file=resolved_settings.gateway_client_cert_file,
            key_file=resolved_settings.gateway_client_key_file,
        )
    else:
        mtls_context = None
    app.state.policy_client = policy_client or OPAHttpPolicyClient(
        resolved_settings.opa_url,
        timeout=resolved_settings.policy_timeout_seconds,
        ssl_context=mtls_context if mtls_context is not None else True,
    )
    app.state.approval_store = approval_store or ApprovalStore()
    app.state.launcher_client = launcher_client or LauncherHttpClient(
        resolved_settings.launcher_url,
        ssl_context=mtls_context if mtls_context is not None else create_mtls_client_context(
            ca_file=resolved_settings.internal_ca_cert_file,
            cert_file=resolved_settings.gateway_client_cert_file,
            key_file=resolved_settings.gateway_client_key_file,
        ),
        timeout=resolved_settings.launcher_timeout_seconds,
    )
    app.state.grant_signer = grant_signer or ExecutionGrantSigner(
        resolved_settings.execution_grant_private_key,
        issuer=resolved_settings.execution_grant_issuer,
        audience=resolved_settings.execution_grant_audience,
        ttl_seconds=resolved_settings.execution_grant_ttl_seconds,
    )

    app.include_router(router)

    @app.exception_handler(HTTPException)
    async def _on_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
        # Route handlers raise HTTPException with a structured dict detail
        # (error code, message, request id). Return it flat rather than
        # nested under FastAPI's default {"detail": ...} wrapper, so every
        # error response (validation, auth, policy, tool failure) has the
        # same shape.
        content = (
            exc.detail
            if isinstance(exc.detail, dict)
            else {"error": "http_error", "message": str(exc.detail)}
        )
        return JSONResponse(status_code=exc.status_code, content=content, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Covers malformed request bodies caught before any dependency
        # (including identity) resolves, e.g. an unknown top-level field
        # such as a client-supplied `risk`. Fails closed with a generic
        # 422 rather than guessing at intent.
        body: dict[str, Any] = {
            "error": "invalid_request",
            "message": "request failed schema validation",
            "request_id": str(uuid4()),
        }
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content=body)

    return app


# Run with `uvicorn gateway.main:create_app --factory`. No module-level app
# instance is built here: doing so would call load_settings() at import
# time, which would make importing this module (e.g. from tests) fail
# unless every required environment variable happened to be set.
