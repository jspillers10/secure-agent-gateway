"""mTLS-only FastAPI surface for the narrow Docker Launcher."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import docker
from fastapi import FastAPI, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from gateway.execution.client import LauncherError, LauncherRequest
from gateway.execution.protocol import ToolResultEnvelope
from gateway.launcher.config import LauncherSettings, load_launcher_settings
from gateway.launcher.service import DockerExecutionLauncher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_launcher_app(
    *,
    settings: LauncherSettings | None = None,
    launcher: DockerExecutionLauncher | None = None,
) -> FastAPI:
    resolved = settings or load_launcher_settings()
    service = launcher or DockerExecutionLauncher(resolved, docker_client=docker.from_env())
    app = FastAPI(
        title="Secure Agent Worker Launcher",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/executions", response_model=ToolResultEnvelope)
    async def execute(payload: LauncherRequest) -> ToolResultEnvelope:
        try:
            return await asyncio.to_thread(service.execute, payload.grant)
        except LauncherError as exc:
            logger.warning("execution rejected code=%s", exc.code)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "execution_rejected"},
            ) from exc

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Any, _exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"error": "invalid_launcher_request"},
        )

    return app
