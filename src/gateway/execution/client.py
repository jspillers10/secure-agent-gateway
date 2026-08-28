"""Gateway contract for the narrow Worker Launcher / Execution Service."""

from __future__ import annotations

import ssl
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from gateway.execution.protocol import ExecutionGrant, ToolResultEnvelope


class LauncherError(Exception):
    def __init__(self, code: str = "launcher_unavailable") -> None:
        super().__init__(code)
        self.code = code


class LauncherRequest(BaseModel):
    """The complete public Launcher API: one signed grant and no runtime flags."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant: ExecutionGrant


class LauncherClient(Protocol):
    async def execute(self, grant: ExecutionGrant) -> ToolResultEnvelope: ...


def create_mtls_client_context(*, ca_file: str, cert_file: str, key_file: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


class LauncherHttpClient:
    def __init__(self, base_url: str, *, ssl_context: ssl.SSLContext, timeout: float) -> None:
        self._endpoint = f"{base_url.rstrip('/')}/v1/executions"
        self._ssl_context = ssl_context
        self._timeout = timeout

    async def execute(self, grant: ExecutionGrant) -> ToolResultEnvelope:
        try:
            async with httpx.AsyncClient(
                verify=self._ssl_context,
                timeout=self._timeout,
            ) as client:
                response = await client.post(
                    self._endpoint,
                    json=LauncherRequest(grant=grant).model_dump(mode="json"),
                )
            response.raise_for_status()
            return ToolResultEnvelope.model_validate(response.json())
        except (httpx.HTTPError, ValidationError, ValueError, TypeError) as exc:
            raise LauncherError() from exc
