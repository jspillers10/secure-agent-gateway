"""Worker-side client for the TLS-over-Unix-socket egress protocol."""

from __future__ import annotations

import json
import os
import socket
import ssl
import tempfile
from pathlib import Path

from pydantic import ValidationError

from gateway.egress.protocol import BrokerFetchRequest, BrokerFetchResult


class EgressClientError(Exception):
    pass


class UnixTlsEgressClient:
    def __init__(
        self,
        *,
        socket_path: str,
        server_hostname: str,
        server_ca_pem: str,
        client_certificate_pem: str,
        client_private_key_pem: str,
        timeout_seconds: float,
    ) -> None:
        self._socket_path = socket_path
        self._server_hostname = server_hostname
        self._server_ca_pem = server_ca_pem
        self._client_certificate_pem = client_certificate_pem
        self._client_private_key_pem = client_private_key_pem
        self._timeout_seconds = timeout_seconds

    def fetch(self, request: BrokerFetchRequest) -> BrokerFetchResult:
        context = ssl.create_default_context(cadata=self._server_ca_pem)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        cert_path: str | None = None
        key_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", delete=False
            ) as cert_file:
                cert_file.write(self._client_certificate_pem)
                cert_path = cert_file.name
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", delete=False
            ) as key_file:
                key_file.write(self._client_private_key_pem)
                key_path = key_file.name
            os.chmod(cert_path, 0o600)
            os.chmod(key_path, 0o600)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        finally:
            for path in (cert_path, key_path):
                if path is not None:
                    Path(path).unlink(missing_ok=True)

        unix_family = getattr(socket, "AF_UNIX", 1)
        raw = socket.socket(unix_family, socket.SOCK_STREAM)
        tls_socket: ssl.SSLSocket | None = None
        try:
            raw.settimeout(self._timeout_seconds)
            raw.connect(self._socket_path)
            tls_socket = context.wrap_socket(raw, server_hostname=self._server_hostname)
            encoded = request.model_dump_json().encode("utf-8")
            if len(encoded) > 128 * 1024:
                raise EgressClientError("broker_request_too_large")
            tls_socket.sendall(encoded + b"\n")
            response = self._readline(tls_socket, 1024 * 1024)
            try:
                result = BrokerFetchResult.model_validate(json.loads(response))
            except (json.JSONDecodeError, ValidationError) as exc:
                raise EgressClientError("broker_response_invalid") from exc
            if result.status != "succeeded":
                raise EgressClientError(result.error_code or "broker_denied")
            return result
        except (OSError, ssl.SSLError) as exc:
            raise EgressClientError("broker_connection_failed") from exc
        finally:
            if tls_socket is not None:
                tls_socket.close()
            else:
                raw.close()

    @staticmethod
    def _readline(sock: ssl.SSLSocket, limit: int) -> bytes:
        output = bytearray()
        while len(output) <= limit:
            chunk = sock.recv(min(16_384, limit + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if b"\n" in chunk:
                break
        if len(output) > limit or not output.endswith(b"\n") or output.count(b"\n") != 1:
            raise EgressClientError("broker_response_invalid")
        return bytes(output[:-1])
