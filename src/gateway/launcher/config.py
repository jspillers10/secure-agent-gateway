"""Fail-closed Launcher configuration loaded only by the Launcher service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class LauncherConfigurationError(RuntimeError):
    pass


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise LauncherConfigurationError(f"cannot read required credential file: {path}") from exc


@dataclass(frozen=True, slots=True)
class LauncherSettings:
    grant_public_key_pem: str
    grant_issuer: str
    grant_audience: str
    worker_image_reference: str
    execution_timeout_seconds: int
    output_limit_bytes: int
    memory_limit: str
    nano_cpus: int
    pids_limit: int
    egress_socket_volume: str = "secure-agent-gateway_egress_socket"
    egress_socket_path: str = "/run/secure-agent-egress/broker.sock"
    egress_server_hostname: str = "egress-broker"
    egress_server_ca_pem: str = ""
    worker_ca_private_key_pem: str = ""
    worker_ca_certificate_pem: str = ""


def load_launcher_settings(env: dict[str, str] | None = None) -> LauncherSettings:
    source = env if env is not None else dict(os.environ)
    required = ["GRANT_PUBLIC_KEY_FILE", "WORKER_IMAGE_REFERENCE"]
    missing = [name for name in required if not source.get(name)]
    if missing:
        raise LauncherConfigurationError(
            f"missing required Launcher environment variables: {', '.join(missing)}"
        )
    timeout = int(source.get("WORKER_EXECUTION_TIMEOUT_SECONDS", "5"))
    output_limit = int(source.get("WORKER_OUTPUT_LIMIT_BYTES", "524288"))
    nano_cpus = int(source.get("WORKER_NANO_CPUS", "500000000"))
    pids_limit = int(source.get("WORKER_PIDS_LIMIT", "64"))
    if not 1 <= timeout <= 60:
        raise LauncherConfigurationError("worker timeout must be between 1 and 60 seconds")
    if not 1024 <= output_limit <= 1024 * 1024:
        raise LauncherConfigurationError("worker output limit must be between 1 KiB and 1 MiB")
    if not 10_000_000 <= nano_cpus <= 2_000_000_000:
        raise LauncherConfigurationError("worker CPU limit is outside the prototype bounds")
    if not 1 <= pids_limit <= 256:
        raise LauncherConfigurationError("worker PID limit is outside the prototype bounds")
    return LauncherSettings(
        grant_public_key_pem=_read(source["GRANT_PUBLIC_KEY_FILE"]),
        grant_issuer=source.get("GRANT_ISSUER", "secure-agent-gateway"),
        grant_audience=source.get("GRANT_AUDIENCE", "secure-agent-worker-launcher"),
        worker_image_reference=source["WORKER_IMAGE_REFERENCE"],
        execution_timeout_seconds=timeout,
        output_limit_bytes=output_limit,
        memory_limit=source.get("WORKER_MEMORY_LIMIT", "128m"),
        nano_cpus=nano_cpus,
        pids_limit=pids_limit,
        egress_socket_volume=source.get(
            "EGRESS_SOCKET_VOLUME", "secure-agent-gateway_egress_socket"
        ),
        egress_socket_path=source.get(
            "EGRESS_SOCKET_PATH", "/run/secure-agent-egress/broker.sock"
        ),
        egress_server_hostname=source.get("EGRESS_SERVER_HOSTNAME", "egress-broker"),
        egress_server_ca_pem=(
            _read(source["EGRESS_SERVER_CA_CERT_FILE"])
            if source.get("EGRESS_SERVER_CA_CERT_FILE")
            else ""
        ),
        worker_ca_private_key_pem=(
            _read(source["WORKER_CLIENT_CA_KEY_FILE"])
            if source.get("WORKER_CLIENT_CA_KEY_FILE")
            else ""
        ),
        worker_ca_certificate_pem=(
            _read(source["WORKER_CLIENT_CA_CERT_FILE"])
            if source.get("WORKER_CLIENT_CA_CERT_FILE")
            else ""
        ),
    )
