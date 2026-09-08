"""Fail-closed, server-owned egress broker configuration."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from gateway.egress.broker import EgressBrokerSettings
from gateway.egress.url_policy import canonicalize_https_url


class EgressConfigurationError(RuntimeError):
    pass


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise EgressConfigurationError(f"cannot read required egress credential: {path}") from exc


@dataclass(frozen=True, slots=True)
class EgressServiceSettings:
    broker: EgressBrokerSettings
    socket_path: str
    server_certificate_file: str
    server_key_file: str
    worker_ca_certificate_file: str
    upstream_ca_file: str | None


def load_egress_settings(env: dict[str, str] | None = None) -> EgressServiceSettings:
    source = env if env is not None else dict(os.environ)
    required = (
        "EGRESS_SOCKET_PATH",
        "EGRESS_SERVER_CERT_FILE",
        "EGRESS_SERVER_KEY_FILE",
        "WORKER_CLIENT_CA_CERT_FILE",
        "GRANT_PUBLIC_KEY_FILE",
        "EGRESS_ALLOWED_ORIGINS",
        "EGRESS_DENIED_CIDRS",
    )
    missing = [key for key in required if not source.get(key)]
    if missing:
        raise EgressConfigurationError(f"missing egress settings: {', '.join(missing)}")
    origins: set[str] = set()
    for item in source["EGRESS_ALLOWED_ORIGINS"].split(","):
        canonical = canonicalize_https_url(item.strip())
        if canonical.value != f"{canonical.origin}/":
            raise EgressConfigurationError("egress allowlist entries must be origins")
        origins.add(canonical.origin)
    if not origins or len(origins) > 16:
        raise EgressConfigurationError("egress allowlist must contain 1-16 origins")
    denied_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    denied_items = [item.strip() for item in source["EGRESS_DENIED_CIDRS"].split(",")]
    if not denied_items or any(not item for item in denied_items) or len(denied_items) > 32:
        raise EgressConfigurationError("egress denied CIDRs must contain 1-32 networks")
    for item in denied_items:
        try:
            denied_networks.add(ipaddress.ip_network(item, strict=True))
        except ValueError as exc:
            raise EgressConfigurationError("invalid deployment-specific denied CIDR") from exc
    max_redirects = int(source.get("EGRESS_MAX_REDIRECTS", "3"))
    max_bytes = int(source.get("EGRESS_MAX_RESPONSE_BYTES", "65536"))
    max_timeout = float(source.get("EGRESS_MAX_TIMEOUT_SECONDS", "5.0"))
    if not 0 <= max_redirects <= 5 or not 1024 <= max_bytes <= 1024 * 1024:
        raise EgressConfigurationError("egress limits outside prototype bounds")
    if not 0.1 <= max_timeout <= 30.0:
        raise EgressConfigurationError("egress timeout outside prototype bounds")
    ca_file = source.get("EGRESS_UPSTREAM_CA_FILE")
    return EgressServiceSettings(
        broker=EgressBrokerSettings(
            grant_public_key_pem=_read(source["GRANT_PUBLIC_KEY_FILE"]),
            grant_issuer=source.get("GRANT_ISSUER", "secure-agent-gateway"),
            grant_audience=source.get("GRANT_AUDIENCE", "secure-agent-worker-launcher"),
            worker_ca_certificate_pem=_read(source["WORKER_CLIENT_CA_CERT_FILE"]),
            allowed_origins=frozenset(origins),
            denied_networks=tuple(
                sorted(
                    denied_networks,
                    key=lambda network: (
                        network.version,
                        int(network.network_address),
                        network.prefixlen,
                    ),
                )
            ),
            max_redirects=max_redirects,
            max_response_bytes=max_bytes,
            max_timeout_seconds=max_timeout,
        ),
        socket_path=source["EGRESS_SOCKET_PATH"],
        server_certificate_file=source["EGRESS_SERVER_CERT_FILE"],
        server_key_file=source["EGRESS_SERVER_KEY_FILE"],
        worker_ca_certificate_file=source["WORKER_CLIENT_CA_CERT_FILE"],
        upstream_ca_file=ca_file,
    )
