"""Server-side configuration. All values are read from the environment.

There are no default cryptographic secrets. If a required value is missing
or invalid, including an attempt to configure a JWT algorithm other than
RS256, startup fails closed (the process refuses to serve traffic) rather
than falling back to an insecure default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from gateway.egress.url_policy import DestinationPolicyError, canonicalize_https_url

# RS256 is the only algorithm this gateway will ever verify tokens with.
# It is intentionally not a free-form setting: SUPPORTED_JWT_ALGORITHMS is
# a set of exactly one, and load_settings() rejects any other value
# (including "HS256", "none", or a typo) at startup, before the process
# ever serves traffic. See src/gateway/identity/tokens.py for why a
# single-algorithm allow-list is what actually prevents algorithm
# confusion attacks.
SUPPORTED_JWT_ALGORITHMS = frozenset({"RS256"})


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class Settings:
    issuer: str
    audience: str
    jwt_public_key: str
    jwt_algorithm: str
    opa_url: str
    approver_api_key: str
    approver_identity: str
    policy_timeout_seconds: float
    launcher_url: str
    launcher_timeout_seconds: float
    execution_grant_private_key: str
    execution_grant_public_key: str
    execution_grant_issuer: str
    execution_grant_audience: str
    execution_grant_ttl_seconds: int
    internal_ca_cert_file: str
    gateway_client_cert_file: str
    gateway_client_key_file: str
    web_fetch_allowed_origins: tuple[str, ...] = (
        "https://example.com",
        "https://www.example.com",
    )
    web_fetch_max_redirects: int = 3
    web_fetch_max_response_bytes: int = 65_536
    web_fetch_timeout_seconds: float = 5.0


def _read_public_key(env: dict[str, str]) -> str:
    inline = env.get("JWT_PUBLIC_KEY")
    if inline:
        return inline
    path = env.get("JWT_PUBLIC_KEY_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                return handle.read()
        except OSError as exc:
            raise ConfigurationError(f"cannot read JWT_PUBLIC_KEY_FILE={path!r}: {exc}") from exc
    raise ConfigurationError("one of JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_FILE must be set")


def _read_inline_or_file(env: dict[str, str], *, inline_name: str, file_name: str) -> str:
    inline = env.get(inline_name)
    if inline:
        return inline
    path = env.get(file_name)
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                return handle.read()
        except OSError as exc:
            raise ConfigurationError(f"cannot read {file_name}={path!r}: {exc}") from exc
    raise ConfigurationError(f"one of {inline_name} or {file_name} must be set")


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Load settings from the environment, failing closed on any gap."""
    source = env if env is not None else dict(os.environ)

    required = [
        "JWT_ISSUER",
        "JWT_AUDIENCE",
        "OPA_URL",
        "LAUNCHER_URL",
        "APPROVER_API_KEY",
        "APPROVER_IDENTITY",
        "INTERNAL_CA_CERT_FILE",
        "GATEWAY_CLIENT_CERT_FILE",
        "GATEWAY_CLIENT_KEY_FILE",
    ]
    missing = [key for key in required if not source.get(key)]
    if missing:
        raise ConfigurationError(f"missing required environment variables: {', '.join(missing)}")

    jwt_algorithm = source.get("JWT_ALGORITHM", "RS256")
    if jwt_algorithm not in SUPPORTED_JWT_ALGORITHMS:
        raise ConfigurationError(
            f"unsupported JWT_ALGORITHM={jwt_algorithm!r}; "
            f"only {sorted(SUPPORTED_JWT_ALGORITHMS)} is accepted"
        )

    grant_ttl = int(source.get("EXECUTION_GRANT_TTL_SECONDS", "30"))
    if not 1 <= grant_ttl <= 300:
        raise ConfigurationError("EXECUTION_GRANT_TTL_SECONDS must be between 1 and 300")
    for endpoint_name in ("OPA_URL", "LAUNCHER_URL"):
        if not source[endpoint_name].startswith("https://"):
            raise ConfigurationError(f"{endpoint_name} must use https://")

    raw_origins = source.get(
        "WEB_FETCH_ALLOWED_ORIGINS", "https://example.com,https://www.example.com"
    )
    origins: list[str] = []
    try:
        for raw_origin in raw_origins.split(","):
            canonical = canonicalize_https_url(raw_origin.strip())
            if canonical.value != f"{canonical.origin}/":
                raise ConfigurationError("WEB_FETCH_ALLOWED_ORIGINS entries must be origins")
            origins.append(canonical.origin)
    except DestinationPolicyError as exc:
        raise ConfigurationError(f"invalid WEB_FETCH_ALLOWED_ORIGINS: {exc.code}") from exc
    if not origins or len(origins) > 16 or len(set(origins)) != len(origins):
        raise ConfigurationError("WEB_FETCH_ALLOWED_ORIGINS must contain 1-16 unique origins")
    max_redirects = int(source.get("WEB_FETCH_MAX_REDIRECTS", "3"))
    max_response_bytes = int(source.get("WEB_FETCH_MAX_RESPONSE_BYTES", "65536"))
    fetch_timeout = float(source.get("WEB_FETCH_TIMEOUT_SECONDS", "5.0"))
    if not 0 <= max_redirects <= 5:
        raise ConfigurationError("WEB_FETCH_MAX_REDIRECTS must be between 0 and 5")
    if not 1024 <= max_response_bytes <= 1024 * 1024:
        raise ConfigurationError("WEB_FETCH_MAX_RESPONSE_BYTES must be between 1 KiB and 1 MiB")
    if not 0.1 <= fetch_timeout <= 30.0:
        raise ConfigurationError("WEB_FETCH_TIMEOUT_SECONDS must be between 0.1 and 30")

    return Settings(
        issuer=source["JWT_ISSUER"],
        audience=source["JWT_AUDIENCE"],
        jwt_public_key=_read_public_key(source),
        jwt_algorithm=jwt_algorithm,
        opa_url=source["OPA_URL"],
        approver_api_key=source["APPROVER_API_KEY"],
        approver_identity=source["APPROVER_IDENTITY"],
        policy_timeout_seconds=float(source.get("POLICY_TIMEOUT_SECONDS", "2.0")),
        launcher_url=source["LAUNCHER_URL"],
        launcher_timeout_seconds=float(source.get("LAUNCHER_TIMEOUT_SECONDS", "10.0")),
        execution_grant_private_key=_read_inline_or_file(
            source,
            inline_name="EXECUTION_GRANT_PRIVATE_KEY",
            file_name="EXECUTION_GRANT_PRIVATE_KEY_FILE",
        ),
        execution_grant_public_key=_read_inline_or_file(
            source,
            inline_name="EXECUTION_GRANT_PUBLIC_KEY",
            file_name="EXECUTION_GRANT_PUBLIC_KEY_FILE",
        ),
        execution_grant_issuer=source.get("EXECUTION_GRANT_ISSUER", "secure-agent-gateway"),
        execution_grant_audience=source.get(
            "EXECUTION_GRANT_AUDIENCE", "secure-agent-worker-launcher"
        ),
        execution_grant_ttl_seconds=grant_ttl,
        internal_ca_cert_file=source["INTERNAL_CA_CERT_FILE"],
        gateway_client_cert_file=source["GATEWAY_CLIENT_CERT_FILE"],
        gateway_client_key_file=source["GATEWAY_CLIENT_KEY_FILE"],
        web_fetch_allowed_origins=tuple(origins),
        web_fetch_max_redirects=max_redirects,
        web_fetch_max_response_bytes=max_response_bytes,
        web_fetch_timeout_seconds=fetch_timeout,
    )
