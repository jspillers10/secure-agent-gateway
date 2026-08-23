"""Server-side configuration. All values are read from the environment.

There are no default cryptographic secrets. If a required value is missing
or invalid, including an attempt to configure a JWT algorithm other than
RS256, startup fails closed (the process refuses to serve traffic) rather
than falling back to an insecure default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

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


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Load settings from the environment, failing closed on any gap."""
    source = env if env is not None else dict(os.environ)

    required = [
        "JWT_ISSUER",
        "JWT_AUDIENCE",
        "OPA_URL",
        "APPROVER_API_KEY",
        "APPROVER_IDENTITY",
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

    return Settings(
        issuer=source["JWT_ISSUER"],
        audience=source["JWT_AUDIENCE"],
        jwt_public_key=_read_public_key(source),
        jwt_algorithm=jwt_algorithm,
        opa_url=source["OPA_URL"],
        approver_api_key=source["APPROVER_API_KEY"],
        approver_identity=source["APPROVER_IDENTITY"],
        policy_timeout_seconds=float(source.get("POLICY_TIMEOUT_SECONDS", "2.0")),
    )
