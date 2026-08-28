"""Tests for fail-closed configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from gateway.config import ConfigurationError, load_settings


def _base_env(tmp_public_key_path: str | None = None) -> dict[str, str]:
    env = {
        "JWT_ISSUER": "https://issuer.test",
        "JWT_AUDIENCE": "secure-agent-gateway",
        "JWT_PUBLIC_KEY": "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n",
        "OPA_URL": "https://opa:8181",
        "LAUNCHER_URL": "https://launcher:8443",
        "APPROVER_API_KEY": "dev-only-key",
        "APPROVER_IDENTITY": "dev-only-approver",
        "EXECUTION_GRANT_PRIVATE_KEY": "dev-only-private-key-fixture",
        "EXECUTION_GRANT_PUBLIC_KEY": "dev-only-public-key-fixture",
        "INTERNAL_CA_CERT_FILE": "internal-ca-cert.pem",
        "GATEWAY_CLIENT_CERT_FILE": "gateway-client-cert.pem",
        "GATEWAY_CLIENT_KEY_FILE": "gateway-client-key.pem",
    }
    if tmp_public_key_path:
        del env["JWT_PUBLIC_KEY"]
        env["JWT_PUBLIC_KEY_FILE"] = tmp_public_key_path
    return env


def test_load_settings_succeeds_with_all_required_vars() -> None:
    settings = load_settings(_base_env())
    assert settings.issuer == "https://issuer.test"
    assert settings.jwt_algorithm == "RS256"
    assert settings.approver_identity == "dev-only-approver"
    assert settings.policy_timeout_seconds == 2.0


def test_load_settings_fails_closed_when_vars_missing() -> None:
    with pytest.raises(ConfigurationError):
        load_settings({})


def test_load_settings_fails_closed_when_approver_identity_missing() -> None:
    env = _base_env()
    del env["APPROVER_IDENTITY"]
    with pytest.raises(ConfigurationError):
        load_settings(env)


def test_load_settings_reads_public_key_from_file(tmp_path: Path) -> None:
    key_path = tmp_path / "public.pem"
    key_path.write_text("-----BEGIN PUBLIC KEY-----\nfromfile\n-----END PUBLIC KEY-----\n")
    settings = load_settings(_base_env(tmp_public_key_path=str(key_path)))
    assert "fromfile" in settings.jwt_public_key


def test_load_settings_fails_closed_when_key_file_missing() -> None:
    with pytest.raises(ConfigurationError):
        load_settings(_base_env(tmp_public_key_path="/nonexistent/path/public.pem"))


@pytest.mark.parametrize("bad_algorithm", ["HS256", "none", "None", "RS384", "ES256", ""])
def test_load_settings_rejects_unsupported_jwt_algorithm(bad_algorithm: str) -> None:
    env = _base_env()
    env["JWT_ALGORITHM"] = bad_algorithm
    with pytest.raises(ConfigurationError):
        load_settings(env)


def test_load_settings_accepts_explicit_rs256() -> None:
    env = _base_env()
    env["JWT_ALGORITHM"] = "RS256"
    settings = load_settings(env)
    assert settings.jwt_algorithm == "RS256"


@pytest.mark.parametrize("endpoint", ["OPA_URL", "LAUNCHER_URL"])
def test_internal_service_endpoint_must_use_https(endpoint: str) -> None:
    env = _base_env()
    env[endpoint] = "http://internal-service:8080"
    with pytest.raises(ConfigurationError, match="must use https"):
        load_settings(env)
