from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.approvals.store import ApprovalStore
from gateway.config import Settings
from gateway.execution.local_launcher import InProcessLauncher
from gateway.execution.signing import ExecutionGrantSigner
from gateway.main import create_app
from tests.helpers.fake_policy import FakePolicyClient
from tests.helpers.keys import generate_rsa_keypair, mint_token

ISSUER = "https://issuer.test"
AUDIENCE = "secure-agent-gateway"


@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[str, str]:
    return generate_rsa_keypair()


@pytest.fixture(scope="session")
def grant_keypair() -> tuple[str, str]:
    return generate_rsa_keypair()


@pytest.fixture
def settings(rsa_keypair: tuple[str, str], grant_keypair: tuple[str, str]) -> Settings:
    _private, public = rsa_keypair
    grant_private, grant_public = grant_keypair
    return Settings(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwt_public_key=public,
        jwt_algorithm="RS256",
        opa_url="http://opa.invalid:8181",  # unit tests never actually contact OPA
        approver_api_key="test-approver-key",
        approver_identity="test-approver-identity",
        policy_timeout_seconds=1.0,
        launcher_url="https://launcher.invalid:8443",
        launcher_timeout_seconds=1.0,
        execution_grant_private_key=grant_private,
        execution_grant_public_key=grant_public,
        execution_grant_issuer="secure-agent-gateway",
        execution_grant_audience="secure-agent-worker-launcher",
        execution_grant_ttl_seconds=30,
        internal_ca_cert_file="not-used-in-unit-tests",
        gateway_client_cert_file="not-used-in-unit-tests",
        gateway_client_key_file="not-used-in-unit-tests",
    )


@pytest.fixture
def fake_policy_client() -> FakePolicyClient:
    return FakePolicyClient()


@pytest.fixture
def approval_store() -> ApprovalStore:
    return ApprovalStore()


@pytest.fixture
def launcher_client(settings: Settings) -> InProcessLauncher:
    return InProcessLauncher(
        grant_public_key_pem=settings.execution_grant_public_key,
        issuer=settings.execution_grant_issuer,
        audience=settings.execution_grant_audience,
    )


@pytest.fixture
def grant_signer(settings: Settings) -> ExecutionGrantSigner:
    return ExecutionGrantSigner(
        settings.execution_grant_private_key,
        issuer=settings.execution_grant_issuer,
        audience=settings.execution_grant_audience,
        ttl_seconds=settings.execution_grant_ttl_seconds,
    )


@pytest.fixture
def app(
    settings: Settings,
    fake_policy_client: FakePolicyClient,
    approval_store: ApprovalStore,
    launcher_client: InProcessLauncher,
    grant_signer: ExecutionGrantSigner,
) -> FastAPI:
    return create_app(
        settings=settings,
        policy_client=fake_policy_client,
        approval_store=approval_store,
        launcher_client=launcher_client,
        grant_signer=grant_signer,
    )


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture
def make_token(rsa_keypair: tuple[str, str]) -> Callable[..., str]:
    private, _public = rsa_keypair

    def _make(**overrides: object) -> str:
        return mint_token(private, issuer=ISSUER, audience=AUDIENCE, **overrides)  # type: ignore[arg-type]

    return _make
