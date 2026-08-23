from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.approvals.store import ApprovalStore
from gateway.config import Settings
from gateway.main import create_app
from tests.helpers.fake_policy import FakePolicyClient
from tests.helpers.keys import generate_rsa_keypair, mint_token

ISSUER = "https://issuer.test"
AUDIENCE = "secure-agent-gateway"


@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[str, str]:
    return generate_rsa_keypair()


@pytest.fixture
def settings(rsa_keypair: tuple[str, str]) -> Settings:
    _private, public = rsa_keypair
    return Settings(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwt_public_key=public,
        jwt_algorithm="RS256",
        opa_url="http://opa.invalid:8181",  # unit tests never actually contact OPA
        approver_api_key="test-approver-key",
        approver_identity="test-approver-identity",
        policy_timeout_seconds=1.0,
    )


@pytest.fixture
def fake_policy_client() -> FakePolicyClient:
    return FakePolicyClient()


@pytest.fixture
def approval_store() -> ApprovalStore:
    return ApprovalStore()


@pytest.fixture
def app(
    settings: Settings, fake_policy_client: FakePolicyClient, approval_store: ApprovalStore
) -> FastAPI:
    return create_app(
        settings=settings, policy_client=fake_policy_client, approval_store=approval_store
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
