from __future__ import annotations

import dataclasses
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from scripts.generate_dev_keys import _create_ca

from gateway.execution.audit import LAUNCHER_AUDIT_LOGGER_NAME
from gateway.execution.client import LauncherError, LauncherRequest
from gateway.execution.protocol import ActionEnvelope, ApprovalBinding, EgressGrant, ToolIdentity
from gateway.execution.signing import ExecutionGrantSigner, sign_tool_result
from gateway.hashing import sha256_hex
from gateway.launcher.config import LauncherSettings
from gateway.launcher.service import DockerExecutionLauncher
from gateway.registry.tools import TOOL_REGISTRY, WORKER_ARTIFACT_DIGEST
from gateway.worker.runtime import WorkerRequest, execute_worker_request
from tests.helpers.keys import generate_rsa_keypair


def _grant(private_key: str, *, tool_name: str = "documents.read") -> object:
    is_web = tool_name == "web.fetch_text"
    arguments = {"url": "https://example.com/"} if is_web else {"document_id": "doc-001"}
    action = ActionEnvelope(
        invocation_id="invocation-launcher",
        request_id="request-launcher",
        correlation_id="correlation-launcher",
        agent_id="agent-001",
        delegated_user_id="user-001",
        tool=ToolIdentity(name=tool_name, artifact_digest=WORKER_ARTIFACT_DIGEST),
        arguments=arguments,
        argument_digest=sha256_hex(arguments),
        approval=ApprovalBinding(required=False, state="not_required"),
        policy_version="test-v1",
        risk="low",
        destination="https://example.com/" if is_web else None,
        created_at=datetime.now(tz=UTC),
    )
    return ExecutionGrantSigner(
        private_key,
        issuer="secure-agent-gateway",
        audience="secure-agent-worker-launcher",
    ).issue(
        action,
        egress=(
            EgressGrant(initial_url="https://example.com/", allowed_origins=("https://example.com",))
            if is_web
            else None
        ),
    )


class _Socket:
    def __init__(self) -> None:
        self.payload = b""
        self.closed = False

    def sendall(self, value: bytes) -> None:
        self.payload += value

    def shutdown(self, _how: object) -> None:
        pass


class _Attached:
    def __init__(self) -> None:
        self._sock = _Socket()

    def close(self) -> None:
        self.closed = True


class _Container:
    def __init__(self, *, mode: str) -> None:
        self.mode = mode
        self.attached = _Attached()
        self.removed: tuple[bool, bool] | None = None

    def attach_socket(self, *, params: dict[str, int]) -> _Attached:
        assert params == {"stdin": 1, "stream": 1}
        return self.attached

    def start(self) -> None:
        if self.mode == "start-failure":
            raise RuntimeError("simulated Docker start failure")

    def wait(self, *, timeout: int) -> dict[str, int]:
        assert timeout == 5
        if self.mode == "timeout":
            raise TimeoutError("simulated timeout")
        return {"StatusCode": 0 if self.mode != "exit-failure" else 1}

    def logs(self, *, stdout: bool, stderr: bool) -> bytes:
        assert stdout and not stderr
        if self.mode == "oversize":
            return b"x" * 2049
        request = WorkerRequest.model_validate_json(self.attached._sock.payload.strip())
        if self.mode == "wrong-invocation":
            now = datetime.now(tz=UTC)
            return sign_tool_result(
                {
                    "protocol_version": "1.0",
                    "invocation_id": "wrong-invocation",
                    "grant_nonce": request.grant.nonce,
                    "worker_id": request.worker_id,
                    "tool": request.grant.action.tool.model_dump(mode="json"),
                    "status": "succeeded",
                    "result": {"ok": True},
                    "result_digest": sha256_hex({"ok": True}),
                    "error_code": None,
                    "started_at": now.isoformat(),
                    "completed_at": now.isoformat(),
                },
                request.result_private_key_pem,
            ).model_dump_json().encode()
        return execute_worker_request(request).model_dump_json().encode()

    def remove(self, *, force: bool, v: bool) -> None:
        self.removed = (force, v)
        if self.mode == "cleanup-failure":
            raise RuntimeError("simulated cleanup failure")

    def reload(self) -> None:
        pass

    attrs = {"State": {"Status": "failed", "Error": "simulated"}}


class _Images:
    def __init__(self, *, artifact_digest: str = WORKER_ARTIFACT_DIGEST) -> None:
        self.artifact_digest = artifact_digest

    def get(self, reference: str) -> object:
        assert reference == "secure-agent-gateway-worker:milestone1"
        return type(
            "Image",
            (),
            {
                "id": "sha256:" + "a" * 64,
                "attrs": {
                    "Config": {
                        "Labels": {"org.secure-agent.artifact-digest": self.artifact_digest}
                    }
                },
            },
        )()


class _Containers:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.calls: list[dict[str, Any]] = []
        self.created: list[_Container] = []

    def create(self, **kwargs: Any) -> _Container:
        self.calls.append(kwargs)
        container = _Container(mode=self.mode)
        self.created.append(container)
        return container


class _Docker:
    def __init__(self, *, mode: str = "success", artifact_digest: str = WORKER_ARTIFACT_DIGEST):
        self.images = _Images(artifact_digest=artifact_digest)
        self.containers = _Containers(mode)


def _launcher(
    *,
    mode: str = "success",
    artifact_digest: str = WORKER_ARTIFACT_DIGEST,
    with_egress_identity: bool = False,
):
    private_key, public_key = generate_rsa_keypair()
    docker = _Docker(mode=mode, artifact_digest=artifact_digest)
    worker_ca_private = ""
    worker_ca_certificate = ""
    if with_egress_identity:
        ca_key, ca_certificate = _create_ca("launcher-test-worker-ca")
        worker_ca_private = ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        worker_ca_certificate = ca_certificate.public_bytes(serialization.Encoding.PEM).decode()
    settings = LauncherSettings(
        grant_public_key_pem=public_key,
        grant_issuer="secure-agent-gateway",
        grant_audience="secure-agent-worker-launcher",
        worker_image_reference="secure-agent-gateway-worker:milestone1",
        execution_timeout_seconds=5,
        output_limit_bytes=2048,
        memory_limit="128m",
        nano_cpus=500_000_000,
        pids_limit=64,
        egress_server_ca_pem="test-server-ca" if with_egress_identity else "",
        worker_ca_private_key_pem=worker_ca_private,
        worker_ca_certificate_pem=worker_ca_certificate,
    )
    return DockerExecutionLauncher(settings, docker_client=docker), docker, private_key


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "attacker/image"),
        ("command", ["sh", "-c", "id"]),
        ("mounts", ["/:/host"]),
        ("capabilities", ["SYS_ADMIN"]),
        ("network", "host"),
        ("host_path", "/var/run/docker.sock"),
        ("runtime_flags", {"privileged": True}),
    ],
)
def test_launcher_api_rejects_every_caller_runtime_control(field: str, value: object) -> None:
    private_key, _ = generate_rsa_keypair()
    payload = {"grant": _grant(private_key).model_dump(mode="json"), field: value}  # type: ignore[union-attr]
    with pytest.raises(ValidationError):
        LauncherRequest.model_validate(payload)


def test_launcher_owns_hardened_runtime_configuration_and_returns_fixture_result() -> None:
    launcher, docker, private_key = _launcher()
    result = launcher.execute(_grant(private_key))  # type: ignore[arg-type]
    assert result.status == "succeeded"
    assert result.result == {
        "document_id": "doc-001",
        "content": "Q3 planning notes (mock content).",
    }
    options = docker.containers.calls[0]
    assert options["image"].startswith("sha256:")
    assert options["entrypoint"] == ["python", "-m", "gateway.worker.main"]
    assert options["network_disabled"] is True
    assert options["user"] == "10001:10001"
    assert options["read_only"] is True
    assert options["cap_drop"] == ["ALL"]
    assert options["security_opt"] == ["no-new-privileges:true"]
    assert options["mem_limit"] == "128m"
    assert options["nano_cpus"] == 500_000_000
    assert options["pids_limit"] == 64
    assert options["tmpfs"] == {"/tmp": "rw,noexec,nosuid,nodev,size=16m"}  # noqa: S108
    assert options["log_config"] == {
        "type": "local",
        "config": {"max-size": "1m", "max-file": "1", "compress": "false"},
    }
    assert not ({"volumes", "mounts", "network", "privileged", "devices"} & options.keys())
    assert docker.containers.created[0].removed == (True, True)


def test_web_worker_remains_network_disabled_and_receives_only_fixed_broker_socket() -> None:
    launcher, docker, private_key = _launcher(with_egress_identity=True)
    result = launcher.execute(_grant(private_key, tool_name="web.fetch_text"))  # type: ignore[arg-type]
    assert result.status == "failed"  # the unit fake intentionally has no live Unix socket
    options = docker.containers.calls[0]
    assert options["network_disabled"] is True
    assert options["volumes"] == {
        "secure-agent-gateway_egress_socket": {
            "bind": "/run/secure-agent-egress",
            "mode": "ro",
        }
    }
    assert options["group_add"] == ["20000"]
    assert "network" not in options
    request = WorkerRequest.model_validate_json(
        docker.containers.created[0].attached._sock.payload.strip()
    )
    assert request.egress_socket_path == "/run/secure-agent-egress/broker.sock"
    assert request.egress_client_certificate_pem is not None
    certificate = x509.load_pem_x509_certificate(
        request.egress_client_certificate_pem.encode("utf-8")
    )
    uris = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == [
        "spiffe://secure-agent-gateway/worker/"
        f"{request.grant.action.invocation_id}/{request.worker_id}"
    ]


def test_each_accepted_invocation_has_one_launcher_terminal_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    launcher, _docker, private_key = _launcher()
    with caplog.at_level(logging.INFO, logger=LAUNCHER_AUDIT_LOGGER_NAME):
        launcher.execute(_grant(private_key))  # type: ignore[arg-type]
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == LAUNCHER_AUDIT_LOGGER_NAME
    ]
    assert [event["event"] for event in events].count("accepted") == 1
    assert [event["event"] for event in events].count("terminal") == 1


def test_unknown_tool_and_unregistered_artifact_never_create_container() -> None:
    launcher, docker, private_key = _launcher()
    with pytest.raises(LauncherError, match="unknown_tool"):
        launcher.execute(_grant(private_key, tool_name="unknown.tool"))  # type: ignore[arg-type]
    assert docker.containers.calls == []

    launcher, docker, private_key = _launcher(artifact_digest="sha256:" + "0" * 64)
    with pytest.raises(LauncherError, match="worker_artifact_mismatch"):
        launcher.execute(_grant(private_key))  # type: ignore[arg-type]
    assert docker.containers.calls == []


@pytest.mark.parametrize(
    "mode", ["start-failure", "timeout", "exit-failure", "oversize", "cleanup-failure"]
)
def test_resource_and_worker_failures_are_contained_and_cleaned_up(mode: str) -> None:
    launcher, docker, private_key = _launcher(mode=mode)
    with pytest.raises(LauncherError):
        launcher.execute(_grant(private_key))  # type: ignore[arg-type]
    assert docker.containers.created[0].removed == (True, True)


def test_result_from_wrong_worker_invocation_is_rejected() -> None:
    launcher, docker, private_key = _launcher(mode="wrong-invocation")
    with pytest.raises(LauncherError, match="worker_protocol_error"):
        launcher.execute(_grant(private_key))  # type: ignore[arg-type]
    assert docker.containers.created[0].removed == (True, True)


def test_compose_mounts_orchestration_socket_only_into_launcher() -> None:
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose.count("/var/run/docker.sock:/var/run/docker.sock") == 1
    launcher_section = compose.split("  launcher:", 1)[1].split("  gateway:", 1)[0]
    assert "/var/run/docker.sock:/var/run/docker.sock" in launcher_section


def test_compose_broker_is_not_a_worker_network_and_socket_is_narrowly_shared() -> None:
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    broker_section = compose.split("\n  egress-broker:", 1)[1].split("\n  web-fixture:", 1)[0]
    gateway_section = compose.split("\n  gateway:", 1)[1].split("\n  egress-broker:", 1)[0]
    assert "networks: [fixture_net, protected_net]" in broker_section
    assert "egress_socket:/run/secure-agent-egress" in broker_section
    assert "/var/run/docker.sock" not in broker_section
    assert "egress_socket:/run/secure-agent-egress" not in gateway_section
    launcher_source = (
        Path(__file__).parents[1] / "src/gateway/launcher/service.py"
    ).read_text(encoding="utf-8")
    assert "network_disabled=True" in launcher_source


def test_compose_uses_explicit_per_service_credential_mounts() -> None:
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    assert "./devkeys:/keys:ro" not in compose

    sections: dict[str, str] = {}
    for name in (
            "opa",
            "launcher",
            "gateway",
            "ingress",
            "egress-broker",
            "web-fixture",
            "protected-fixture",
    ):
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|^networks:)",
            compose,
        )
        assert match is not None
        sections[name] = match.group(1)
    assert "execution-grant-private.pem" in sections["gateway"]
    assert "worker-client-ca-private.pem" not in sections["gateway"]
    assert "worker-client-ca-private.pem" in sections["launcher"]
    assert "execution-grant-private.pem" not in sections["launcher"]
    assert "-key.pem" not in sections["opa"].replace("opa-key.pem", "")
    assert "execution-grant-private.pem" not in sections["egress-broker"]
    assert "worker-client-ca-private.pem" not in sections["egress-broker"]
    assert "execution-grant-private.pem" not in sections["web-fixture"]
    assert "worker-client-ca-private.pem" not in sections["web-fixture"]
    assert "execution-grant-private.pem" not in sections["protected-fixture"]
    assert "/keys/" not in sections["ingress"]


def test_launcher_failure_cannot_call_gateway_process_handler(
    app: FastAPI,
    client: TestClient,
    make_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def _forbidden_handler(_args: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {"forbidden": True}

    class _FailingLauncher:
        async def execute(self, _grant: object) -> object:
            raise LauncherError("launcher_unavailable")

    monkeypatch.setitem(
        TOOL_REGISTRY,
        "documents.read",
        dataclasses.replace(TOOL_REGISTRY["documents.read"], handler=_forbidden_handler),
    )  # type: ignore[index]
    app.state.launcher_client = _FailingLauncher()
    response = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
        headers={"Authorization": f"Bearer {make_token(scopes=['documents.read'])}"},
    )
    assert response.status_code == 502
    assert response.json()["error"] == "tool_execution_failed"
    assert called is False
