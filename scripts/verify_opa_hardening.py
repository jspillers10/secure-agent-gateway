#!/usr/bin/env python
"""Verify OPA hardening against the live Docker Compose stack.

Unlike scripts/smoke_test.py (which only talks to the gateway's published
port), this script talks to OPA directly, which, in the hardened
topology, has no port published to the host at all (see docker-compose.yml
and docs/architecture.md for why). It must therefore run from *inside*
the same internal Docker network the compose stack creates. internal_net
has no egress, so a plain Python image can't `pip install` anything
there; reuse the already-built gateway image, which already has httpx
as a project dependency:

    docker compose up -d --build
    docker run --rm --network secure-agent-gateway_internal_net \\
        -v "$(pwd)/scripts:/scripts:ro" \\
        --entrypoint python secure-agent-gateway-gateway \\
        /scripts/verify_opa_hardening.py

It proves two things a Rego-only `opa test` run cannot: that the real,
running OPA server (not just the policy source) rejects administrative
mutation of its own policy, and that a compromised-gateway-style input
carrying spoofed required_scope/risk fields is ignored by the real server,
not just by the Rego test suite or the Python FakePolicyClient mirror.
"""

from __future__ import annotations

import ssl
import sys

import httpx

OPA_URL = "https://opa:8181"
CA_FILE = "/keys/internal-server-ca-cert.pem"
CLIENT_CERT = "/keys/gateway-client-cert.pem"
CLIENT_KEY = "/keys/gateway-client-key.pem"


def main() -> int:
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        status = "PASS" if condition else "FAIL"
        print(f"[{status}] {name}" + (f": {detail}" if detail and not condition else ""))
        if not condition:
            failures.append(name)

    tls_context = ssl.create_default_context(cafile=CA_FILE)
    tls_context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    with httpx.Client(
        base_url=OPA_URL,
        timeout=10.0,
        verify=tls_context,
    ) as client:
        health_resp = client.get("/health")
        check("OPA health check reachable", health_resp.status_code == 200, health_resp.text)

        real_query_resp = client.post(
            "/v1/data/gateway/authz/result",
            json={
                "input": {
                    "agent_id": "agent-verify",
                    "delegated_user_id": "user-verify",
                    "scopes": ["documents.read"],
                    "tool": "documents.read",
                    "approval_state": "none",
                }
            },
        )
        check(
            "gateway authz query allowed",
            real_query_resp.status_code == 200
            and real_query_resp.json().get("result", {}).get("decision") == "allow",
            real_query_resp.text,
        )

        spoofed_resp = client.post(
            "/v1/data/gateway/authz/result",
            json={
                "input": {
                    "agent_id": "agent-verify",
                    "delegated_user_id": "user-verify",
                    "scopes": ["documents.read"],
                    "tool": "admin.rotate_key",
                    "approval_state": "none",
                    # A compromised gateway trying to smuggle a weaker
                    # scope/risk past the policy. Real OPA must ignore
                    # both fields entirely and deny based on its own
                    # `tools` mapping for admin.rotate_key.
                    "required_scope": "documents.read",
                    "risk": "low",
                }
            },
        )
        check(
            "spoofed required_scope/risk ignored (compromised-gateway regression)",
            spoofed_resp.status_code == 200
            and spoofed_resp.json().get("result", {}).get("decision") == "deny",
            spoofed_resp.text,
        )

        policy_put_resp = client.put(
            "/v1/policies/evil", content=b"package evil", headers={"Content-Type": "text/plain"}
        )
        check(
            "policy mutation via PUT rejected",
            policy_put_resp.status_code == 401,
            f"status={policy_put_resp.status_code} body={policy_put_resp.text}",
        )

        policy_delete_resp = client.delete("/v1/policies/gateway")
        check(
            "policy deletion via DELETE rejected",
            policy_delete_resp.status_code == 401,
            f"status={policy_delete_resp.status_code} body={policy_delete_resp.text}",
        )

        data_snoop_resp = client.get("/v1/data")
        check(
            "data introspection via GET /v1/data rejected",
            data_snoop_resp.status_code == 401,
            f"status={data_snoop_resp.status_code} body={data_snoop_resp.text}",
        )

    if failures:
        print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1

    print("\nAll OPA hardening checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
