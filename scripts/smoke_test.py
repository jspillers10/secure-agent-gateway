#!/usr/bin/env python
"""End-to-end smoke test against a running Docker Compose stack.

Exercises the real gateway container talking to the real OPA container:
this is the check that the Rego policy and the Python policy-input
assembly actually agree with each other, which the hermetic unit tests
(which use a Python test double for the policy client) cannot prove by
themselves.

Usage:
    python scripts/generate_dev_keys.py
    docker compose --profile worker-build build worker-image
    docker compose up -d --build
    python scripts/smoke_test.py
    docker compose down
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import httpx
import jwt

DEVKEYS_DIR = Path(__file__).resolve().parent.parent / "devkeys"
BASE_URL = "http://localhost:8088"
ISSUER = "https://issuer.secure-agent-gateway.local"
AUDIENCE = "secure-agent-gateway"
APPROVER_API_KEY = "dev-only-approver-key-not-a-secret"


def mint_token(private_key: str, *, scopes: list[str], agent_id: str = "agent-smoke") -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": agent_id,
        "agent_id": agent_id,
        "delegated_user": {"id": "user-smoke"},
        "scopes": scopes,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def main() -> int:
    private_key_path = DEVKEYS_DIR / "private.pem"
    if not private_key_path.exists():
        print(f"error: {private_key_path} not found. Run scripts/generate_dev_keys.py first.")
        return 1
    private_key = private_key_path.read_text(encoding="utf-8")

    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        status = "PASS" if condition else "FAIL"
        print(f"[{status}] {name}" + (f": {detail}" if detail and not condition else ""))
        if not condition:
            failures.append(name)

    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        for _attempt in range(20):
            try:
                resp = client.get("/healthz")
                if resp.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            print("error: gateway never became healthy")
            return 1
        check("health check", resp.status_code == 200)

        no_token_resp = client.post(
            "/v1/tool-invocations", json={"tool": "documents.read", "arguments": {}}
        )
        check("missing token rejected", no_token_resp.status_code == 401)

        read_token = mint_token(private_key, scopes=["documents.read"])
        allow_resp = client.post(
            "/v1/tool-invocations",
            json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
            headers={"Authorization": f"Bearer {read_token}"},
        )
        check(
            "valid read request allowed",
            allow_resp.status_code == 200 and allow_resp.json().get("decision") == "allow",
            allow_resp.text,
        )

        unknown_tool_resp = client.post(
            "/v1/tool-invocations",
            json={"tool": "os.system", "arguments": {}},
            headers={"Authorization": f"Bearer {read_token}"},
        )
        check("unknown tool rejected", unknown_tool_resp.status_code == 404)

        escalation_resp = client.post(
            "/v1/tool-invocations",
            json={"tool": "tickets.create", "arguments": {"title": "t", "description": "d"}},
            headers={"Authorization": f"Bearer {read_token}"},
        )
        check(
            "scope escalation attempt denied",
            escalation_resp.status_code == 200 and escalation_resp.json().get("decision") == "deny",
            escalation_resp.text,
        )

        admin_token = mint_token(private_key, scopes=["admin.rotate_key"])
        approval_required_resp = client.post(
            "/v1/tool-invocations",
            json={"tool": "admin.rotate_key", "arguments": {"key_id": "key-1", "reason": "rotate"}},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        check(
            "high-risk tool requires approval",
            approval_required_resp.status_code == 200
            and approval_required_resp.json().get("decision") == "approval-required",
            approval_required_resp.text,
        )

        create_approval_resp = client.post(
            "/v1/approvals",
            json={
                "tool": "admin.rotate_key",
                "arguments": {"key_id": "key-1", "reason": "rotate"},
                "agent_id": "agent-smoke",
                "delegated_user_id": "user-smoke",
            },
            headers={"X-Approver-Key": APPROVER_API_KEY},
        )
        approval_created = create_approval_resp.status_code == 200
        check("approval record created", approval_created, create_approval_resp.text)
        approval_id = create_approval_resp.json().get("approval_id") if approval_created else None

        if approval_id:
            approved_resp = client.post(
                "/v1/tool-invocations",
                json={
                    "tool": "admin.rotate_key",
                    "arguments": {"key_id": "key-1", "reason": "rotate"},
                    "approval_id": approval_id,
                },
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            approved_ok = (
                approved_resp.status_code == 200 and approved_resp.json().get("decision") == "allow"
            )
            check("approved high-risk tool executes", approved_ok, approved_resp.text)

            replay_resp = client.post(
                "/v1/tool-invocations",
                json={
                    "tool": "admin.rotate_key",
                    "arguments": {"key_id": "key-1", "reason": "rotate"},
                    "approval_id": approval_id,
                },
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            check(
                "replayed approval denied",
                replay_resp.status_code == 200 and replay_resp.json().get("decision") == "deny",
                replay_resp.text,
            )
        else:
            check("approved high-risk tool executes", False, "no approval_id to use")
            check("replayed approval denied", False, "no approval_id to use")

    if failures:
        print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1

    print("\nAll smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
