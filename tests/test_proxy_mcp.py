"""MCP proxy: interception, approvals, list filtering, audit, and end to end."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from secure_agent_gateway.hashing import sha256_hex
from secure_agent_gateway.proxy.approvals import ApprovalError, FileApprovalStore
from secure_agent_gateway.proxy.audit import JsonlAuditLog
from secure_agent_gateway.proxy.mcp import McpProxy
from secure_agent_gateway.proxy.policy import Policy

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_SERVER = Path(__file__).parent / "helpers" / "fake_mcp_server.py"

POLICY = {
    "default": "deny",
    "tools": [
        {"name": "echo", "action": "allow"},
        {"name": "read_file", "action": "allow", "deny_args": {"path": ["*.env"]}},
        {"name": "run_shell", "action": "deny"},
        {"name": "write_file", "action": "ask"},
    ],
}


class Harness:
    def __init__(self, tmp_path: Path, clock: Any = None) -> None:
        self.to_client: list[Any] = []
        self.to_upstream: list[Any] = []
        self.raw_upstream: list[bytes] = []
        self.audit_path = tmp_path / "audit.jsonl"
        kwargs = {"clock": clock} if clock else {}
        self.store = FileApprovalStore(tmp_path / "approvals", **kwargs)
        self.proxy = McpProxy(
            policy=Policy.model_validate(POLICY),
            approvals=self.store,
            audit=JsonlAuditLog(self.audit_path),
            server="fake",
            server_id="sha256:server-a",
            send_to_client=lambda b: self.to_client.append(json.loads(b)),
            send_to_upstream=self._upstream,
            log=lambda _msg: None,
        )

    def _upstream(self, data: bytes) -> None:
        self.raw_upstream.append(data)
        self.to_upstream.append(json.loads(data))

    def call(self, name: str, arguments: dict[str, Any], request_id: int = 1) -> None:
        msg = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        self.proxy.handle_client_line(json.dumps(msg).encode())

    def audit(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def _error_text(response: dict[str, Any]) -> str:
    assert response["result"]["isError"] is True
    text: str = response["result"]["content"][0]["text"]
    return text


# --- interception ------------------------------------------------------------


def test_allowed_call_is_forwarded(h: Harness) -> None:
    h.call("echo", {"text": "hi"})
    assert h.to_upstream[0]["params"] == {"name": "echo", "arguments": {"text": "hi"}}
    assert h.to_client == []


def test_denied_call_returns_is_error_and_never_reaches_upstream(h: Harness) -> None:
    h.call("run_shell", {"cmd": "cat .env"}, request_id=7)
    assert h.to_upstream == []
    assert h.to_client[0]["id"] == 7
    assert "denied" in _error_text(h.to_client[0])


def test_arg_denial_and_secret_detection_block(h: Harness) -> None:
    h.call("read_file", {"path": "/app/.env"}, request_id=1)
    h.call("echo", {"text": f"exfil {FAKE_AWS_KEY}"}, request_id=2)
    assert h.to_upstream == []
    assert "deny pattern" in _error_text(h.to_client[0])
    assert "aws_access_key_id" in _error_text(h.to_client[1])
    assert FAKE_AWS_KEY not in _error_text(h.to_client[1])


def test_unknown_tool_uses_default(h: Harness) -> None:
    h.call("drop_database", {})
    assert h.to_upstream == []


def test_forwarded_message_is_the_parsed_object_not_the_raw_bytes(h: Harness) -> None:
    # Duplicate keys: Python keeps the last value. Whatever another parser
    # would pick, upstream only ever receives the one the policy evaluated.
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"run_shell","name":"echo","arguments":{"text":"x"}}}'
    )
    h.proxy.handle_client_line(raw)
    assert h.raw_upstream[0].count(b'"name"') == 1
    assert h.to_upstream[0]["params"]["name"] == "echo"


def test_malformed_input_is_rejected(h: Harness) -> None:
    h.proxy.handle_client_line(b"{not json")
    h.proxy.handle_client_line(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":NaN}}')
    h.proxy.handle_client_line(b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":"x"}')
    h.proxy.handle_client_line(
        b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":[1]}}'
    )
    assert h.to_upstream == []
    assert [r["error"]["code"] for r in h.to_client] == [-32700, -32700, -32602, -32602]


def test_tools_call_notification_is_dropped(h: Harness) -> None:
    msg = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "echo", "arguments": {}}}
    h.proxy.handle_client_line(json.dumps(msg).encode())
    assert h.to_upstream == []
    assert h.to_client == []


def test_other_methods_pass_through(h: Harness) -> None:
    msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    h.proxy.handle_client_line(json.dumps(msg).encode())
    assert h.to_upstream == [msg]


def test_batch_forwards_allowed_and_answers_blocked(h: Harness) -> None:
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_shell"}},
    ]
    h.proxy.handle_client_line(json.dumps(batch).encode())
    assert [m["id"] for m in h.to_upstream[0]] == [1]
    assert h.to_client[0]["id"] == 2


# --- tools/list filtering ----------------------------------------------------


def _list_response(request_id: Any) -> bytes:
    tools = [{"name": n} for n in ("echo", "read_file", "run_shell", "write_file", "mystery")]
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}).encode()


def test_tools_list_hides_denied_tools(h: Harness) -> None:
    h.proxy.handle_client_line(b'{"jsonrpc":"2.0","id":"L1","method":"tools/list"}')
    h.proxy.handle_upstream_line(_list_response("L1"))
    names = [t["name"] for t in h.to_client[0]["result"]["tools"]]
    assert names == ["echo", "read_file", "write_file"]
    event = h.audit()[-1]
    assert event["event"] == "tools_list_filtered"
    assert event["hidden_tools"] == ["run_shell", "mystery"]


def test_only_tools_list_responses_are_filtered(h: Harness) -> None:
    h.proxy.handle_client_line(b'{"jsonrpc":"2.0","id":"1","method":"tools/list"}')
    # Same value, different JSON type: not the tools/list response.
    h.proxy.handle_upstream_line(_list_response(1))
    assert len(h.to_client[0]["result"]["tools"]) == 5


# --- approvals ---------------------------------------------------------------


def _approval_id(response: dict[str, Any]) -> str:
    text = _error_text(response)
    return text.split("Approval request id: ")[1].split(".")[0]


def test_ask_holds_call_until_approved_then_allows_once(h: Harness) -> None:
    args = {"path": "notes.txt", "content": "hello"}
    h.call("write_file", args, request_id=1)
    assert h.to_upstream == []
    approval_id = _approval_id(h.to_client[0])

    pending = h.store.pending()
    assert [p.approval_id for p in pending] == [approval_id]
    assert pending[0].argument_hash == sha256_hex(args)

    h.store.approve(approval_id, approved_by="tester")
    h.call("write_file", args, request_id=2)
    assert [m["id"] for m in h.to_upstream] == [2]

    # Replay: the grant was consumed, so the same call is held again.
    h.call("write_file", args, request_id=3)
    assert [m["id"] for m in h.to_upstream] == [2]
    assert _approval_id(h.to_client[-1]) != approval_id


def test_approval_for_different_arguments_does_not_apply(h: Harness) -> None:
    h.call("write_file", {"path": "notes.txt", "content": "hello"})
    h.store.approve(_approval_id(h.to_client[0]), approved_by="tester")
    h.call("write_file", {"path": "notes.txt", "content": "rm -rf /"}, request_id=2)
    assert h.to_upstream == []
    # The original grant is still there for the call it was made for.
    h.call("write_file", {"path": "notes.txt", "content": "hello"}, request_id=3)
    assert [m["id"] for m in h.to_upstream] == [3]


def test_approval_does_not_transfer_between_tools_or_servers(tmp_path: Path) -> None:
    store = FileApprovalStore(tmp_path)
    record, _ = store.request(
        server="a", server_id="sha256:a", tool_name="write_file",
        argument_hash="sha256:x", grant_ttl_seconds=60, preview={},
    )
    store.approve(record.approval_id, approved_by="t")
    assert store.try_consume(server_id="sha256:b", tool_name="write_file", argument_hash="sha256:x") is None
    assert store.try_consume(server_id="sha256:a", tool_name="edit_file", argument_hash="sha256:x") is None
    assert store.try_consume(server_id="sha256:a", tool_name="write_file", argument_hash="sha256:x")


def test_retry_before_approval_reuses_the_open_request(h: Harness) -> None:
    h.call("write_file", {"path": "a"}, request_id=1)
    h.call("write_file", {"path": "a"}, request_id=2)
    assert _approval_id(h.to_client[0]) == _approval_id(h.to_client[1])
    assert len(h.store.pending()) == 1


def test_granted_approval_expires(tmp_path: Path) -> None:
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = FileApprovalStore(tmp_path, clock=lambda: now[0])
    record, _ = store.request(
        server="a", server_id="s", tool_name="t", argument_hash="h",
        grant_ttl_seconds=60, preview={},
    )
    store.approve(record.approval_id, approved_by="t")
    now[0] += timedelta(seconds=61)
    assert store.try_consume(server_id="s", tool_name="t", argument_hash="h") is None


def test_expired_request_cannot_be_approved(tmp_path: Path) -> None:
    now = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = FileApprovalStore(tmp_path, clock=lambda: now[0])
    record, _ = store.request(
        server="a", server_id="s", tool_name="t", argument_hash="h",
        grant_ttl_seconds=60, preview={},
    )
    now[0] += timedelta(hours=2)
    assert store.pending() == []
    with pytest.raises(ApprovalError, match="expired"):
        store.approve(record.approval_id, approved_by="t")


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "ABCDEF0123", "", "0123456789a"])
def test_approve_rejects_malformed_ids(tmp_path: Path, bad_id: str) -> None:
    with pytest.raises(ApprovalError, match="malformed"):
        FileApprovalStore(tmp_path).approve(bad_id, approved_by="t")


def test_approve_twice_fails(tmp_path: Path) -> None:
    store = FileApprovalStore(tmp_path)
    record, _ = store.request(
        server="a", server_id="s", tool_name="t", argument_hash="h",
        grant_ttl_seconds=60, preview={},
    )
    store.approve(record.approval_id, approved_by="t")
    with pytest.raises(ApprovalError):
        store.approve(record.approval_id, approved_by="t")


def test_concurrent_consumers_only_one_wins(tmp_path: Path) -> None:
    # Repeated because a broken claim primitive only loses some races.
    store = FileApprovalStore(tmp_path)
    for round_number in range(25):
        argument_hash = f"sha256:{round_number}"
        record, _ = store.request(
            server="a", server_id="s", tool_name="t", argument_hash=argument_hash,
            grant_ttl_seconds=60, preview={},
        )
        store.approve(record.approval_id, approved_by="t")
        barrier = threading.Barrier(8)
        wins: list[object] = []

        def consume(
            h: str = argument_hash,
            barrier: threading.Barrier = barrier,
            wins: list[object] = wins,
        ) -> None:
            # A separate store instance per thread, as with separate processes.
            other = FileApprovalStore(tmp_path)
            barrier.wait()
            if other.try_consume(server_id="s", tool_name="t", argument_hash=h):
                wins.append(1)

        threads = [threading.Thread(target=consume) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(wins) == 1, f"round {round_number}: {len(wins)} consumers won"


def test_pending_preview_is_redacted_and_grant_drops_it(h: Harness) -> None:
    h.proxy.policy = Policy.model_validate({**POLICY, "secrets": {"action": "ask"}})
    h.call("write_file", {"path": "a", "content": f"key {FAKE_AWS_KEY}"})
    record = h.store.pending()[0]
    assert FAKE_AWS_KEY not in json.dumps(record.preview)
    h.store.approve(record.approval_id, approved_by="t")
    granted = json.loads((h.store.granted_dir / f"{record.approval_id}.json").read_text())
    assert granted["preview"] is None


# --- audit -------------------------------------------------------------------


def test_audit_records_hashes_never_raw_arguments(h: Harness) -> None:
    secret_path = "/very/private/location/.env"
    h.call("read_file", {"path": secret_path}, request_id=1)
    h.call("echo", {"text": FAKE_AWS_KEY}, request_id=2)
    h.call("echo", {"text": "visible-marker"}, request_id=3)
    h.call("write_file", {"content": "draft-marker"}, request_id=4)
    log = h.audit_path.read_text()
    for raw in (secret_path, FAKE_AWS_KEY, "visible-marker", "draft-marker"):
        assert raw not in log
    events = h.audit()
    calls = [e for e in events if e["event"] == "tool_call"]
    assert [e["decision"] for e in calls] == ["deny", "deny", "allow", "ask"]
    assert calls[2]["argument_hash"] == sha256_hex({"text": "visible-marker"})
    assert any(e["event"] == "approval_requested" for e in events)


def test_audit_records_approval_consumption(h: Harness) -> None:
    h.call("write_file", {"path": "a"})
    h.store.approve(_approval_id(h.to_client[0]), approved_by="t")
    h.call("write_file", {"path": "a"}, request_id=2)
    events = [e["event"] for e in h.audit()]
    assert events[-2:] == ["approval_consumed", "tool_call"]
    assert h.audit()[-1]["code"] == "approved"


# --- end to end --------------------------------------------------------------


def _run_session(tmp_path: Path, messages: list[dict[str, Any]]) -> tuple[list[Any], list[Any]]:
    policy = tmp_path / "policy.yaml"
    policy.write_text(json.dumps(POLICY))  # JSON is valid YAML
    call_log = tmp_path / "calls.jsonl"
    env = {**os.environ, "FAKE_MCP_CALL_LOG": str(call_log), "SAG_HOME": str(tmp_path / "state")}
    stdin = "".join(json.dumps(m) + "\n" for m in messages)
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "secure_agent_gateway.cli", "mcp", "-c", str(policy), "--",
         sys.executable, str(FAKE_SERVER)],
        input=stdin.encode(), capture_output=True, env=env, timeout=30, check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    responses = [json.loads(line) for line in proc.stdout.decode().splitlines() if line.strip()]
    calls = (
        [json.loads(line) for line in call_log.read_text().splitlines()]
        if call_log.exists() else []
    )
    return responses, calls


def _rpc(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}


def test_end_to_end_against_a_real_subprocess(tmp_path: Path) -> None:
    responses, calls = _run_session(
        tmp_path,
        [
            _rpc(1, "initialize", {"protocolVersion": "2025-06-18"}),
            _rpc(2, "tools/list"),
            _rpc(3, "tools/call", {"name": "echo", "arguments": {"text": "hi"}}),
            _rpc(4, "tools/call", {"name": "read_file", "arguments": {"path": ".env"}}),
            _rpc(5, "tools/call", {"name": "run_shell", "arguments": {"cmd": "id"}}),
            _rpc(6, "tools/call", {"name": "echo", "arguments": {"text": FAKE_AWS_KEY}}),
            _rpc(7, "tools/call", {"name": "write_file", "arguments": {"path": "x"}}),
        ],
    )
    by_id = {r["id"]: r for r in responses}
    assert set(by_id) == {1, 2, 3, 4, 5, 6, 7}
    assert by_id[1]["result"]["serverInfo"]["name"] == "fake"
    assert [t["name"] for t in by_id[2]["result"]["tools"]] == ["echo", "read_file", "write_file"]
    assert by_id[3]["result"]["isError"] is False
    for blocked in (4, 5, 6, 7):
        assert by_id[blocked]["result"]["isError"] is True
    # Only the allowed call ever reached the server.
    assert calls == [{"name": "echo", "arguments": {"text": "hi"}}]

    audit = (tmp_path / "state" / "audit.jsonl").read_text()
    assert FAKE_AWS_KEY not in audit
    assert '"approval_requested"' in audit


def test_end_to_end_approval_via_cli(tmp_path: Path) -> None:
    write = _rpc(1, "tools/call", {"name": "write_file", "arguments": {"path": "x"}})
    responses, calls = _run_session(tmp_path, [write])
    assert calls == []
    approval_id = _approval_id(responses[0])

    env = {**os.environ, "SAG_HOME": str(tmp_path / "state")}
    approve = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "secure_agent_gateway.cli", "approve", approval_id],
        capture_output=True, env=env, timeout=30, check=False,
    )
    assert approve.returncode == 0, approve.stderr.decode()

    responses, calls = _run_session(tmp_path, [write, {**write, "id": 2}])
    assert calls == [{"name": "write_file", "arguments": {"path": "x"}}]
    by_id = {r["id"]: r for r in responses}
    assert by_id[1]["result"]["isError"] is False
    assert by_id[2]["result"]["isError"] is True  # single use
