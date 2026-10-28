"""The stdio MCP proxy.

    MCP client  <-- stdio -->  sag mcp  <-- stdio -->  upstream MCP server

MCP's stdio transport is newline-delimited JSON-RPC 2.0. Two threads pump
messages (threads, not asyncio subprocess pipes, so this runs unchanged on
Windows):

- client -> upstream: every `tools/call` is evaluated against the policy.
  Allowed calls are forwarded; denied calls and calls waiting for approval
  are answered by the proxy itself with a tool result carrying
  `isError: true` and the reason, so the model sees why and the upstream
  server never sees the call.
- upstream -> client: `tools/list` responses are filtered so statically
  denied tools are never advertised.

Every client message is forwarded as the proxy's own re-serialization of
what it parsed, never as the original bytes. That closes parser-
differential tricks (duplicate keys, odd whitespace, non-standard
constants): the upstream server executes exactly the object the policy
evaluated. Unparseable client input is answered with a JSON-RPC parse
error and dropped.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess  # nosec B404 (launching the upstream server is the job)
import sys
import threading
from collections.abc import Callable
from typing import IO, Any

from gateway.hashing import sha256_hex
from gateway.proxy.approvals import FileApprovalStore
from gateway.proxy.audit import JsonlAuditLog, ProxyAuditEvent
from gateway.proxy.policy import Decision, Policy, evaluate, is_listed
from gateway.proxy.secret_scan import redact

JsonObj = dict[str, Any]


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON constant {name}")


def parse_message(line: bytes) -> Any:
    return json.loads(line.decode("utf-8"), parse_constant=_reject_constant)


def encode_message(message: Any) -> bytes:
    return (
        json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


def _id_key(request_id: Any) -> str:
    # 1 and "1" are different JSON-RPC ids.
    return json.dumps(request_id, sort_keys=True)


def _tool_error(request_id: Any, text: str) -> JsonObj:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


def _rpc_error(request_id: Any, code: int, message: str) -> JsonObj:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class McpProxy:
    def __init__(
        self,
        *,
        policy: Policy,
        approvals: FileApprovalStore,
        audit: JsonlAuditLog,
        server: str,
        server_id: str,
        send_to_client: Callable[[bytes], None],
        send_to_upstream: Callable[[bytes], None],
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.policy = policy
        self.approvals = approvals
        self.audit = audit
        self.server = server
        self.server_id = server_id
        self._send_client = send_to_client
        self._send_upstream = send_to_upstream
        self._log = log or (lambda msg: print(f"[sag] {msg}", file=sys.stderr, flush=True))
        self._list_ids: set[str] = set()
        self._list_lock = threading.Lock()

    # client -> upstream

    def handle_client_line(self, line: bytes) -> None:
        if not line.strip():
            return
        try:
            message = parse_message(line)
        except ValueError:
            self._send_client(encode_message(_rpc_error(None, -32700, "Parse error")))
            return
        if isinstance(message, list):
            forwarded = [m for m in (self._guarded_filter(m) for m in message) if m is not None]
            if forwarded:
                self._send_upstream(encode_message(forwarded))
            return
        filtered = self._guarded_filter(message)
        if filtered is not None:
            self._send_upstream(encode_message(filtered))

    def _guarded_filter(self, message: Any) -> Any:
        # Any failure while deciding (an unwritable audit log, a corrupt
        # approval store) means the message is not forwarded.
        try:
            return self._filter_client(message)
        except Exception as exc:
            self._log(f"internal error, message not forwarded: {type(exc).__name__}: {exc}")
            if isinstance(message, dict) and "id" in message:
                self._send_client(
                    encode_message(_rpc_error(message["id"], -32603, "Internal proxy error"))
                )
            return None

    def _filter_client(self, message: Any) -> Any:
        """Return the message to forward upstream, or None if the proxy
        answered (or dropped) it itself."""
        if not isinstance(message, dict):
            return message
        method = message.get("method")
        if method == "tools/list" and "id" in message:
            with self._list_lock:
                self._list_ids.add(_id_key(message["id"]))
        if method == "tools/call":
            return self._handle_call(message)
        return message

    def _handle_call(self, message: JsonObj) -> JsonObj | None:
        if "id" not in message:
            # A tools/call notification is invalid and can never be
            # answered; drop it rather than let it execute unobserved.
            self._log("dropped tools/call sent without an id")
            return None
        request_id = message["id"]
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments", {}) if isinstance(params, dict) else None
        if arguments is None:
            arguments = {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            malformed = Decision("deny", "malformed", "malformed tools/call params", "-")
            self._audit_call(request_id, None, None, malformed)
            self._send_client(
                encode_message(_rpc_error(request_id, -32602, "Invalid tools/call params"))
            )
            return None

        argument_hash = sha256_hex(arguments)
        decision = evaluate(self.policy, name, arguments)

        if decision.action == "ask":
            consumed = self.approvals.try_consume(
                server_id=self.server_id, tool_name=name, argument_hash=argument_hash
            )
            if consumed is not None:
                self.audit.write(
                    ProxyAuditEvent(
                        event="approval_consumed",
                        server=self.server,
                        server_id=self.server_id,
                        request_id=_id_key(request_id)[:128],
                        tool_name=name,
                        argument_hash=argument_hash,
                        approval_id=consumed.approval_id,
                    )
                )
                decision = Decision("allow", "approved", "approved by a human", decision.rule)

        self._audit_call(request_id, name, argument_hash, decision)

        if decision.action == "allow":
            return message

        if decision.action == "deny":
            self._log(f"DENY {name}: {decision.reason}")
            text = (
                f"Blocked by Secure Agent Gateway policy: {decision.reason}. "
                "The call was not sent to the server."
            )
            self._send_client(encode_message(_tool_error(request_id, text)))
            return None

        record, created = self.approvals.request(
            server=self.server,
            server_id=self.server_id,
            tool_name=name,
            argument_hash=argument_hash,
            grant_ttl_seconds=self.policy.approval_ttl_seconds,
            preview=redact(arguments),
        )
        if created:
            self.audit.write(
                ProxyAuditEvent(
                    event="approval_requested",
                    server=self.server,
                    server_id=self.server_id,
                    tool_name=name,
                    argument_hash=argument_hash,
                    approval_id=record.approval_id,
                    code=decision.code,
                    reason=decision.reason,
                )
            )
        self._log(
            f"APPROVAL NEEDED {name} ({decision.reason}). "
            f"Review with `sag pending`, then `sag approve {record.approval_id}`."
        )
        text = (
            f"Held for human approval by Secure Agent Gateway policy: {decision.reason}. "
            f"Approval request id: {record.approval_id}. The call was not sent to the "
            "server. Ask the user to review and approve it, then retry this exact call "
            "once. Changing the arguments requires a new approval."
        )
        self._send_client(encode_message(_tool_error(request_id, text)))
        return None

    def _audit_call(
        self, request_id: Any, name: str | None, argument_hash: str | None, decision: Decision
    ) -> None:
        self.audit.write(
            ProxyAuditEvent(
                event="tool_call",
                server=self.server,
                server_id=self.server_id,
                request_id=_id_key(request_id)[:128],
                tool_name=name,
                decision=decision.action,
                code=decision.code,
                rule=decision.rule,
                reason=decision.reason,
                argument_hash=argument_hash,
            )
        )

    # upstream -> client

    def handle_upstream_line(self, line: bytes) -> None:
        if not line.strip():
            return
        try:
            message = parse_message(line)
        except ValueError:
            # Not ours to judge; enforcement happens on tools/call, not here.
            self._send_client(line if line.endswith(b"\n") else line + b"\n")
            return
        if isinstance(message, list):
            message = [self._filter_upstream(m) for m in message]
        else:
            message = self._filter_upstream(message)
        self._send_client(encode_message(message))

    def _filter_upstream(self, message: Any) -> Any:
        if not isinstance(message, dict) or "id" not in message or "method" in message:
            return message
        key = _id_key(message["id"])
        with self._list_lock:
            if key not in self._list_ids:
                return message
            self._list_ids.discard(key)
        result = message.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return message
        kept, hidden = [], []
        for tool in result["tools"]:
            name = tool.get("name") if isinstance(tool, dict) else None
            if isinstance(name, str) and is_listed(self.policy, name):
                kept.append(tool)
            else:
                hidden.append(str(name)[:128])
        if hidden:
            self.audit.write(
                ProxyAuditEvent(
                    event="tools_list_filtered", server=self.server, hidden_tools=hidden
                )
            )
        return {**message, "result": {**result, "tools": kept}}


def resolve_command(argv: list[str]) -> list[str]:
    """Resolve the upstream executable via PATH (and PATHEXT on Windows,
    so `npx` finds `npx.cmd`)."""
    found = shutil.which(argv[0])
    return [found, *argv[1:]] if found else list(argv)


def _locked_writer(stream: IO[bytes]) -> Callable[[bytes], None]:
    lock = threading.Lock()

    def write(data: bytes) -> None:
        with lock:
            stream.write(data)
            stream.flush()

    return write


def run_proxy(
    *,
    policy: Policy,
    approvals: FileApprovalStore,
    audit: JsonlAuditLog,
    server: str,
    upstream: list[str],
    client_in: IO[bytes],
    client_out: IO[bytes],
) -> int:
    # argv list with no shell; the operator chose this command on their own CLI.
    proc = subprocess.Popen(  # noqa: S603  # nosec B603
        resolve_command(upstream),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=0,
    )
    if proc.stdin is None or proc.stdout is None:  # pragma: no cover - PIPE always set
        raise RuntimeError("upstream pipes were not created")
    upstream_in, upstream_out = proc.stdin, proc.stdout
    send_upstream = _locked_writer(upstream_in)
    proxy = McpProxy(
        policy=policy,
        approvals=approvals,
        audit=audit,
        server=server,
        server_id=sha256_hex(upstream),
        send_to_client=_locked_writer(client_out),
        send_to_upstream=send_upstream,
    )
    client_closed = threading.Event()

    def pump_client() -> None:
        try:
            for line in iter(client_in.readline, b""):
                proxy.handle_client_line(line)
        except OSError:
            pass  # upstream went away; the main loop sees it exit
        finally:
            client_closed.set()
            with contextlib.suppress(OSError):
                upstream_in.close()

    def pump_upstream() -> None:
        try:
            for line in iter(upstream_out.readline, b""):
                proxy.handle_upstream_line(line)
        except OSError:
            pass

    client_thread = threading.Thread(target=pump_client, name="sag-client", daemon=True)
    upstream_thread = threading.Thread(target=pump_upstream, name="sag-upstream", daemon=True)
    client_thread.start()
    upstream_thread.start()

    while proc.poll() is None:
        if client_closed.wait(0.2):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    upstream_thread.join(timeout=2)
    return proc.returncode
