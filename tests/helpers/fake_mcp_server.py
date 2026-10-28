"""Minimal stdio MCP server for proxy end-to-end tests.

Every tools/call is recorded (one JSON line per call) in the file named by
FAKE_MCP_CALL_LOG, so tests can assert what actually reached the server.
"""

from __future__ import annotations

import json
import os
import sys

TOOLS = [
    {"name": "echo", "description": "Echo text", "inputSchema": {"type": "object"}},
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
    {"name": "run_shell", "description": "Run a command", "inputSchema": {"type": "object"}},
    {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
]


def main() -> None:
    log_path = os.environ.get("FAKE_MCP_CALL_LOG")
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        if "id" not in msg:
            continue
        method = msg.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            if log_path:
                with open(log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(msg["params"]) + "\n")
            text = json.dumps(msg["params"].get("arguments", {}))
            result = {"content": [{"type": "text", "text": f"ok {text}"}], "isError": False}
        else:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "?"}}
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
