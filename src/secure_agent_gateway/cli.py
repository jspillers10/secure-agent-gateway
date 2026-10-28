"""`sag`: the Secure Agent Gateway command line.

    sag init [PATH]                          write a starter policy
    sag mcp -c POLICY -- CMD [ARGS...]       proxy a stdio MCP server
    sag check -c POLICY TOOL [--args JSON]   dry-run one call against a policy
    sag pending                              list calls waiting for approval
    sag approve ID                           approve one held call, once

State (approvals and the audit log) lives in --state-dir, else $SAG_HOME,
else ~/.sag.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from importlib.resources import files
from pathlib import Path

from secure_agent_gateway.hashing import sha256_hex
from secure_agent_gateway.proxy.approvals import ApprovalError, FileApprovalStore
from secure_agent_gateway.proxy.audit import JsonlAuditLog, ProxyAuditEvent
from secure_agent_gateway.proxy.policy import PolicyError, evaluate, load_policy

EXIT_CODES = {"allow": 0, "deny": 1, "ask": 3}


def _state_dir(arg: str | None) -> Path:
    if arg:
        return Path(arg).expanduser()
    if os.environ.get("SAG_HOME"):
        return Path(os.environ["SAG_HOME"]).expanduser()
    return Path.home() / ".sag"


def _cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    starter = files("secure_agent_gateway.proxy").joinpath("starter_policy.yaml")
    template = starter.read_text(encoding="utf-8")
    target.write_text(template, encoding="utf-8")
    print(f"Wrote {target}. Next:")
    print(f"  sag check -c {target} read_file --args '{{\"path\": \".env\"}}'")
    print(f"  sag mcp -c {target} -- <your MCP server command>")
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    from secure_agent_gateway.proxy.mcp import run_proxy

    upstream = list(args.upstream)
    if upstream and upstream[0] == "--":
        upstream = upstream[1:]
    if not upstream:
        print("usage: sag mcp -c POLICY -- <upstream command> [args...]", file=sys.stderr)
        return 2
    try:
        policy = load_policy(args.config)
    except PolicyError as exc:
        print(f"[sag] {exc}", file=sys.stderr)
        return 2
    state = _state_dir(args.state_dir)
    audit_path = Path(args.audit_log).expanduser() if args.audit_log else state / "audit.jsonl"
    # Display name only: "npx @modelcontextprotocol/server-filesystem".
    first_arg = next((a for a in upstream[1:] if not a.startswith("-")), "")
    name = args.name or f"{Path(upstream[0]).name} {first_arg}".strip()
    print(f"[sag] proxying {' '.join(upstream)} (policy {args.config})", file=sys.stderr)
    return run_proxy(
        policy=policy,
        approvals=FileApprovalStore(state / "approvals"),
        audit=JsonlAuditLog(audit_path),
        server=name,
        upstream=upstream,
        client_in=sys.stdin.buffer,
        client_out=sys.stdout.buffer,
    )


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.config)
    except PolicyError as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        arguments = json.loads(args.args)
    except ValueError as exc:
        print(f"--args is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(arguments, dict):
        print("--args must be a JSON object", file=sys.stderr)
        return 2
    decision = evaluate(policy, args.tool, arguments)
    if args.json:
        print(
            json.dumps(
                {
                    "tool": args.tool,
                    "decision": decision.action,
                    "code": decision.code,
                    "rule": decision.rule,
                    "reason": decision.reason,
                    "argument_hash": sha256_hex(arguments),
                }
            )
        )
    else:
        print(f"{decision.action.upper()}  {args.tool}")
        print(f"  rule:   {decision.rule}")
        print(f"  reason: {decision.reason}")
    return EXIT_CODES[decision.action]


def _cmd_pending(args: argparse.Namespace) -> int:
    store = FileApprovalStore(_state_dir(args.state_dir) / "approvals")
    records = store.pending()
    if not records:
        print("No calls waiting for approval.")
        return 0
    for record in records:
        print(f"{record.approval_id}  {record.tool_name}  (server: {record.server})")
        print(f"  requested: {record.created_at}   expires: {record.expires_at}")
        print(f"  arguments: {json.dumps(record.preview, ensure_ascii=False)}")
        print(f"  approve:   sag approve {record.approval_id}")
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    state = _state_dir(args.state_dir)
    store = FileApprovalStore(state / "approvals")
    try:
        approver = getpass.getuser()
    except (KeyError, OSError):
        approver = "unknown"
    try:
        record = store.approve(args.approval_id, approved_by=approver)
    except ApprovalError as exc:
        print(exc, file=sys.stderr)
        return 1
    JsonlAuditLog(state / "audit.jsonl").write(
        ProxyAuditEvent(
            event="approval_granted",
            server=record.server,
            server_id=record.server_id,
            tool_name=record.tool_name,
            argument_hash=record.argument_hash,
            approval_id=record.approval_id,
            approved_by=approver,
        )
    )
    print(
        f"Approved {record.approval_id}: one call to {record.tool_name} with the exact "
        f"same arguments, until {record.expires_at}. Ask the agent to retry."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sag", description="Secure Agent Gateway: policy enforcement for MCP tool calls."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write a starter policy")
    p_init.add_argument("path", nargs="?", default="sag-policy.yaml")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing file")
    p_init.set_defaults(func=_cmd_init)

    p_mcp = sub.add_parser("mcp", help="proxy a stdio MCP server through a policy")
    p_mcp.add_argument("-c", "--config", required=True, help="policy YAML")
    p_mcp.add_argument("--name", help="server name shown in approvals and audit")
    p_mcp.add_argument("--state-dir", help="approvals + audit directory (default ~/.sag)")
    p_mcp.add_argument("--audit-log", help="audit JSONL path (default <state-dir>/audit.jsonl)")
    p_mcp.add_argument("upstream", nargs=argparse.REMAINDER, help="-- <command> [args...]")
    p_mcp.set_defaults(func=_cmd_mcp)

    p_check = sub.add_parser("check", help="dry-run one tool call against a policy")
    p_check.add_argument("-c", "--config", required=True, help="policy YAML")
    p_check.add_argument("tool", help="MCP tool name")
    p_check.add_argument("--args", default="{}", help="arguments as a JSON object")
    p_check.add_argument("--json", action="store_true", help="machine-readable output")
    p_check.set_defaults(func=_cmd_check)

    p_pending = sub.add_parser("pending", help="list calls waiting for approval")
    p_pending.add_argument("--state-dir")
    p_pending.set_defaults(func=_cmd_pending)

    p_approve = sub.add_parser("approve", help="approve one held call")
    p_approve.add_argument("approval_id")
    p_approve.add_argument("--state-dir")
    p_approve.set_defaults(func=_cmd_approve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code: int = args.func(args)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
