"""The `sag` command line: init, check, pending, approve."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_agent_gateway.cli import main
from secure_agent_gateway.proxy.approvals import FileApprovalStore


def test_init_writes_starter_policy_and_refuses_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "sag-policy.yaml"
    assert main(["init", str(target)]) == 0
    assert "default: ask" in target.read_text()
    assert main(["init", str(target)]) == 1
    assert main(["init", str(target), "--force"]) == 0


@pytest.mark.parametrize(
    ("tool", "args", "code"),
    [
        ("read_file", '{"path": "README.md"}', 0),
        ("read_file", '{"path": ".env"}', 1),
        ("run_shell", '{"command": "ls"}', 1),
        ("write_file", '{"path": "a"}', 3),
    ],
)
def test_check_exit_codes(tmp_path: Path, tool: str, args: str, code: int) -> None:
    policy = tmp_path / "p.yaml"
    main(["init", str(policy)])
    assert main(["check", "-c", str(policy), tool, "--args", args]) == code


def test_check_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "p.yaml"
    main(["init", str(policy)])
    capsys.readouterr()
    main(["check", "-c", str(policy), "read_file", "--args", '{"path": ".env"}', "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "deny"
    assert out["code"] == "arg_denied"
    assert out["argument_hash"].startswith("sha256:")


def test_check_rejects_bad_input(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    main(["init", str(policy)])
    assert main(["check", "-c", str(policy), "x", "--args", "not json"]) == 2
    assert main(["check", "-c", str(policy), "x", "--args", "[1]"]) == 2
    bad = tmp_path / "bad.yaml"
    bad.write_text("default: sometimes\n")
    assert main(["check", "-c", str(bad), "x"]) == 2


def test_pending_and_approve(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = FileApprovalStore(tmp_path / "approvals")
    record, _ = store.request(
        server="fs", server_id="s", tool_name="write_file", argument_hash="sha256:h",
        grant_ttl_seconds=60, preview={"path": "a"},
    )
    assert main(["pending", "--state-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert record.approval_id in out
    assert '"path": "a"' in out

    assert main(["approve", record.approval_id, "--state-dir", str(tmp_path)]) == 0
    assert main(["approve", record.approval_id, "--state-dir", str(tmp_path)]) == 1
    assert main(["pending", "--state-dir", str(tmp_path)]) == 0
    assert "No calls waiting" in capsys.readouterr().out

    audit = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert audit[-1]["event"] == "approval_granted"


def test_mcp_requires_upstream_command(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    main(["init", str(policy)])
    assert main(["mcp", "-c", str(policy)]) == 2
    assert main(["mcp", "-c", str(policy), "--"]) == 2
