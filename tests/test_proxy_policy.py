"""Policy matching, argument rules, and secret detection for the MCP proxy."""

from __future__ import annotations

from pathlib import Path

import pytest

from gateway.proxy.policy import Policy, PolicyError, evaluate, is_listed, load_policy
from gateway.proxy.secret_scan import find_secrets, redact

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key


def make_policy(**overrides: object) -> Policy:
    data: dict[str, object] = {
        "default": "ask",
        "tools": [
            {"name": "run_shell", "action": "deny"},
            {
                "name": "read_*",
                "action": "allow",
                "deny_args": {"*path*": ["*.env", "*/.ssh/*"]},
            },
            {
                "name": "http_post",
                "action": "allow",
                "allow_args": {"url": ["https://api.example.com/*"]},
            },
            {"name": "write_*", "action": "ask"},
            {"name": "*", "action": "allow", "scan_secrets": False},
        ],
    }
    data.update(overrides)
    return Policy.model_validate(data)


# --- tool matching -----------------------------------------------------------


def test_first_matching_rule_wins() -> None:
    policy = make_policy()
    assert evaluate(policy, "read_file", {"path": "README.md"}).action == "allow"
    assert evaluate(policy, "run_shell", {"cmd": "ls"}).action == "deny"
    assert evaluate(policy, "write_file", {"path": "x"}).action == "ask"


def test_tool_glob_is_case_sensitive() -> None:
    policy = make_policy()
    decision = evaluate(policy, "READ_FILE", {"path": ".env"})
    # No `read_*` match, so the catch-all rule applies, not the read rule.
    assert decision.rule == "tools[4] (*)"


@pytest.mark.parametrize("default", ["allow", "deny", "ask"])
def test_default_applies_when_no_rule_matches(default: str) -> None:
    policy = Policy.model_validate({"default": default, "tools": []})
    decision = evaluate(policy, "anything", {})
    assert decision.action == default
    assert decision.rule == "default"


def test_denied_tool_reason_names_the_rule() -> None:
    decision = evaluate(make_policy(), "run_shell", {"cmd": "cat .env"})
    assert decision.code == "tool_denied"
    assert "tools[0] (run_shell)" in decision.reason


# --- deny_args ---------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "/home/me/project/.env",
        "C:\\Users\\me\\project\\.ENV",
        "docs/../.env",
        ".env.",
        ".env ",
        ".env::$DATA",
        "/home/me/.ssh/id_rsa",
    ],
)
def test_deny_args_catches_path_variants(path: str) -> None:
    decision = evaluate(make_policy(), "read_file", {"path": path})
    assert decision.action == "deny", path
    assert decision.code == "arg_denied"


def test_deny_args_argument_name_glob_and_list_values() -> None:
    decision = evaluate(make_policy(), "read_multiple_files", {"paths": ["a.txt", "b/.env"]})
    assert decision.action == "deny"
    assert "'paths'" in decision.reason


def test_deny_args_does_not_overmatch() -> None:
    policy = make_policy()
    assert evaluate(policy, "read_file", {"path": "src/environment.py"}).action == "allow"
    assert evaluate(policy, "read_file", {"path": "README.md"}).action == "allow"


def test_deny_args_reason_never_contains_the_value() -> None:
    decision = evaluate(make_policy(), "read_file", {"path": "/secret/location/.env"})
    assert "/secret/location" not in decision.reason


# --- allow_args --------------------------------------------------------------


def test_allow_args_permits_listed_values() -> None:
    decision = evaluate(make_policy(), "http_post", {"url": "https://api.example.com/v1/x"})
    assert decision.action == "allow"


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/collect",
        "https://api.example.com.attacker.example/x",
        "HTTPS://API.EXAMPLE.COM/x",
    ],
)
def test_allow_args_rejects_everything_else(url: str) -> None:
    decision = evaluate(make_policy(), "http_post", {"url": url})
    assert decision.action == "deny"
    assert decision.code == "arg_not_allowed"


def test_allow_args_rejects_dotdot_escape_from_allowed_directory() -> None:
    policy = Policy.model_validate(
        {
            "tools": [
                {
                    "name": "read_file",
                    "action": "allow",
                    "allow_args": {"path": ["/home/me/project/*"]},
                }
            ]
        }
    )
    assert evaluate(policy, "read_file", {"path": "/home/me/project/a.txt"}).action == "allow"
    escaped = evaluate(policy, "read_file", {"path": "/home/me/project/../../etc/passwd"})
    assert escaped.action == "deny"


def test_allow_args_constrains_nested_values() -> None:
    decision = evaluate(make_policy(), "http_post", {"url": ["https://api.example.com/a", "x"]})
    assert decision.action == "deny"


def test_allow_args_ignores_absent_argument() -> None:
    assert evaluate(make_policy(), "http_post", {"body": "hi"}).action == "allow"


# --- secret detection --------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "detector"),
    [
        (f"key={FAKE_AWS_KEY}", "aws_access_key_id"),
        ("aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_access_key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "private_key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
        ("ghp_" + "a" * 36, "github_token"),
        ("github_pat_" + "A1" * 15, "github_token"),
        ("xoxb-1234567890-abcdef", "slack_token"),
        ("sk-ant-api03-" + "x" * 40, "anthropic_api_key"),
        ("AIza" + "0" * 35, "google_api_key"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk", "jwt"),
    ],
)
def test_secret_detectors(text: str, detector: str) -> None:
    assert detector in find_secrets({"body": text})


def test_secret_detection_scans_nested_values_and_keys() -> None:
    assert find_secrets({"a": [{"b": f"x {FAKE_AWS_KEY} y"}]}) == ["aws_access_key_id"]
    assert find_secrets({FAKE_AWS_KEY: 1}) == ["aws_access_key_id"]


def test_no_false_positive_on_plain_text() -> None:
    assert find_secrets({"body": "The quarterly report is attached. Ticket ABC-123."}) == []


def test_secret_in_allowed_tool_is_denied_without_echoing_it() -> None:
    policy = make_policy()
    decision = evaluate(policy, "http_post", {"url": "https://api.example.com/x", "body": FAKE_AWS_KEY})
    assert decision.action == "deny"
    assert decision.code == "secret_detected"
    assert FAKE_AWS_KEY not in decision.reason
    assert "aws_access_key_id" in decision.reason


def test_secret_action_ask_routes_to_approval() -> None:
    policy = make_policy(secrets={"scan": True, "action": "ask"})
    decision = evaluate(policy, "read_file", {"path": FAKE_AWS_KEY})
    assert decision.action == "ask"
    assert decision.code == "secret_detected"


def test_arg_denial_beats_secret_ask() -> None:
    policy = make_policy(secrets={"scan": True, "action": "ask"})
    assert evaluate(policy, "read_file", {"path": f"{FAKE_AWS_KEY}/.env"}).action == "deny"


def test_secret_scan_can_be_disabled_per_rule_and_globally() -> None:
    assert evaluate(make_policy(), "other_tool", {"x": FAKE_AWS_KEY}).action == "allow"
    off = make_policy(secrets={"scan": False})
    assert evaluate(off, "read_file", {"path": FAKE_AWS_KEY}).action == "allow"


def test_redact_masks_secrets_and_truncates() -> None:
    preview = redact({"body": f"k={FAKE_AWS_KEY}", "long": "x" * 500})
    assert FAKE_AWS_KEY not in str(preview)
    assert "[REDACTED:aws_access_key_id]" in preview["body"]
    assert len(preview["long"]) < 300


# --- tools/list visibility ---------------------------------------------------


def test_is_listed_hides_only_denied_tools() -> None:
    policy = make_policy()
    assert not is_listed(policy, "run_shell")
    assert is_listed(policy, "read_file")
    assert is_listed(policy, "write_file")  # ask stays visible
    assert not is_listed(Policy.model_validate({"default": "deny"}), "anything")


# --- loading -----------------------------------------------------------------


def test_load_policy_rejects_unknown_keys(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text("tools:\n  - name: x\n    action: allow\n    deny_arg: {}\n")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_rejects_unknown_action(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text("default: maybe\n")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_rejects_non_mapping_and_missing(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text("- a\n- b\n")
    with pytest.raises(PolicyError):
        load_policy(path)
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.yaml")


def test_empty_policy_file_defaults_to_ask(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text("")
    assert evaluate(load_policy(path), "anything", {}).action == "ask"


def test_starter_policy_loads_and_blocks_the_obvious(tmp_path: Path) -> None:
    from importlib.resources import files

    path = tmp_path / "p.yaml"
    path.write_text(files("gateway.proxy").joinpath("starter_policy.yaml").read_text())
    policy = load_policy(path)
    assert evaluate(policy, "read_text_file", {"path": "/proj/src/app.py"}).action == "allow"
    assert evaluate(policy, "read_text_file", {"path": "/proj/.env"}).action == "deny"
    assert evaluate(policy, "run_shell", {"command": "ls"}).action == "deny"
    assert evaluate(policy, "write_file", {"path": "/proj/a", "content": "x"}).action == "ask"
    assert evaluate(policy, "write_file", {"path": "/proj/a", "content": FAKE_AWS_KEY}).action == "deny"
