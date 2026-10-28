"""YAML tool-call policy for the MCP proxy.

A policy is an ordered list of tool rules plus a default action:

    version: 1
    default: ask                  # allow | deny | ask, for unmatched tools
    secrets: {scan: true, action: deny}
    tools:
      - name: "read_*"            # glob over the MCP tool name
        action: allow
        deny_args:                # glob over argument name -> value globs
          "*path*": ["*.env", "*/.ssh/*"]
      - name: run_shell
        action: deny

Evaluation, failing closed at every step:

1. The first rule whose `name` glob matches the tool wins. No match means
   `default`.
2. A `deny` rule denies outright.
3. `deny_args`: any string leaf of a matching argument that matches any
   value glob denies. Matching is case-insensitive and also tries
   slash-normalized, `..`-collapsed, and Windows-trimmed forms of the
   value, so `.ENV`, `a\\..\\.env`, and `.env.` are all caught.
4. `allow_args`: every string leaf of a matching argument (when present)
   must match at least one value glob, in both its raw and `..`-collapsed
   form, case-sensitively. Anything else denies. Prefer allow-lists:
   deny-lists are best-effort against an adversary who can choose
   arbitrary encodings.
5. Secret scan: if any argument contains a credential pattern, apply
   `secrets.action`.
6. Otherwise apply the rule's action (`allow` or `ask`).

Decision reasons are built only from policy text and argument *names*,
never from argument values, so they are safe to return to the model and
to write to the audit log.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from gateway.proxy.secret_scan import find_secrets

Action = Literal["allow", "deny", "ask"]


class SecretsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan: bool = True
    action: Literal["deny", "ask"] = "deny"


class ToolRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    action: Action
    deny_args: dict[str, list[str]] = Field(default_factory=dict)
    allow_args: dict[str, list[str]] = Field(default_factory=dict)
    scan_secrets: bool = True


class Policy(BaseModel):
    """Closed schema: a typo such as `deny_arg:` is a load error, never a
    silently ignored rule."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    default: Action = "ask"
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    approval_ttl_seconds: int = Field(default=600, gt=0, le=86_400)
    tools: list[ToolRule] = Field(default_factory=list)


class PolicyError(ValueError):
    pass


def load_policy(path: str | Path) -> Policy:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"policy {path} must be a YAML mapping")
    try:
        return Policy.model_validate(raw)
    except ValueError as exc:
        raise PolicyError(f"invalid policy {path}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class Decision:
    action: Action
    code: str
    reason: str
    rule: str


def _rule_label(index: int, rule: ToolRule) -> str:
    return f"tools[{index}] ({rule.name})"


def match_rule(policy: Policy, tool_name: str) -> tuple[int, ToolRule] | None:
    for index, rule in enumerate(policy.tools):
        if fnmatch.fnmatchcase(tool_name, rule.name):
            return index, rule
    return None


def is_listed(policy: Policy, tool_name: str) -> bool:
    """Whether a tool should appear in `tools/list`. Only statically denied
    tools are hidden; `ask` tools stay visible so the model can request
    them and a human can approve."""
    matched = match_rule(policy, tool_name)
    action = matched[1].action if matched else policy.default
    return action != "deny"


def _leaves(value: Any) -> Iterator[str]:
    """Scalar leaves of an argument value, stringified canonically."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from _leaves(item)
    else:
        yield json.dumps(value)


def _collapse(text: str) -> str | None:
    # Collapse `..` segments for path-like values only; normalizing a URL
    # would turn `https://` into `https:/` and break legitimate allow globs.
    if "://" in text:
        return None
    return posixpath.normpath(text)


_WINDOWS_STREAM = re.compile(r"::\$data$")


def _deny_candidates(text: str) -> set[str]:
    lowered = text.lower()
    slashed = lowered.replace("\\", "/")
    out = {lowered, slashed}
    collapsed = _collapse(slashed)
    if collapsed is not None:
        out.add(collapsed)
    # Win32 path normalization strips trailing dots/spaces and NTFS
    # default-stream suffixes, so `.env.` and `.env::$DATA` open `.env`.
    for candidate in list(out):
        trimmed = _WINDOWS_STREAM.sub("", candidate).rstrip(". ")
        if trimmed:
            out.add(trimmed)
    return out


def _allow_candidates(text: str) -> set[str]:
    out = {text}
    collapsed = _collapse(text.replace("\\", "/"))
    if collapsed is not None and collapsed != text.replace("\\", "/"):
        out.add(collapsed)
    return out


def _matching_args(arguments: dict[str, Any], key_glob: str) -> Iterator[tuple[str, Any]]:
    # Argument names match case-insensitively: a broader match only ever
    # constrains more arguments.
    for name, value in arguments.items():
        if fnmatch.fnmatch(name.lower(), key_glob.lower()):
            yield name, value


def _safe_name(name: str) -> str:
    return repr(name[:64])


def _check_args(rule: ToolRule, arguments: dict[str, Any], label: str) -> Decision | None:
    for key_glob, patterns in rule.deny_args.items():
        for name, value in _matching_args(arguments, key_glob):
            for leaf in _leaves(value):
                candidates = _deny_candidates(leaf)
                for pattern in patterns:
                    p = pattern.lower()
                    if any(fnmatch.fnmatchcase(c, p) for c in candidates):
                        return Decision(
                            "deny",
                            "arg_denied",
                            f"argument {_safe_name(name)} matches deny pattern {pattern!r}",
                            label,
                        )
    for key_glob, patterns in rule.allow_args.items():
        for name, value in _matching_args(arguments, key_glob):
            for leaf in _leaves(value):
                candidates = _allow_candidates(leaf)
                if not any(
                    all(fnmatch.fnmatchcase(c, pattern) for c in candidates)
                    for pattern in patterns
                ):
                    return Decision(
                        "deny",
                        "arg_not_allowed",
                        f"argument {_safe_name(name)} is outside the allowed values "
                        f"{patterns!r}",
                        label,
                    )
    return None


def evaluate(policy: Policy, tool_name: str, arguments: dict[str, Any]) -> Decision:
    matched = match_rule(policy, tool_name)
    if matched is None:
        label = "default"
        rule: ToolRule | None = None
        action: Action = policy.default
    else:
        label = _rule_label(*matched)
        rule = matched[1]
        action = rule.action

    if action == "deny":
        code = "default_deny" if rule is None else "tool_denied"
        return Decision("deny", code, f"tool {tool_name!r} is denied by {label}", label)

    if rule is not None:
        arg_decision = _check_args(rule, arguments, label)
        if arg_decision is not None:
            return arg_decision

    if policy.secrets.scan and (rule is None or rule.scan_secrets):
        found = find_secrets(arguments)
        if found:
            return Decision(
                policy.secrets.action,
                "secret_detected",
                "arguments contain what looks like a credential (" + ", ".join(found) + ")",
                label,
            )

    if action == "ask":
        return Decision("ask", "approval_required", f"tool {tool_name!r} requires approval", label)
    return Decision("allow", "allowed", f"allowed by {label}", label)
