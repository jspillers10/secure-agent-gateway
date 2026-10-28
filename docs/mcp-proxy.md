# MCP proxy reference

`sag mcp` puts a policy check in front of any stdio MCP server. The MCP
client (Claude Desktop, Claude Code, Cursor, or anything else that speaks
MCP over stdio) launches `sag` in place of the server, and `sag` launches the
real server as a child process.

```
MCP client  <-- stdio -->  sag mcp  <-- stdio -->  upstream MCP server
                              |
                              +-- policy.yaml
                              +-- ~/.sag/approvals/   (sag pending / sag approve)
                              +-- ~/.sag/audit.jsonl
```

## What happens to each message

Client to server:

- `tools/call` is evaluated against the policy.
  - `allow`: forwarded to the server.
  - `deny`: answered by `sag` with a tool result that has `isError: true` and
    the reason. The server never sees the call. The model reads the reason
    and can tell the user what happened.
  - `ask`: held. `sag` records an approval request and answers with
    `isError: true`, the reason, and the request id. After a human runs
    `sag approve <id>`, the same call (same tool, same arguments) succeeds
    once.
- Everything else (`initialize`, `tools/list`, `resources/*`, notifications)
  is forwarded.
- Every forwarded message is `sag`'s own re-serialization of the JSON it
  parsed. The server receives exactly the object the policy evaluated, so
  duplicate keys or other parser quirks cannot smuggle a different call past
  the check.
- Input that is not valid JSON gets a JSON-RPC parse error and is dropped.

Server to client:

- `tools/list` responses are filtered: tools whose policy action is `deny`
  are removed, so the model is never offered them. `ask` tools stay visible.
  Hiding a tool is a convenience. Enforcement happens on `tools/call`, so a
  model that calls a hidden tool by name is still blocked.
- Everything else is passed through unchanged.

## Policy file

`sag init` writes a commented starter policy. The full schema:

```yaml
version: 1                 # required value: 1
default: ask               # allow | deny | ask, for tools no rule matches
approval_ttl_seconds: 600  # how long `sag approve` keeps a grant usable (max 86400)

secrets:
  scan: true               # scan every argument for credentials
  action: deny             # deny | ask

tools:                     # checked in order; first match wins
  - name: "read_*"         # glob over the MCP tool name (case-sensitive)
    action: allow          # allow | deny | ask
    scan_secrets: true     # set false to skip the secret scan for this rule
    deny_args:             # argument-name glob -> list of value globs
      "*path*": ["*.env", "*/.ssh/*"]
    allow_args:            # argument-name glob -> list of value globs
      url: ["https://api.example.com/*"]
```

Unknown keys are rejected when the policy loads, so a typo such as
`deny_arg:` stops `sag` from starting, with an error that names the key.

Try a policy without starting anything:

```bash
sag check -c sag-policy.yaml read_text_file --args '{"path": "/home/me/app/.env"}'
# DENY  read_text_file
#   rule:   tools[3] (read_*)
#   reason: argument 'path' matches deny pattern '*.env'
```

`sag check` exits 0 for allow, 1 for deny, and 3 for ask (2 means bad input),
so it works in scripts and CI. Add `--json` for machine-readable output.

### Evaluation order

1. Find the first rule whose `name` glob matches the tool name. If none
   matches, use `default` and skip steps 3 and 4.
2. If the action is `deny`, deny.
3. `deny_args`: for every argument whose name matches the key glob, check
   every string inside the value (lists and nested objects are walked). If
   any string matches any value glob, deny.
4. `allow_args`: for every argument whose name matches the key glob, every
   string inside the value must match at least one value glob. Otherwise
   deny. An argument that is absent is not checked.
5. Secret scan (when `secrets.scan` and the rule's `scan_secrets` are both
   true): if any argument contains a credential pattern, apply
   `secrets.action`.
6. Apply the rule's action: `allow` forwards, `ask` holds for approval.

### How matching handles tricky values

Globs use Python's `fnmatch`: `*` matches any run of characters including
`/`, `?` matches one character, `[abc]` matches a set.

`deny_args` is built to catch evasions. Each value is checked in several
forms, and a match on any of them denies:

| Form | Example that is caught by `*.env` |
|---|---|
| lowercase | `.ENV` |
| backslashes as slashes | `C:\app\.env` |
| `..` segments collapsed | `docs/../.env` |
| trailing dots and spaces removed | `.env.` and `.env ` (Windows opens `.env`) |
| NTFS stream suffix removed | `.env::$DATA` |

`allow_args` is strict. Matching is case-sensitive, and for path-like
values (anything without `://`) the `..`-collapsed form must also match. So
with `allow_args: {path: ["/home/me/project/*"]}`, the value
`/home/me/project/../../etc/passwd` is denied. Write allow globs in the same
form the client sends (on Windows that usually means backslashes).

Prefer `allow_args` when you can list what is allowed. A deny-list can only
block the encodings someone thought of in advance.

### Secret detection

Detectors (names as they appear in reasons and the audit log):

`aws_access_key_id`, `aws_secret_access_key`, `private_key` (any
`-----BEGIN ... PRIVATE KEY-----` block), `github_token` (`ghp_`, `gho_`,
`ghu_`, `ghs_`, `ghr_`, `github_pat_`), `gitlab_token`, `slack_token`,
`anthropic_api_key`, `openai_api_key`, `google_api_key`, `stripe_secret_key`,
`jwt`.

Every string in the arguments is scanned, including object keys. The
reason names the detector and never includes the matched text. Patterns are
specific on purpose: a generic "high entropy string" check would block
ordinary hashes and IDs.

## Approvals

```
model calls write_file {...}       -> held, request id 3f9c0a1b2e
you run   sag pending              -> shows tool, server, redacted arguments
you run   sag approve 3f9c0a1b2e   -> grant valid for approval_ttl_seconds
model retries the same call        -> forwarded once
model calls it again               -> held again (new request)
```

An approval is bound to:

- the tool name,
- the SHA-256 of the canonical JSON of the arguments (`secure_agent_gateway.hashing.sha256_hex`,
  the same function the reference gateway uses), and
- the upstream server command.

A retry with any argument changed does not match and creates a new request.
A grant is consumed by exactly one call, including when several `sag`
processes share the same state directory: each transition is claimed by
exclusively creating a marker file, which the OS guarantees only one process
can win.

Unanswered requests expire after one hour. If the model retries before you
approve, it gets the same request id back, so retries do not pile up.

`sag pending` shows a preview of the arguments with credentials masked and
long strings truncated, so you can see what you are approving. The preview
is deleted from the record when you approve.

## Audit log

One JSON object per line in `<state-dir>/audit.jsonl` (default
`~/.sag/audit.jsonl`, override with `--audit-log`):

```json
{"argument_hash": "sha256:5b1f...", "code": "arg_denied", "decision": "deny",
 "event": "tool_call", "reason": "argument 'path' matches deny pattern '*.env'",
 "request_id": "4", "rule": "tools[3] (read_*)", "server": "npx @modelcontextprotocol/server-filesystem",
 "server_id": "sha256:9e0c...", "timestamp": "2026-10-28T17:02:11.412Z", "tool_name": "read_text_file"}
```

Events: `tool_call` (every decision), `tools_list_filtered`,
`approval_requested`, `approval_granted`, `approval_consumed`.

Arguments are recorded only as `argument_hash`. The event schema is closed
(`extra="forbid"`) and has no field that could hold a raw argument, tool
result, or matched secret. Reasons are built from the policy text and
argument names only. To check whether a particular call happened, hash its
arguments with `secure_agent_gateway.hashing.sha256_hex` and search for the hash.

## State directory

`--state-dir`, else `$SAG_HOME`, else `~/.sag`. It holds approvals and the
audit log. `sag pending` and `sag approve` use the same lookup, so if you
pass `--state-dir` to `sag mcp`, pass it to them too.

## Security model and limits

What the proxy is good at: it stops a model that has been steered by
injected instructions from calling tools or arguments your policy forbids,
and from pasting a credential it has seen into any tool call. It does this
outside the model, so no prompt can talk it out of a decision.

What it does not cover today:

- **Only `tools/call` is governed.** `resources/read`, `prompts/get`, and
  server-initiated requests (sampling, elicitation) pass through. In most
  clients the user picks resources, so the model does not request them
  directly.
- **Tool results are not inspected.** A tool result can itself carry an
  injection or a secret into the model's context. The secret scan catches
  the secret when the model tries to send it out through a tool call.
- **Encoded secrets evade the scan.** Base64, splitting a key across
  several calls, or any other transformation the model applies first will
  not match the detectors.
- **The server decides what an argument means.** If `notes.txt` is a
  symlink to `.env`, a path rule on `notes.txt` cannot know. Keep the
  server's own sandbox (for example, the directory list you pass to
  `server-filesystem`) as tight as you can, with the proxy as an extra
  layer on top.
- **The server is trusted to name its tools honestly.** The proxy
  constrains what the client may ask for. A malicious server can expose a
  shell under the name `read_file`. Only run servers you trust.
- **Approvals are as strong as the separation between agent and approver.**
  Anyone who can run `sag approve` as you, or write to the state directory,
  can approve. Do not give the agent a shell tool or write access to
  `~/.sag` through any server. The starter policy denies shell and exec
  tools for this reason.
- **stdio only.** Streamable HTTP transport is on the roadmap.

For a deployment with delegated identity (signed JWTs), OPA policy, and
per-call disposable Docker workers, see the hardened reference deployment
in the main README.
