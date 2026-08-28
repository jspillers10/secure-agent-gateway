# Architecture

## Components

```mermaid
flowchart LR
    Agent["AI Agent<br/>(caller, not part of this repo)"]

    subgraph Gateway["Secure Agent Gateway"]
        API["POST /v1/tool-invocations<br/>POST /v1/approvals"]
        Identity["Identity verifier<br/>(PyJWT, RS256 allow-list, sub==agent_id)"]
        Registry["Fixed tool registry<br/>+ per-tool Pydantic schemas<br/>(source of truth #1)"]
        Approvals["Approval store<br/>(validate, then atomic consume)"]
        CrossCheck["Registry ↔ policy<br/>metadata cross-check"]
        Audit["Gateway audit emitter<br/>(redacted, structured)"]
    end

    OPA["Open Policy Agent<br/>policy/gateway/authz.rego<br/>(source of truth #2:<br/>tool -> scope/risk/approval)"]
    Launcher["Worker Launcher<br/>(only Docker API client/socket)"]
    Worker["Fresh hardened Worker<br/>(three inert fixture tools)"]

    Agent -- "Bearer: delegated-identity JWT" --> API
    API --> Identity
    Identity --> Registry
    Registry --> Approvals
    Approvals -- "{agent_id, delegated_user_id,<br/>scopes, tool, approval_state}" --> OPA
    OPA -- "decision + metadata<br/>(required_scope, risk, approval_required)" --> CrossCheck
    CrossCheck -- "only if metadata matches registry" --> API
    API -- "signed, short-lived grant<br/>over mTLS" --> Launcher
    Launcher -- "one request over stdin" --> Worker
    Worker -- "per-run signed result" --> Launcher
    Launcher -- "closed result over mTLS" --> API
    API --> Audit
```

- **Agent**: out of scope for this repo. Any HTTP caller presenting a
  valid delegated-identity token.
- **Identity verifier**: cryptographic and claim verification only. Never
  trusts unverified claims, and requires the JWT `sub` claim to equal
  `agent_id` (see [Identity model](#identity-model) below and
  `src/gateway/identity/tokens.py`).
- **Fixed tool registry**: the only place a tool name resolves to a
  schema, risk, scope, and artifact digest. A corresponding closed registry
  inside the Worker resolves the inert handler. No dynamic import and no
  `getattr` on client input
  (`src/gateway/registry/tools.py`). This is one of *two* independent
  sources of truth for what a tool costs; see
  [Who owns the policy mapping](#who-owns-the-policy-mapping) below.
- **Approval store**: single-use records bound to (tool, argument hash,
  agent identity, delegated-user identity, expiration), with a
  non-consuming `validate()` and a separately-called atomic `consume()`
  (`src/gateway/approvals/store.py`); see
  [Two-phase approval flow](#two-phase-approval-flow).
- **OPA**: the *only* component that renders allow/deny/approval-required,
  and the *only* place the tool -> required-scope/risk/approval-required
  mapping is decided from (the gateway sends a tool name, never a
  pre-resolved scope or risk). The gateway treats any failure to reach it,
  or any response that fails its closed schema, as a deny
  (`src/gateway/policy/opa_client.py`, `policy/gateway/authz.rego`).
- **Registry ↔ policy metadata cross-check**: after OPA answers, the
  gateway compares OPA's `required_scope`/`risk`/`approval_required`
  metadata against its own registry entry for the same tool and fails
  closed on any mismatch, regardless of what `decision` says. See
  [Why a compromised gateway can't weaken policy](#why-a-compromised-gateway-cant-weaken-policy).
- **Worker Launcher**: the only service with the Docker SDK and socket. Its
  one-field request accepts an `ExecutionGrant`, not runtime options; its own
  registry selects an image that is resolved once to an immutable Docker image
  ID and a fixed entry point.
- **Disposable Worker**: one non-root, read-only, network-disabled container
  per accepted grant. It receives one bounded stdin record, re-verifies the
  grant, executes one of the three inert fixtures, signs the result with a
  per-run key, and exits. It has no Docker SDK or socket.
- **Mock tools**: pure, inert functions executed only inside the Worker. No
  shell, no network, no real side effects (`src/gateway/tools_impl/`).
- **Audit emitters**: two closed Pydantic schemas (`AuditEvent` for the
  tool-invocation lifecycle, `ApprovalAuditEvent` for the approval
  lifecycle) that structurally cannot carry raw arguments, tokens,
  approval ids, or approver credentials; only hashes and enum-like
  status fields (`src/gateway/audit/log.py`). Separate redacted Launcher and
  Worker lifecycle schemas record accepted/start/terminal provenance without
  arguments, credentials, grants, nonces, or raw results
  (`src/gateway/execution/audit.py`).

## Identity model

The JWT subject (`sub`) is defined, for this project, to be the same
value as the `agent_id` claim: the token authenticates the *agent*, and
`delegated_user` is a separate, asserted (not cryptographically verified)
claim naming the human the agent is acting for. `verify_delegated_token`
requires `sub == agent_id` and rejects the token outright if they differ.
See the full writeup in `src/gateway/identity/tokens.py`'s module
docstring, and `TokenSubjectMismatch` /
`tests/test_token_verification.py::test_sub_agent_id_mismatch_rejected`.

RS256 is the only algorithm this gateway will ever accept, not just by
default, but enforced: `load_settings()` rejects `JWT_ALGORITHM=HS256`,
`none`, or any value other than `RS256` at startup, before the process
serves any traffic (`src/gateway/config.py::SUPPORTED_JWT_ALGORITHMS`,
`tests/test_config.py::test_load_settings_rejects_unsupported_jwt_algorithm`).

## Who owns the policy mapping

`policy/gateway/authz.rego` defines a `tools` object (the tool name ->
(`required_scope`, `risk`, `approval_required`) mapping) as OPA's own
data. The gateway never sends a pre-resolved `required_scope` or `risk`
in its policy input; it sends only verified identity, the requested tool
*name*, and an approval state. A compromised or buggy gateway that tried
to send those fields anyway would have them ignored entirely, because
nothing in the Rego decision logic reads them. This is proven, not just
asserted, at three levels:

1. `policy/gateway/authz_test.rego::test_ignores_spoofed_required_scope_and_risk`:
   a Rego unit test.
2. `tests/test_approvals.py::test_fake_policy_client_ignores_spoofed_scope_metadata`:
   a Python-level test of the policy-client contract.
3. `scripts/verify_opa_hardening.py`: a live-OPA integration check run
   against the real, running Docker Compose stack.

## Request sequence: `POST /v1/tool-invocations`

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway
    participant Approvals as Approval Store
    participant OPA
    participant Launcher as Worker Launcher
    participant Worker as Disposable Worker

    Agent->>Gateway: POST /v1/tool-invocations<br/>Authorization: Bearer <JWT><br/>{tool, arguments, approval_id?}
    Gateway->>Gateway: Verify signature, iss, aud, exp, sub==agent_id, claims<br/>(RS256-only allow-list, no alg confusion)
    alt token invalid
        Gateway-->>Agent: 401 (generic, no oracle)
    end
    Gateway->>Gateway: Resolve tool from fixed registry
    alt unknown tool
        Gateway-->>Agent: 404 unknown_tool
    end
    Gateway->>Gateway: Validate arguments (extra="forbid")
    alt bad/extra arguments
        Gateway-->>Agent: 422 invalid_arguments
    end
    Gateway->>Approvals: validate(approval_id, ...): non-consuming
    Approvals-->>Gateway: valid | invalid (never mutates the record)
    Gateway->>OPA: POST /v1/data/gateway/authz/result<br/>{agent_id, delegated_user_id, scopes, tool, approval_state}
    alt OPA unreachable / response fails closed schema
        Gateway-->>Agent: 503 policy_unavailable (approval untouched)
    end
    OPA-->>Gateway: decision + required_scope + risk + approval_required
    Gateway->>Gateway: Cross-check metadata against fixed registry
    alt metadata disagrees with registry
        Gateway-->>Agent: 503 policy_registry_mismatch (approval untouched)
    end
    alt deny
        Gateway-->>Agent: 200 {decision: "deny"} (approval untouched)
    else approval-required
        Gateway-->>Agent: 200 {decision: "approval-required"} (approval untouched)
    else allow, tool requires approval
        Gateway->>Approvals: consume(approval_id, ...): atomic final check
        alt consume fails (race lost / expired since validate)
            Gateway-->>Agent: 200 {decision: "deny"} (approval finalization failed)
        end
    end
    opt allow, and (no approval needed OR consume succeeded)
        Gateway->>Gateway: Build ActionEnvelope and sign short-lived ExecutionGrant
        Gateway->>Launcher: POST /v1/executions over mTLS<br/>{grant only; no runtime controls}
        Launcher->>Launcher: Verify signature, claims, bindings, and nonce;<br/>atomically claim nonce
        Launcher->>Worker: Create fresh hardened container by immutable image ID;<br/>deliver one bounded stdin record
        Worker->>Worker: Re-verify grant and execute fixed-registry fixture
        Worker-->>Launcher: Per-run signed ToolResultEnvelope
        Launcher->>Launcher: Verify invocation/nonce/worker/tool/artifact binding; destroy Worker
        alt Launcher, Worker, protocol, or cleanup fails
            Gateway-->>Agent: 502 tool_execution_failed (generic)
        end
        Launcher-->>Gateway: authenticated closed result
        Gateway-->>Agent: 200 {decision: "allow", result}
    end
    Gateway->>Gateway: Emit redacted audit event(s) (always, every branch)
```

## Response shape

All three policy outcomes (`allow`, `deny`, `approval-required`) return
`200 OK` with a `decision` field: the gateway successfully rendered a
decision in each case. HTTP error codes are reserved for requests the
gateway could not evaluate at all or could not trust the answer to:
`401` (bad token), `404` (unknown tool), `422` (schema validation
failure, including a rejected client-supplied `risk` field), `502`
(isolated-execution failure), `503` (policy engine unreachable, or the
policy's metadata disagreed with the registry).

## Two-phase approval flow

`admin.rotate_key` requires approval. A separate, distinctly-authenticated
endpoint (`POST /v1/approvals`, gated by a static approver credential
standing in for a real approver identity system; see
[Known limitations](threat-model.md#known-limitations)) creates a record
binding a tool name, an argument hash, and an identity pair to a
single-use, time-limited token. The approver identity recorded on that
grant (`granted_by`) is derived from trusted server configuration
(`APPROVER_IDENTITY`), never from client input: the request schema has
no `granted_by` field at all.

Consuming that approval is a **two-phase** operation, specifically to
avoid burning it on anything other than a genuine execution:

1. **Validate** (non-consuming): the gateway checks the approval's
   binding (tool, argument hash, agent identity, delegated-user
   identity, expiration) without marking it used. This produces the
   `approval_state` ("valid" / "invalid" / "none") sent to OPA.
2. **Decide**: OPA is asked for a decision. A policy denial, an
   approval-required response, a policy-engine outage, or a
   registry/policy metadata mismatch all leave the approval exactly as
   valid as it was before the request started.
3. **Consume** (atomic): only when OPA answers `allow` for a tool that
   requires approval does the gateway call the *same* record's `consume()`,
   a single lock-guarded check-and-mark-used operation. Only then does
   execution happen.

This is what prevents "premature consumption": in a naive single-phase
design, an approval consumed at policy-input-preparation time would be
stranded as spent by a subsequent denial or outage, even though nothing
was ever executed. It's also what makes a race between two callers
presenting the same approval safe: both can validate as "the approval
looks fine", but only one can win the atomic consume.
See `src/gateway/approvals/store.py` and the regression tests in
`tests/test_approvals.py` (`test_approval_survives_policy_outage`,
`test_approval_survives_policy_denial`,
`test_approval_race_only_one_consumer_wins`,
`test_approval_expiring_between_validate_and_consume_fails_closed`).

Presenting an invalid approval (wrong id, already used, wrong arguments,
wrong identity, expired) is treated as an outright deny, not a second
invitation to retry, and is recorded in the audit trail with a distinct
`approval_state`. The audit trail never records the approval id itself,
the approver credential, or raw arguments; only tool name, identity,
argument hash, and an event/reason (see `ApprovalAuditEvent` in
`src/gateway/audit/log.py`).

## Why the risk level can't be forged

`ToolInvocationRequest` (`src/gateway/api/schemas.py`) has no `risk`
field and `extra="forbid"`. Risk is never client input, and, as of the
OPA-owns-the-mapping correction, it isn't gateway-computed-and-sent
either: OPA resolves it from its own `tools` data given only the tool
name, and the gateway cross-checks that resolved value against its own
registry before trusting anything about the decision.

## Why a compromised gateway can't weaken policy

Two independent components each hold their own copy of the tool -> scope/
risk/approval-required mapping: the Python `TOOL_REGISTRY`
(`src/gateway/registry/tools.py`) and OPA's `tools` data
(`policy/gateway/authz.rego`). The gateway never sends its copy to OPA;
it sends only the tool *name*, so a bug or compromise in the gateway
that caused it to construct a wrong policy input still can't make OPA
resolve the wrong scope or risk, because OPA was never told one; it
looks it up itself. The gateway then cross-checks OPA's answer against
its own copy and fails closed on any disagreement, which catches the
*other* direction of drift (OPA's data going stale relative to the
registry). See [Who owns the policy mapping](#who-owns-the-policy-mapping)
for how this is proven, not just designed.

## Why algorithm confusion can't work

`verify_delegated_token` calls `jwt.decode(..., algorithms=[algorithm])`
with a single-element allow-list, and `algorithm` can only ever be
`"RS256"`, because `load_settings()` rejects any other value at startup
(see [Identity model](#identity-model)). PyJWT only ever attempts
verification using an algorithm drawn from that list; it never lets the
token's own `alg` header pick the verification method. Neither `none` nor
`HS256` is ever in the allow-list, so neither a signature-less token nor
an HS256-with-public-key-as-secret forgery can verify. See
`tests/test_token_verification.py::test_algorithm_confusion_none_rejected`
and `::test_algorithm_confusion_hs256_with_public_key_rejected`.

## Docker network topology

```mermaid
flowchart LR
    Host["Host machine<br/>(curl, smoke_test.py)"]

    subgraph edge["edge_net (normal bridge)"]
        Gateway["gateway<br/>127.0.0.1:8088 published"]
    end

    subgraph internal["internal_net (Docker internal: true,<br/>no route to the internet)"]
        Gateway
        OPA["opa<br/>mTLS, no published port"]
        Launcher["launcher<br/>mTLS, no published port<br/>only Docker socket holder"]
    end

    Host -- "127.0.0.1:8088" --> Gateway
    Gateway -- "https://opa:8181 (mTLS)" --> OPA
    Gateway -- "https://launcher:8443 (mTLS + signed grant)" --> Launcher
    Launcher -- "Docker API" --> Worker["fresh Worker<br/>no network attachment"]
```

`internal_net` is a Docker Compose network with `internal: true`: Docker
gives it no route to the outside world, which was verified empirically
(not assumed): a container attached only to it cannot resolve DNS or
open any outbound connection (see `docs/threat-model.md`'s security
assumptions for how this was checked). Both `gateway` and `opa` sit on
it, and it carries the mutually authenticated Gateway-to-OPA and
Gateway-to-Launcher control channels. Disposable Workers are attached to no
Docker network at all.

`opa` is attached to **only** `internal_net` and has no published port at
all. This was a deliberate choice after finding, empirically, that Docker
Compose does not honor a service's `ports:` mapping when its only network
is `internal: true`: publishing a port relies on the same NAT
infrastructure that `internal: true` disables. Rather than weaken OPA's
isolation to get a published port, OPA simply gets none: a stronger
guarantee than "published but loopback-only" would have been, at the cost
of OPA not being directly reachable from the host (see
`scripts/verify_opa_hardening.py` for how it's still tested, from a
container joined to the same internal network).

`gateway` is additionally attached to `edge_net`, an ordinary
non-internal bridge network, solely so its own port can be published to
`127.0.0.1:8088` for manual curl testing and `scripts/smoke_test.py`.
That second network leg does mean the gateway container itself retains
real network-level egress capability; it is not egress-blocked the way
`opa` is. See `docs/threat-model.md`'s known limitations for that
tradeoff made explicit, and why it's judged acceptable (the gateway's own
code never constructs an outbound HTTP client except `OPAHttpPolicyClient`,
targeting only the configured `OPA_URL`).

OPA's own HTTPS API requires a client certificate signed by the development
Gateway-client CA. Its `--authorization=basic` policy in
`policy/system/authz.rego` checks the Gateway SPIFFE URI and allows only the decision
query and a liveness check; every other request, including attempts to
upload/replace/delete a policy via `PUT`/`DELETE /v1/policies/*` or to
read `/v1/data`, gets a `401`. This was verified against a real running
OPA server (not inferred from documentation); see
`policy/system/authz_test.rego` and `scripts/verify_opa_hardening.py`.
