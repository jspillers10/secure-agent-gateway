# Milestone 2 Implementation Report

## Scope and claim

This milestone adds one real read-only tool, `web.fetch_text`, and a separate
egress broker while preserving the Milestone 1 Gateway, OPA, signed-grant,
Launcher, disposable-Worker, result-authentication, approval, and audit paths.
The scoped claim is that a registered Worker can retrieve bounded UTF-8 text
from an explicitly permitted HTTPS origin without receiving a general network
route, and that the enumerated destination, redirect, credential, and resource
attacks are denied before a forbidden connection.

This is a research prototype, not a production proxy, workload-identity
system, sandbox, or proof of SSRF resistance.

## Implemented path

1. The public API remains `POST /v1/tool-invocations`. `web.fetch_text` has one
   required argument, `url`, and the existing request/response contract is
   unchanged.
2. The Gateway canonicalizes the HTTPS URL before hashing it, records the
   normalized destination in the `ActionEnvelope`, and signs an `EgressGrant`
   containing only server-owned origin, content-type, redirect, size, and time
   authority.
3. The Launcher re-verifies the grant and creates the same non-root,
   read-only, capability-dropped, quota-bound, `network_disabled=True` Worker.
   For this tool only, it attaches one fixed named volume read-only at
   `/run/secure-agent-egress`; no caller can select the volume or path.
4. The Launcher issues a fresh Worker client certificate valid for at most the
   invocation window. Its only URI SAN binds both invocation ID and Worker ID.
5. The Worker re-verifies the grant and sends one closed request over TLS on
   the Unix socket. It has no broker URL, HTTP method, headers, cookies,
   credentials, DNS answer, IP address, or network option to choose.
6. The broker verifies mTLS identity, exact invocation/Worker binding, signed
   grant, tool/artifact/argument/approval binding, expiry, replay, destination
   authority, and limits. It then performs canonical origin authorization,
   one connect-time DNS resolution, all-answer IP classification, a numeric-IP
   connection with TLS verification for the original hostname, a fixed GET,
   bounded response processing, and the complete independent check on every
   redirect.
7. Every attempted hop produces a closed audit decision with hashes and timing,
   not raw response content or credentials.

## Destination and protocol policy

- HTTPS only; port 443 only; GET only.
- No user-info, fragments, controls/whitespace, backslashes, malformed percent
  escapes, alternate numeric host forms, caller headers, cookies, implicit
  authentication, proxies, or compression.
- Raw non-ASCII path and query characters are rejected before DNS. Existing
  valid percent escapes are retained and normalized, so the validated request
  target has one ASCII HTTP/1.1 wire representation.
- Host case, DNS trailing dots, IDNA, and percent-escape case are canonicalized.
- Every IPv4 and IPv6 answer must be global. Loopback, private, link-local,
  multicast, unspecified, reserved, non-global, IPv4-mapped blocked IPv4, and
  explicit metadata addresses are denied.
- At most 32 DNS answers are accepted. A larger set is denied in full before
  connection and recorded with its actual answer count; answers are neither
  partially validated nor silently truncated to fit the closed audit schema.
- The selected numeric address comes from the already validated answer set;
  the connector does not resolve the hostname again. TLS still uses the
  canonical hostname for certificate verification.
- Redirects are limited to three and independently canonicalized, allowlisted,
  resolved, address-validated, connected, and audited.
- Only `text/plain` and `text/html`, optional UTF-8 charset, strict UTF-8 bytes,
  identity content encoding, at most 64 KiB, and at most five seconds total.

## Security matrix and controls

`tests/test_egress.py` covers IPv4/IPv6 loopback, private, link-local,
multicast, metadata, unspecified, reserved/non-global and mapped addresses;
decimal/octal/hex alternate numeric hosts; scheme, port, user-info, slash,
control, percent, fragment, case, trailing-dot, and IDNA handling; mixed DNS
answers and answer changes; pinned connection addresses; allowed direct and
independently allowed redirect controls; allowed-to-blocked redirect with zero
protected connections; disallowed origins, loops, and hop limits; body,
content-type, encoding, UTF-8, slow-response, and TLS failures; the GET-only
header set; protocol unknown-field rejection; grant expiry/replay; and missing,
unknown-CA, expired, wrong-role, and other-invocation Worker credentials. The
tests use an independent connector observer; every blocked destination case
asserts zero connector calls.

`tests/test_launcher.py` additionally inspects the real Docker create options:
the authorized web Worker remains network-disabled, has no `network` option,
and receives exactly the fixed read-only socket volume and fixed supplemental
  group. The existing live hardening harness continues to attempt a direct IP
  socket from a Worker. `scripts/verify_milestone2.py` exercises direct
  retrieval, an independently allowed redirect, an allowed-to-blocked redirect,
  and an alternate numeric host through the real Compose path. A separate
  protected fixture increments a shared counter immediately after TCP `accept`,
  before TLS or HTTP parsing. Its observation endpoint is on the distinct
  allowed HTTPS fixture and has a read-only mount, so control traffic cannot
  increment the protected counter. The harness first proves a direct TCP
  control increments the counter and then proves the blocked redirect causes
  zero additional accepted connections.

`scripts/verify_broker_mtls.py` runs in a separate read-only evaluation
container with networking disabled. It receives only the existing broker
socket volume, the development credential mount, a bounded temporary
filesystem, and the fixed broker socket group. Against the real Unix TLS
endpoint it verifies a matching positive request, TLS rejection of an
otherwise appropriate Worker certificate signed by an untrusted CA, and
authorization rejection of a trusted Worker certificate bound to a different
invocation. Unique, current grants isolate the cases from expiry and replay.
The invocation-mismatch case must complete TLS and receive a structured deny
with no DNS work. Fixture counter observations before and after each negative
case establish zero protected-target connections; the matching control is
independently observed as exactly one connection.

The harness also contains live cases for no client certificate, an expired
certificate issued through the production invocation-certificate path, and a
trusted certificate with server-auth rather than client-auth purpose. Each
targets the dedicated protected listener and compares its accepted-connection
count before and after. Their current execution status is recorded below; the
existence of a harness case is not treated as evidence that it passed.

### Strict TLS certificate-profile correction

The first local Compose run reached the broker but failed the TLS handshake
with OpenSSL's `Missing Authority Key Identifier` error. Inspection of the
generated chain showed that every persistent development CA and service leaf
already contained an Authority Key Identifier. The missing extension was on
the short-lived, per-invocation Worker client leaf minted by the Launcher.

The runtime issuer now adds a non-critical Authority Key Identifier derived
from the Worker client CA public key. CA trust, TLS verification, service URI
identity, client-auth purpose, certificate lifetime, and invocation/Worker
binding remain unchanged. No persistent key or certificate required rotation:
the affected leaf exists only for one invocation and was regenerated by the
rebuilt Launcher. A focused regression test performs an actual mutual-TLS
handshake with `VERIFY_X509_STRICT` and the runtime-issued Worker leaf.

### Post-review deadline and protocol-log correction

A bounded follow-up correction addressed two publication-review findings.
The broker now derives one monotonic operation deadline from the earlier of
the signed grant's remaining lifetime and the signed, server-capped fetch
timeout. That same deadline is checked before every hop and passed unchanged
through DNS resolution, numeric-address connection, TLS, redirects, and
response reads. The broker also checks it immediately after resolver and
connector returns, so an injected or defective dependency cannot cause a
later hop after authority has expired.

System `getaddrinfo` now runs in one disposable process per lookup using the
standard-library `spawn` context, which avoids forking the broker's
multi-threaded TLS server. On deadline expiry the parent terminates the child,
escalates to a kill if required, joins it, closes the process and pipe handles,
and returns only after cleanup. The child returns a closed success/error
message and no resolver exception text. This adds no dependency or externally
visible service, but it changes DNS latency and must be included in the next
full-path measurement.

Broker transport, JSON, and closed-schema failures now log only fixed reason
codes plus whether TLS had been established. They do not log exception text,
tracebacks, rejected values, grants, certificates, or payload bytes. The
client still receives only the fixed `broker_protocol_invalid` envelope.

### Remaining review corrections

Raw Unicode request targets are rejected with the fixed
`url_request_target_non_ascii` code before resolution. DNS answer sets larger
than 32 are rejected whole with `dns_answer_limit_exceeded`; the audit record
stores the actual count and no misleading partial list of hashes. Authenticated
requests that fail URL or DNS policy still receive one terminal hop decision.
Malformed framing, UTF-8, JSON, and schema input receives the fixed, redacted
protocol result with no fabricated invocation context, because no validated
request identity exists at that boundary.

The supported response-body limit remains 65,536 bytes. The Worker and
Launcher complete-output limits are now 524,288 bytes, and the Worker's local
Docker log cap is 1 MiB. The finite result bound is calculated as 65,536 body
characters times the maximum six-byte JSON escape expansion, plus 3,351
schema-bounded non-body string characters times six, plus 4,096 bytes for
closed-schema keys, punctuation, and bounded numeric fields: 417,418 bytes.
The 524,288-byte protocol limit therefore exceeds the calculated maximum by
106,870 bytes. A regression serializes and signs a valid 65,536-NUL body with
a maximum-length URL and identity fields; the exact body boundary succeeds,
while one byte beyond the signed body limit is rejected.

CI now executes `opa check --strict policy/`; the label and command no longer
disagree.

## Latency measurement

Two measurement scopes are intentionally separate.

### Host broker-core measurement completed

On 2026-09-01, Windows with Python 3.13.5 ran
`scripts/measure_milestone2_host.py` for 20 authenticated broker-core fetches
of `https://example.com/`. These requests used real DNS, TCP, TLS hostname
verification, HTTP parsing, response bounds, per-invocation Worker
certificates, and signed grants. They did **not** include Gateway/OPA,
Launcher, Docker Worker startup/teardown, or TLS-over-Unix-socket transit.

| Component | p50 | p95 |
|---|---:|---:|
| Connect-time DNS | 0.757 ms | 1.029 ms |
| Broker hop (DNS + TCP/TLS/GET/read/policy) | 124.241 ms | 134.103 ms |
| Authenticated total broker fetch | 125.068 ms | 135.319 ms |

The script prints all raw samples. These are single-host observations against a
public service, not stable performance claims.

### Full Compose measurement completed

`scripts/measure_milestone2.py` measures the complete
Gateway → OPA → Launcher → fresh Worker → Unix-mTLS broker → HTTPS fixture path
and reports DNS, broker, and total-fetch latency separately. On 2026-09-03,
Windows with Python 3.13.5 and Docker Desktop's Linux engine 29.7.2 ran 20
sequential allowed invocations against the local HTTPS fixture using the
current build and process-isolated DNS resolver.

| Component | p50 | p95 | Minimum | Maximum |
|---|---:|---:|---:|---:|
| Process-isolated connect-time DNS | 357.267 ms | 375.738 ms | 346.352 ms | 377.870 ms |
| Broker hop | 359.802 ms | 378.014 ms | 348.952 ms | 380.108 ms |
| Full controlled fetch | 1259.519 ms | 1413.962 ms | 1180.718 ms | 3297.720 ms |

The full controlled-fetch timer starts before the host request to the Gateway
and ends after its response, so it includes OPA authorization, Launcher work,
fresh Docker Worker creation and teardown, Worker grant verification,
Unix-socket mutual TLS, broker enforcement, and the fixture HTTPS request. The
broker field is broker-reported hop time; the DNS field is its connect-time
resolution subset. These single-machine prototype measurements are not a
production capacity or tail-latency claim. The script printed all 20 raw
samples during the run.

## Verification status

The earlier full local readiness run on 2026-09-02, before the post-review
deadline and logging correction, produced these results:

- 157/157 Python tests passed on Windows with Python 3.13.14; aggregate
  statement coverage was 76%.
- Ruff passed across `src`, `tests`, and `scripts`; strict Mypy passed for all
  53 source files; Bandit reported zero issues.
- 29/29 OPA policy tests passed and `opa check --strict` compiled the policy
  tree successfully with the pinned OPA 0.70.0 image.
- `pip-audit` found no known dependency vulnerabilities. The unpublished local
  `secure-agent-gateway` distribution itself was explicitly skipped because it
  is not present on PyPI.
- Both the source distribution and wheel built successfully. The wheel and its
  pinned runtime dependencies installed into a new isolated environment, and
  package version `0.1.0` imported successfully.
- 9/9 live Gateway smoke checks passed.
- 5/5 live Milestone 2 path checks passed: direct retrieval, independently
  allowed redirect, allowed-to-blocked redirect denial, zero protected-target
  connections, and alternate-numeric-host rejection.
- 7/7 live broker-socket assertions passed: matching identity/grant success and
  observation; untrusted-CA TLS rejection and zero connections; successful TLS
  followed by cross-invocation authorization denial, zero DNS work, and zero
  connections.
- 8/8 live Worker hardening and cleanup checks passed.
- 6/6 live OPA hardening checks passed.
- 6/6 live Gateway-to-OPA and Gateway-to-Launcher mutual-TLS checks passed.

Focused verification of the post-review correction on 2026-09-02 produced:

- 63/63 tests in `tests/test_egress.py` passed. The new regressions cover a
  successful spawned system lookup, forced cleanup of a delayed resolver,
  configured-timeout termination, grant-expiry termination with zero connector
  calls, and exclusion of a secret marker from protocol logs and the fixed
  error response.
- Ruff passed for the two changed egress modules and focused test file.
- Strict Mypy passed for the two changed egress modules.
- Bandit reported no issue in the two changed egress modules.
- The full Python/static suite, Compose checks, live broker checks, package
  build, dependency audit, and latency measurements were not rerun in this
  bounded correction pass.

Focused verification of review findings 3--6 on 2026-09-02 produced:

- 91/91 focused tests in `tests/test_egress.py` and `tests/test_launcher.py`
  passed. These include raw Unicode path/query rejection, preservation of
  valid escapes, whole-set denial for 33 DNS answers with zero connector
  calls, fixed malformed framing/encoding/schema results, exact 64 KiB body
  behavior, worst-case signed-result serialization, and the enlarged bounded
  Docker log configuration.
- Scoped Ruff passed. Strict Mypy passed for the 12 affected source modules,
  and the one subsequently adjusted Worker module passed again. Bandit passed
  across `src` with the repository configuration.
- `opa check --strict /policy` passed inside the running pinned OPA container.
- The live Compose harness reported 6/6 checks passed. A raw TCP positive
  control changed the dedicated listener from 0 to 1 accepted connection; the
  allowed-to-blocked redirect left it at 1. Direct and redirect fetches also
  completed through the containerized process-isolated resolver, with broker
  audit events containing the spawned DNS timings.
- The corrected live broker credential harness passed all 13 assertions:
  matching identity/grant success and connection observation; unknown-CA,
  missing, expired, and wrong-purpose TLS rejection with zero additional
  protected connections; and successful trusted-client TLS followed by
  cross-invocation authorization rejection before DNS or egress. The missing
  certificate case accepts a `BrokenPipeError` only when a subsequent TLS read
  produces the specific `certificate_required` alert. Focused tests confirm a
  bare broken pipe, timeout, or unrelated TLS alert remains a harness failure.

The final current-build validation matrix completed on 2026-09-03:

- A disposable Python 3.13.5 candidate environment upgraded its bootstrap
  installer to pip 26.2.1 before installing the unchanged CI-equivalent
  `.[dev]` scope. Every direct version matched `pyproject.toml`, including the
  runtime, Launcher, test, static-analysis, audit, and build dependencies, and
  `pip check` reported no broken requirements.
- A separate disposable environment ran the repository-pinned pip-audit
  2.10.1 against the candidate environment's installed `Lib/site-packages`.
  It found no known vulnerabilities and no advisory was suppressed.
  `secure-agent-gateway 0.1.0` was the sole skip because the unpublished local
  distribution is not available on PyPI. The scan covers Python distributions
  known to the configured advisory services; it does not audit this project's
  source, OS packages, container images, Docker, or the OPA binary. Direct
  requirements are pinned, but transitive requirements are not lockfile-bound
  and were resolved for this installation.
- Because a fresh Python 3.13.5 virtual environment reproduced the vulnerable
  pip 25.1.1 bootstrap state before the explicit upgrade, both CI jobs that
  install project dependencies now upgrade bootstrap pip to at least 26.2
  first. No application or development dependency declaration changed.
- Build 1.6.0 produced both `secure_agent_gateway-0.1.0.tar.gz` and
  `secure_agent_gateway-0.1.0-py3-none-any.whl` using Hatchling 1.32.0. A fresh
  Python 3.13.5 environment installed the wheel and runtime dependencies,
  imported `gateway`, confirmed package version 0.1.0, and passed `pip check`.
- 174/174 Python tests passed on Windows with Python 3.13.5 and 79% aggregate
  statement coverage. Ruff passed across `src`, `tests`, and `scripts`; strict
  Mypy passed all 53 source files; Bandit reported zero issues across `src`.
- 29/29 OPA policy tests passed and `opa check --strict /policy` succeeded with
  the pinned OPA 0.70.0 image.

The post-review current-build validation matrix completed on 2026-09-08:

- The remaining review corrections now enforce one end-to-end deadline across
  DNS, TCP, TLS, request, response headers, and body reads; redact denied
  origins from responses and audit records; convert excessively nested JSON to
  the fixed protocol error; require corroborated certificate/TLS transport
  failures in the internal mTLS harness; and keep the documented reproduction
  steps aligned with CI.
- 198/198 Python tests passed with 82% aggregate statement coverage. Ruff
  passed across `src`, `tests`, and `scripts`; strict Mypy passed all 53 source
  files; Bandit reported zero findings across `src`; and `git diff --check`
  passed apart from Windows line-ending notices.
- A clean disposable Python 3.13 environment passed dependency installation,
  `pip check`, and a separate pip-audit scan with no known vulnerabilities.
  The source distribution and wheel built successfully, and the wheel imported
  as version 0.1.0 in a fresh environment.
- 29/29 OPA tests and `opa check --strict` passed with the pinned image.
- The full Compose stack passed host smoke tests, controlled direct and
  redirected HTTPS fetches, redirect and deployment-CIDR denials with zero
  protected-target connections, per-service credential isolation, Gateway
  network confinement, disposable Worker hardening and cleanup, OPA mutation
  and introspection denials, broker client-certificate and invocation-binding
  negatives, and Gateway-to-OPA/Launcher mutual-TLS controls.
- The rebuilt Compose path passed 9/9 Gateway smoke checks, 6/6 controlled
  egress checks, 13/13 live broker Unix-mTLS and invocation-binding assertions,
  8/8 Worker hardening and cleanup checks, 6/6 OPA hardening checks, and 6/6
  Gateway-to-OPA and Gateway-to-Launcher mutual-TLS checks. No disposable
  Worker container remained after the checks.
- The 20-run current-build full-path measurement, including process-isolated
  DNS, completed with the results recorded in the latency section above.

The allowed-to-blocked redirect reached the authenticated broker and was
denied by redirect enforcement; the fixture independently observed zero
connections to the protected target. The live untrusted-CA case failed at the
intended TLS control. The invocation-mismatch case used a current, signed,
unreplayed authorization and a current Worker certificate from the trusted CA;
TLS completed before the broker returned its authorization denial, with no DNS
resolution or protected-target connection.

The deadline, protocol-log, connection-observer, closed-failure, output-bound,
strict-OPA, and live credential-coverage findings are implemented and supported
by the evidence above. The checkpoint is ready for final technical review and
remote CI based on the demonstrated local acceptance checks. Remote CI has not
run, so this is not yet publication evidence. This remains a research
checkpoint, not a production-readiness or general security claim.

## Outstanding publication-review findings

- Remote CI remains outstanding; all results above are local observations.
- The dependency audit cannot assess the unpublished project source, operating
  system packages, container images, Docker daemon, or OPA binary, and the
  absence of a transitive lock file limits exact dependency reproducibility.

## Limitations

- Allowed content remains untrusted and may contain prompt injection or active
  markup. Milestone 5 is not implemented.
- A permitted origin can proxy other data or change behavior after approval;
  destination validation cannot establish semantic trust.
- Docker shares the host kernel. The Launcher and Docker daemon remain
  high-value trust assumptions, and the Launcher now also holds the
  development Worker client-CA key.
- Workload certificates, grant replay state, broker replay state, approval
  state, and audit output are local prototype mechanisms without production
  enrollment, revocation, durability, replication, or protected keys.
- IP and IDNA classification require maintenance. DNS, TLS, and HTTP parser
  vulnerabilities, traffic analysis, origin compromise, and denial of service
  against the broker remain possible.
- The broker currently uses HTTP/1.1 and identity encoding only. It does not
  support authenticated origins, cookies, arbitrary headers, non-443 HTTPS,
  HTTP/2, content decompression, or general-purpose browsing.
- Host ingress terminates at a credential-free, fixed-target proxy. The Gateway
  has only the internal control-plane and ingress networks; Workers have no
  network attachment; and the trusted broker alone reaches the fixture
  networks. This is a development topology, not a claim of production-grade
  infrastructure isolation.
