"""The single vertical-slice endpoint: POST /v1/tool-invocations.

Flow: verify identity -> resolve tool from fixed registry -> validate
arguments -> non-consuming approval validation -> ask OPA (which owns the
tool -> scope/risk/approval-required mapping) -> cross-check OPA's
metadata against the fixed registry -> execute (consuming any approval
atomically immediately beforehand) only on allow -> always emit a
redacted audit event. Every branch fails closed: an unknown tool, invalid
arguments, an unreachable policy engine, or a registry/policy metadata
mismatch all result in a denial, never a default allow.

Approval two-phase sequence (see src/gateway/approvals/store.py for the
full rationale): validate (non-consuming) -> ask OPA -> only on "allow"
with the tool's approval_required flag set, atomically consume -> only
proceed to execution if that consume succeeds. A policy denial, an
approval-required response, a policy-engine outage, or a registry/policy
mismatch never consumes an approval; a race between two callers presenting
the same approval can only ever let one of them execute.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError

from gateway.api.deps import (
    get_approval_store,
    get_grant_signer,
    get_launcher_client,
    get_policy_client,
    get_settings,
    get_verified_identity,
    require_approver_key,
)
from gateway.api.schemas import (
    ApprovalCreateRequest,
    ApprovalCreateResponse,
    ToolInvocationRequest,
    ToolInvocationResponse,
)
from gateway.approvals.store import ApprovalStore
from gateway.audit.log import (
    ApprovalAuditEvent,
    AuditEvent,
    emit_approval_audit_event,
    emit_audit_event,
)
from gateway.config import Settings
from gateway.execution.client import LauncherClient, LauncherError
from gateway.execution.protocol import ActionEnvelope, ApprovalBinding, ToolIdentity
from gateway.execution.signing import ExecutionGrantSigner
from gateway.hashing import sha256_hex
from gateway.identity.models import AgentIdentity
from gateway.policy.client import PolicyClient, PolicyError
from gateway.registry.tools import UnknownToolError, resolve_tool

router = APIRouter()
_log = logging.getLogger("gateway.api")


def _error_body(code: str, message: str, request_id: str) -> dict[str, Any]:
    return {"error": code, "message": message, "request_id": request_id}


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/v1/tool-invocations", response_model=ToolInvocationResponse)
async def invoke_tool(
    payload: ToolInvocationRequest,
    identity: AgentIdentity = Depends(get_verified_identity),
    policy_client: PolicyClient = Depends(get_policy_client),
    approval_store: ApprovalStore = Depends(get_approval_store),
    launcher_client: LauncherClient = Depends(get_launcher_client),
    grant_signer: ExecutionGrantSigner = Depends(get_grant_signer),
) -> ToolInvocationResponse:
    request_id = str(uuid4())
    correlation_id = payload.correlation_id or request_id
    now = datetime.now(tz=UTC)

    try:
        tool_spec = resolve_tool(payload.tool)
    except UnknownToolError as exc:
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=payload.tool,
                scope_decision="unknown",
                policy_decision="deny",
                policy_version=None,
                risk_level=None,
                approval_state="not_applicable",
                argument_hash=None,
                result_hash=None,
                outcome="denied",
                error_code="unknown_tool",
            )
        )
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, _error_body("unknown_tool", "no such tool", request_id)
        ) from exc

    try:
        validated_args = tool_spec.args_model.model_validate(payload.arguments)
    except ValidationError as exc:
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=tool_spec.name,
                scope_decision="unknown",
                policy_decision="deny",
                policy_version=None,
                risk_level=tool_spec.risk.value,
                approval_state="not_applicable",
                argument_hash=None,
                result_hash=None,
                outcome="denied",
                error_code="invalid_arguments",
            )
        )
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _error_body("invalid_arguments", "arguments failed schema validation", request_id),
        ) from exc

    argument_hash = sha256_hex(validated_args.model_dump(mode="json"))
    scope_decision: Literal["granted", "denied"] = (
        "granted" if tool_spec.required_scope in identity.scopes else "denied"
    )

    # --- Phase 1: non-consuming approval validation -------------------
    # Never mutates the approval store. Whatever OPA decides next, this
    # approval (if any) is still exactly as usable as it was before this
    # request started.
    approval_state: Literal["none", "valid", "invalid"]
    audit_approval_state: str
    if payload.approval_id is None:
        approval_state = "none"
        audit_approval_state = "not_supplied" if tool_spec.approval_required else "not_required"
    else:
        validation = approval_store.validate(
            payload.approval_id,
            tool_name=tool_spec.name,
            argument_hash=argument_hash,
            agent_id=identity.agent_id,
            delegated_user_id=identity.delegated_user.id,
        )
        if validation.ok:
            approval_state = "valid"
            audit_approval_state = "validated"
        else:
            approval_state = "invalid"
            audit_approval_state = f"invalid:{validation.outcome.value}"
            emit_approval_audit_event(
                ApprovalAuditEvent(
                    request_id=request_id,
                    correlation_id=correlation_id,
                    timestamp=now,
                    event="binding_failed",
                    tool_name=tool_spec.name,
                    agent_id=identity.agent_id,
                    delegated_user_id=identity.delegated_user.id,
                    granted_by=None,
                    argument_hash=argument_hash,
                    reason=validation.outcome.value,
                )
            )

    # --- Phase 2: ask OPA. OPA owns the tool -> scope/risk/approval ----
    # mapping entirely; the gateway sends only verified identity, the
    # requested tool name, and the approval state it just validated. It
    # never sends a pre-resolved required_scope or risk, so a compromised
    # or buggy gateway cannot weaken the decision by lying about either;
    # see policy/gateway/authz.rego and
    # tests/test_approvals.py::test_fake_policy_client_ignores_spoofed_scope_metadata.
    policy_input = {
        "agent_id": identity.agent_id,
        "delegated_user_id": identity.delegated_user.id,
        "scopes": list(identity.scopes),
        "tool": tool_spec.name,
        "approval_state": approval_state,
    }

    try:
        decision = await policy_client.evaluate(policy_input)
    except PolicyError as exc:
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=tool_spec.name,
                scope_decision=scope_decision,
                policy_decision="error",
                policy_version=None,
                risk_level=tool_spec.risk.value,
                approval_state=audit_approval_state,
                argument_hash=argument_hash,
                result_hash=None,
                outcome="error",
                error_code="policy_unavailable",
            )
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            _error_body(
                "policy_unavailable", "policy engine unavailable; request denied", request_id
            ),
        ) from exc

    # --- Phase 3: registry-policy mismatch cross-check -----------------
    # Two independent sources of truth (this file's registry, OPA's
    # `tools` data) must agree on what this tool costs. Any disagreement
    # is treated as a fail-closed configuration error, regardless of what
    # `decision.decision` says: an "allow" from a policy whose metadata
    # doesn't match the registry is never trusted.
    if (
        decision.required_scope != tool_spec.required_scope
        or decision.risk != tool_spec.risk.value
        or decision.approval_required != tool_spec.approval_required
    ):
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=tool_spec.name,
                scope_decision=scope_decision,
                policy_decision="error",
                policy_version=decision.policy_version,
                risk_level=tool_spec.risk.value,
                approval_state=audit_approval_state,
                argument_hash=argument_hash,
                result_hash=None,
                outcome="error",
                error_code="policy_registry_mismatch",
            )
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            _error_body(
                "policy_registry_mismatch",
                "policy metadata disagreed with the tool registry; request denied",
                request_id,
            ),
        )

    if decision.decision == "deny":
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=tool_spec.name,
                scope_decision=scope_decision,
                policy_decision="deny",
                policy_version=decision.policy_version,
                risk_level=tool_spec.risk.value,
                approval_state=audit_approval_state,
                argument_hash=argument_hash,
                result_hash=None,
                outcome="denied",
                error_code=None,
            )
        )
        return ToolInvocationResponse(
            request_id=request_id,
            correlation_id=correlation_id,
            decision="deny",
            tool=tool_spec.name,
            risk_level=tool_spec.risk.value,
            policy_version=decision.policy_version,
            result=None,
            message="denied by policy",
        )

    if decision.decision == "approval-required":
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=tool_spec.name,
                scope_decision=scope_decision,
                policy_decision="approval-required",
                policy_version=decision.policy_version,
                risk_level=tool_spec.risk.value,
                approval_state=audit_approval_state,
                argument_hash=argument_hash,
                result_hash=None,
                outcome="approval_required",
                error_code=None,
            )
        )
        return ToolInvocationResponse(
            request_id=request_id,
            correlation_id=correlation_id,
            decision="approval-required",
            tool=tool_spec.name,
            risk_level=tool_spec.risk.value,
            policy_version=decision.policy_version,
            result=None,
            message="approval required before execution",
        )

    # decision.decision == "allow"
    if decision.approval_required:
        # Reachable only when approval_state was "valid", which requires
        # payload.approval_id to have been set. Guard it anyway: a policy
        # that somehow allowed an approval-gated tool without a validated
        # approval is an inconsistency, not a license to execute.
        if payload.approval_id is None:
            emit_audit_event(
                AuditEvent(
                    request_id=request_id,
                    correlation_id=correlation_id,
                    timestamp=now,
                    agent_id=identity.agent_id,
                    delegated_user_id=identity.delegated_user.id,
                    tool_name=tool_spec.name,
                    scope_decision=scope_decision,
                    policy_decision="error",
                    policy_version=decision.policy_version,
                    risk_level=tool_spec.risk.value,
                    approval_state=audit_approval_state,
                    argument_hash=argument_hash,
                    result_hash=None,
                    outcome="error",
                    error_code="policy_inconsistent",
                )
            )
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                _error_body(
                    "policy_inconsistent",
                    "policy allowed an approval-gated tool without a validated approval",
                    request_id,
                ),
            )

        # --- Phase 4: atomic final consume, immediately before execution
        consume_result = approval_store.consume(
            payload.approval_id,
            tool_name=tool_spec.name,
            argument_hash=argument_hash,
            agent_id=identity.agent_id,
            delegated_user_id=identity.delegated_user.id,
        )
        if not consume_result.ok:
            emit_approval_audit_event(
                ApprovalAuditEvent(
                    request_id=request_id,
                    correlation_id=correlation_id,
                    timestamp=now,
                    event="binding_failed",
                    tool_name=tool_spec.name,
                    agent_id=identity.agent_id,
                    delegated_user_id=identity.delegated_user.id,
                    granted_by=None,
                    argument_hash=argument_hash,
                    reason=consume_result.outcome.value,
                )
            )
            emit_audit_event(
                AuditEvent(
                    request_id=request_id,
                    correlation_id=correlation_id,
                    timestamp=now,
                    agent_id=identity.agent_id,
                    delegated_user_id=identity.delegated_user.id,
                    tool_name=tool_spec.name,
                    scope_decision=scope_decision,
                    policy_decision="allow",
                    policy_version=decision.policy_version,
                    risk_level=tool_spec.risk.value,
                    approval_state=f"consume_failed:{consume_result.outcome.value}",
                    argument_hash=argument_hash,
                    result_hash=None,
                    outcome="denied",
                    error_code="approval_consume_failed",
                )
            )
            return ToolInvocationResponse(
                request_id=request_id,
                correlation_id=correlation_id,
                decision="deny",
                tool=tool_spec.name,
                risk_level=tool_spec.risk.value,
                policy_version=decision.policy_version,
                result=None,
                message="approval could not be finalized immediately before execution",
            )

        emit_approval_audit_event(
            ApprovalAuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                event="consumed",
                tool_name=tool_spec.name,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                granted_by=None,
                argument_hash=argument_hash,
            )
        )
        audit_approval_state = "consumed"

    approval_binding = ApprovalBinding(
        required=decision.approval_required,
        state="consumed" if decision.approval_required else "not_required",
        digest=(
            sha256_hex({"approval_capability": payload.approval_id})
            if decision.approval_required
            else None
        ),
    )
    invocation_id = str(uuid4())
    action = ActionEnvelope(
        invocation_id=invocation_id,
        request_id=request_id,
        correlation_id=correlation_id,
        agent_id=identity.agent_id,
        delegated_user_id=identity.delegated_user.id,
        tool=ToolIdentity(name=tool_spec.name, artifact_digest=tool_spec.artifact_digest),
        arguments=validated_args.model_dump(mode="json"),
        argument_digest=argument_hash,
        approval=approval_binding,
        policy_version=decision.policy_version,
        risk=tool_spec.risk.value,
        created_at=datetime.now(tz=UTC),
    )
    grant = grant_signer.issue(action)

    try:
        worker_result = await launcher_client.execute(grant)
        if (
            worker_result.invocation_id != invocation_id
            or worker_result.grant_nonce != grant.nonce
            or worker_result.tool != action.tool
        ):
            raise LauncherError("result_binding_mismatch")
    except LauncherError as exc:
        _log.warning("isolated execution failed request_id=%s tool=%s", request_id, tool_spec.name)
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=tool_spec.name,
                scope_decision=scope_decision,
                policy_decision="allow",
                policy_version=decision.policy_version,
                risk_level=tool_spec.risk.value,
                approval_state=audit_approval_state,
                argument_hash=argument_hash,
                result_hash=sha256_hex({"error": "tool_execution_failed"}),
                outcome="error",
                error_code="tool_execution_failed",
            )
        )
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            _error_body("tool_execution_failed", "the tool failed to execute", request_id),
        ) from exc

    if worker_result.status == "failed" or worker_result.result is None:
        emit_audit_event(
            AuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                agent_id=identity.agent_id,
                delegated_user_id=identity.delegated_user.id,
                tool_name=tool_spec.name,
                scope_decision=scope_decision,
                policy_decision="allow",
                policy_version=decision.policy_version,
                risk_level=tool_spec.risk.value,
                approval_state=audit_approval_state,
                argument_hash=argument_hash,
                result_hash=worker_result.result_digest,
                outcome="error",
                error_code="tool_execution_failed",
            )
        )
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            _error_body("tool_execution_failed", "the tool failed to execute", request_id),
        )

    result = worker_result.result
    result_hash = worker_result.result_digest
    emit_audit_event(
        AuditEvent(
            request_id=request_id,
            correlation_id=correlation_id,
            timestamp=now,
            agent_id=identity.agent_id,
            delegated_user_id=identity.delegated_user.id,
            tool_name=tool_spec.name,
            scope_decision=scope_decision,
            policy_decision="allow",
            policy_version=decision.policy_version,
            risk_level=tool_spec.risk.value,
            approval_state=audit_approval_state,
            argument_hash=argument_hash,
            result_hash=result_hash,
            outcome="executed",
            error_code=None,
        )
    )
    return ToolInvocationResponse(
        request_id=request_id,
        correlation_id=correlation_id,
        decision="allow",
        tool=tool_spec.name,
        risk_level=tool_spec.risk.value,
        policy_version=decision.policy_version,
        result=result,
        message=None,
    )


@router.post(
    "/v1/approvals",
    response_model=ApprovalCreateResponse,
    dependencies=[Depends(require_approver_key)],
)
async def create_approval(
    payload: ApprovalCreateRequest,
    approval_store: ApprovalStore = Depends(get_approval_store),
    settings: Settings = Depends(get_settings),
) -> ApprovalCreateResponse:
    request_id = str(uuid4())
    correlation_id = request_id
    now = datetime.now(tz=UTC)

    try:
        tool_spec = resolve_tool(payload.tool)
    except UnknownToolError as exc:
        emit_approval_audit_event(
            ApprovalAuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                event="rejected",
                tool_name=payload.tool,
                agent_id=payload.agent_id,
                delegated_user_id=payload.delegated_user_id,
                granted_by=settings.approver_identity,
                argument_hash=None,
                reason="unknown_tool",
            )
        )
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, _error_body("unknown_tool", "no such tool", request_id)
        ) from exc

    try:
        validated_args = tool_spec.args_model.model_validate(payload.arguments)
    except ValidationError as exc:
        emit_approval_audit_event(
            ApprovalAuditEvent(
                request_id=request_id,
                correlation_id=correlation_id,
                timestamp=now,
                event="rejected",
                tool_name=tool_spec.name,
                agent_id=payload.agent_id,
                delegated_user_id=payload.delegated_user_id,
                granted_by=settings.approver_identity,
                argument_hash=None,
                reason="invalid_arguments",
            )
        )
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _error_body("invalid_arguments", "arguments failed schema validation", request_id),
        ) from exc

    argument_hash = sha256_hex(validated_args.model_dump(mode="json"))
    record = approval_store.create(
        tool_name=tool_spec.name,
        argument_hash=argument_hash,
        agent_id=payload.agent_id,
        delegated_user_id=payload.delegated_user_id,
        granted_by=settings.approver_identity,
        ttl_seconds=payload.ttl_seconds,
    )
    emit_approval_audit_event(
        ApprovalAuditEvent(
            request_id=request_id,
            correlation_id=correlation_id,
            timestamp=now,
            event="created",
            tool_name=tool_spec.name,
            agent_id=payload.agent_id,
            delegated_user_id=payload.delegated_user_id,
            granted_by=settings.approver_identity,
            argument_hash=argument_hash,
        )
    )
    return ApprovalCreateResponse(
        approval_id=record.approval_id, tool=tool_spec.name, expires_at=record.expires_at
    )
