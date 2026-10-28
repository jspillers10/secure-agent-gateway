"""In-memory approval record store.

Approval records are single-use and bound to (tool, argument hash, agent
identity, delegated-user identity, expiration). Two operations share the
same binding checks but differ in one critical way:

- `validate()` performs every check *without* marking the record used. It
  is used before asking OPA for a decision, so a policy denial, an
  approval-required response, or a policy-engine outage never burns a
  legitimate, still-valid approval.
- `consume()` performs the same checks and, only if every one of them
  passes, atomically marks the record used in the same critical section.
  It is called exactly once, immediately before tool execution, only
  after OPA has already returned "allow". Because the check and the
  mark-used are atomic under a single lock, two concurrent requests racing
  to consume the same approval can never both succeed: the loser sees
  `already_used`, same as a genuine replay.

This two-phase design (validate, decide, then consume-immediately-before-
execution) is what prevents "premature consumption": in the older
single-phase design, an approval was consumed at policy-input-preparation
time, so a subsequent policy denial or outage would strand it as spent
even though nothing was ever executed. See tests/test_approvals.py for the
regression tests (approval survives a policy outage, approval survives a
policy denial, only one of two competing consumers wins, an approval that
expires between validate() and consume() fails closed).

Known limitation (documented in docs/threat-model.md and the roadmap):
this store is process-local, in-memory, and lost on restart. A production
deployment must back it with a persistent store that offers the same
atomic check-and-set guarantee (e.g. a unique constraint in a relational
database, or Redis with a Lua-scripted compare-and-set).
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum


class ApprovalOutcome(StrEnum):
    GRANTED = "granted"
    NOT_FOUND = "not_found"
    ALREADY_USED = "already_used"
    EXPIRED = "expired"
    TOOL_MISMATCH = "tool_mismatch"
    ARGUMENT_MISMATCH = "argument_mismatch"
    IDENTITY_MISMATCH = "identity_mismatch"


@dataclass(frozen=True, slots=True)
class ApprovalCheckResult:
    outcome: ApprovalOutcome

    @property
    def ok(self) -> bool:
        return self.outcome is ApprovalOutcome.GRANTED


@dataclass(slots=True)
class ApprovalRecord:
    approval_id: str
    tool_name: str
    argument_hash: str
    agent_id: str
    delegated_user_id: str
    granted_by: str
    created_at: datetime
    expires_at: datetime
    used: bool = False
    used_at: datetime | None = None


@dataclass
class ApprovalStore:
    _records: dict[str, ApprovalRecord] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def create(
        self,
        *,
        tool_name: str,
        argument_hash: str,
        agent_id: str,
        delegated_user_id: str,
        granted_by: str,
        ttl_seconds: int,
    ) -> ApprovalRecord:
        now = datetime.now(tz=UTC)
        record = ApprovalRecord(
            approval_id=secrets.token_urlsafe(24),
            tool_name=tool_name,
            argument_hash=argument_hash,
            agent_id=agent_id,
            delegated_user_id=delegated_user_id,
            granted_by=granted_by,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._records[record.approval_id] = record
        return record

    @staticmethod
    def _check(
        record: ApprovalRecord | None,
        *,
        tool_name: str,
        argument_hash: str,
        agent_id: str,
        delegated_user_id: str,
        now: datetime,
    ) -> ApprovalOutcome:
        if record is None:
            return ApprovalOutcome.NOT_FOUND
        if record.used:
            return ApprovalOutcome.ALREADY_USED
        if now >= record.expires_at:
            return ApprovalOutcome.EXPIRED
        if record.tool_name != tool_name:
            return ApprovalOutcome.TOOL_MISMATCH
        if record.agent_id != agent_id or record.delegated_user_id != delegated_user_id:
            return ApprovalOutcome.IDENTITY_MISMATCH
        if record.argument_hash != argument_hash:
            return ApprovalOutcome.ARGUMENT_MISMATCH
        return ApprovalOutcome.GRANTED

    def validate(
        self,
        approval_id: str,
        *,
        tool_name: str,
        argument_hash: str,
        agent_id: str,
        delegated_user_id: str,
    ) -> ApprovalCheckResult:
        """Check binding without consuming. Never mutates the record."""
        now = datetime.now(tz=UTC)
        with self._lock:
            record = self._records.get(approval_id)
            outcome = self._check(
                record,
                tool_name=tool_name,
                argument_hash=argument_hash,
                agent_id=agent_id,
                delegated_user_id=delegated_user_id,
                now=now,
            )
        return ApprovalCheckResult(outcome)

    def consume(
        self,
        approval_id: str,
        *,
        tool_name: str,
        argument_hash: str,
        agent_id: str,
        delegated_user_id: str,
    ) -> ApprovalCheckResult:
        """Atomically re-check binding and mark used in one critical
        section. Call this exactly once, immediately before executing the
        tool the approval was granted for; never before a policy
        decision is known."""
        now = datetime.now(tz=UTC)
        with self._lock:
            record = self._records.get(approval_id)
            outcome = self._check(
                record,
                tool_name=tool_name,
                argument_hash=argument_hash,
                agent_id=agent_id,
                delegated_user_id=delegated_user_id,
                now=now,
            )
            if outcome is ApprovalOutcome.GRANTED and record is not None:
                record.used = True
                record.used_at = now
        return ApprovalCheckResult(outcome)
