"""File-backed, single-use approvals for the MCP proxy.

The proxy and `sag approve` run as separate processes, so approval state
lives on disk under `<state_dir>/approvals/`:

    pending/<id>.json   requested by the proxy, waiting for a human
    granted/<id>.json   approved, waiting to be consumed by one retry
    used/<id>.json      consumed; kept for inspection
    claims/             one marker per state transition (see below)

Like secure_agent_gateway.approvals.store, an approval is bound to the exact tool and
the canonical hash of its arguments (secure_agent_gateway.hashing.sha256_hex), plus the
upstream server it was requested through. A retry with different
arguments, a different tool, or through a different server does not
match, and a granted approval is consumed by exactly one call.

Single use holds across processes because every transition (approve,
consume) is first claimed by exclusively creating a marker file
(O_CREAT | O_EXCL, CREATE_NEW on Windows). Exactly one creator succeeds;
everyone else gets FileExistsError and moves on. `os.rename` is not used
as the mutex because on Windows several concurrent renames of the same
file can all report success. See test_concurrent_consumers_only_one_wins.

The approval id is a handle a human types, not a bearer credential: a
retry never presents it, and granting requires write access to the state
directory. Keep that directory out of reach of the agent's own tools.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_ID_PATTERN = re.compile(r"^[0-9a-f]{10}$")

# How long an unanswered request stays approvable.
PENDING_TTL_SECONDS = 3600


class ApprovalError(Exception):
    pass


@dataclass(slots=True)
class ApprovalRecord:
    approval_id: str
    server: str
    server_id: str
    tool_name: str
    argument_hash: str
    created_at: str
    expires_at: str
    grant_ttl_seconds: int
    # Redacted, truncated argument preview for the human reviewer. Present
    # only while pending; dropped from the record once granted.
    preview: Any = None
    approved_at: str | None = None
    approved_by: str | None = None
    used_at: str | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ApprovalRecord:
        return cls(**data)

    def binds(self, *, server_id: str, tool_name: str, argument_hash: str) -> bool:
        return (
            self.server_id == server_id
            and self.tool_name == tool_name
            and self.argument_hash == argument_hash
        )


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _iso(value: datetime) -> str:
    return value.isoformat()


class FileApprovalStore:
    def __init__(self, root: Path, *, clock: Callable[[], datetime] = _utcnow) -> None:
        self.root = Path(root)
        self._clock = clock
        self.pending_dir = self.root / "pending"
        self.granted_dir = self.root / "granted"
        self.used_dir = self.root / "used"
        self.claims_dir = self.root / "claims"
        for directory in (self.pending_dir, self.granted_dir, self.used_dir, self.claims_dir):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    @staticmethod
    def _read(path: Path) -> ApprovalRecord | None:
        try:
            return ApprovalRecord.from_json(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def _write_atomic(path: Path, record: ApprovalRecord) -> None:
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(asdict(record), fh, sort_keys=True)
        os.replace(tmp, path)

    def _expired(self, record: ApprovalRecord) -> bool:
        return self._clock() >= datetime.fromisoformat(record.expires_at)

    def _records(self, directory: Path) -> list[tuple[Path, ApprovalRecord]]:
        out = []
        for path in sorted(directory.glob("*.json")):
            record = self._read(path)
            if record is not None:
                out.append((path, record))
        return out

    def request(
        self,
        *,
        server: str,
        server_id: str,
        tool_name: str,
        argument_hash: str,
        grant_ttl_seconds: int,
        preview: Any,
    ) -> tuple[ApprovalRecord, bool]:
        """Return the open request for this exact call, creating one if
        needed. The bool is True when a new request was created, so a model
        retrying before a human answers does not pile up duplicates."""
        for _path, record in self._records(self.pending_dir):
            if not self._expired(record) and record.binds(
                server_id=server_id, tool_name=tool_name, argument_hash=argument_hash
            ):
                return record, False
        now = self._clock()
        while True:
            approval_id = secrets.token_hex(5)
            path = self.pending_dir / f"{approval_id}.json"
            if not path.exists():
                break
        record = ApprovalRecord(
            approval_id=approval_id,
            server=server,
            server_id=server_id,
            tool_name=tool_name,
            argument_hash=argument_hash,
            created_at=_iso(now),
            expires_at=_iso(now + timedelta(seconds=PENDING_TTL_SECONDS)),
            grant_ttl_seconds=grant_ttl_seconds,
            preview=preview,
        )
        self._write_atomic(path, record)
        return record, True

    def pending(self) -> list[ApprovalRecord]:
        return [r for _p, r in self._records(self.pending_dir) if not self._expired(r)]

    def approve(self, approval_id: str, *, approved_by: str) -> ApprovalRecord:
        if not _ID_PATTERN.fullmatch(approval_id):
            raise ApprovalError(f"malformed approval id {approval_id!r}")
        source = self.pending_dir / f"{approval_id}.json"
        record = self._read(source)
        if record is None:
            raise ApprovalError(f"no pending approval {approval_id}")
        if self._expired(record):
            raise ApprovalError(f"approval request {approval_id} has expired")
        if not self._claim(f"approve-{approval_id}"):
            raise ApprovalError(f"approval {approval_id} was already handled")
        now = self._clock()
        record.preview = None
        record.approved_at = _iso(now)
        record.approved_by = approved_by
        record.expires_at = _iso(now + timedelta(seconds=record.grant_ttl_seconds))
        self._write_atomic(self.granted_dir / f"{approval_id}.json", record)
        with contextlib.suppress(OSError):
            source.unlink()
        return record

    def _claim(self, marker: str) -> bool:
        """Exclusively create claims/<marker>; True only for the one winner."""
        try:
            fd = os.open(self.claims_dir / marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        os.close(fd)
        return True

    def try_consume(
        self, *, server_id: str, tool_name: str, argument_hash: str
    ) -> ApprovalRecord | None:
        """Consume one unexpired grant bound to this exact call, or return
        None. Never consumes a grant that does not match."""
        for path, record in self._records(self.granted_dir):
            if self._expired(record) or not record.binds(
                server_id=server_id, tool_name=tool_name, argument_hash=argument_hash
            ):
                continue
            if not self._claim(f"consume-{record.approval_id}"):
                continue  # lost a race to another consumer
            record.used_at = _iso(self._clock())
            with contextlib.suppress(OSError):
                self._write_atomic(self.used_dir / path.name, record)
                path.unlink()
            return record
        return None
