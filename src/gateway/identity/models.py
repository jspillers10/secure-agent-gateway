"""Typed representation of a verified delegated identity.

An instance of AgentIdentity only ever exists after full cryptographic and
claim verification (see tokens.py). Nothing downstream should trust a
dict/JWT payload directly; only this model.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DelegatedUser(BaseModel):
    """The human on whose behalf the agent is acting."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=256)
    display_name: str | None = Field(default=None, max_length=256)


class AgentIdentity(BaseModel):
    """A verified delegated-identity principal: an agent acting for a user."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(min_length=1, max_length=256)
    delegated_user: DelegatedUser
    scopes: tuple[str, ...]
    token_id: str = Field(min_length=1, max_length=256)
    issued_at: datetime
    expires_at: datetime

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes
