"""HTTP client for Open Policy Agent.

Queries `data.gateway.authz.result`, a single, narrow rule the Rego
policy in policy/gateway/authz.rego defines specifically to be queried,
returning exactly `{"decision": ..., "policy_version": ..., "required_scope":
..., "risk": ..., "approval_required": ...}` and nothing else (the
package has several other helper rules that exist only to make the Rego
readable; querying the bare package would return those too, which the
closed PolicyDecision schema would then reject as unexpected fields).
Any transport error, non-2xx response, or response that doesn't validate
against that closed schema (missing field, unknown field, empty version,
unknown decision string) is raised as PolicyError so the caller fails
closed.
"""

from __future__ import annotations

from collections.abc import Mapping

import httpx
from pydantic import ValidationError

from gateway.policy.client import PolicyDecision, PolicyError


class OPAHttpPolicyClient:
    def __init__(self, base_url: str, *, timeout: float = 2.0) -> None:
        self._endpoint = f"{base_url.rstrip('/')}/v1/data/gateway/authz/result"
        self._timeout = timeout

    async def evaluate(self, policy_input: Mapping[str, object]) -> PolicyDecision:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(self._endpoint, json={"input": dict(policy_input)})
            response.raise_for_status()
            body = response.json()
            result = body["result"]
            return PolicyDecision.model_validate(result)
        except (httpx.HTTPError, KeyError, ValueError, ValidationError, TypeError) as exc:
            raise PolicyError(f"policy evaluation failed: {exc}") from exc
