"""Server-owned mapping from registered tools to pinned Worker runtime data."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from gateway.registry.tools import TOOL_REGISTRY


@dataclass(frozen=True, slots=True)
class LauncherToolSpec:
    tool_name: str
    artifact_digest: str
    image_reference: str
    entrypoint: tuple[str, ...]
    requires_egress: bool


def build_launcher_registry(worker_image_reference: str) -> Mapping[str, LauncherToolSpec]:
    specs = {
        name: LauncherToolSpec(
            tool_name=name,
            artifact_digest=tool.artifact_digest,
            image_reference=worker_image_reference,
            entrypoint=("python", "-m", "gateway.worker.main"),
            requires_egress=tool.requires_egress,
        )
        for name, tool in TOOL_REGISTRY.items()
    }
    return MappingProxyType(specs)
