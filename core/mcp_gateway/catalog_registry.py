"""Deterministic canonical tool catalog registry for NEXT-22C."""

from __future__ import annotations

from typing import Any

from mcp_gateway.contracts import (
    CATALOG_VERSION,
    TOOL_GROUP_ORDER,
    CanonicalToolManifest,
    canonical_sha256,
)
from mcp_gateway.tool_manifest import build_default_canonical_manifests


class CanonicalCatalogRegistry:
    """Single canonical registry guaranteeing unique, deterministically ordered tools and manifest hashes."""

    def __init__(
        self,
        tools: list[CanonicalToolManifest] | None = None,
        *,
        catalog_version: str = CATALOG_VERSION,
    ) -> None:
        self.catalog_version = catalog_version
        self._tools: dict[str, CanonicalToolManifest] = {}
        self._aliases: dict[str, str] = {}
        for item in (build_default_canonical_manifests() if tools is None else tools):
            self.register(item)

    def register(self, manifest: CanonicalToolManifest) -> None:
        if manifest.tool_name in self._tools:
            raise ValueError(f"Duplicate canonical tool registration: {manifest.tool_name}")
        for existing in self._tools.values():
            if existing.tool_id == manifest.tool_id:
                raise ValueError(f"Duplicate canonical tool_id: {manifest.tool_id}")
        self._tools[manifest.tool_name] = manifest
        for alias in manifest.compatibility_aliases:
            if alias in self._aliases or alias in self._tools:
                raise ValueError(f"Tool compatibility alias collision: {alias}")
            self._aliases[alias] = manifest.tool_name

    def get(self, name: str) -> CanonicalToolManifest | None:
        canonical_name = self._aliases.get(name, name)
        return self._tools.get(canonical_name)

    def list_ordered(self) -> list[CanonicalToolManifest]:
        return sorted(
            self._tools.values(),
            key=lambda m: (TOOL_GROUP_ORDER.get(m.tool_group, 999), m.tool_name),
        )

    @property
    def manifest_sha256(self) -> str:
        return canonical_sha256(
            {
                "catalog_version": self.catalog_version,
                "tools": [
                    {
                        "tool_id": m.tool_id,
                        "tool_name": m.tool_name,
                        "schema_version": m.schema_version,
                        "schema_sha256": m.schema_sha256,
                        "tool_group": m.tool_group.value,
                        "required_authorization_scopes": list(m.required_authorization_scopes),
                        "execution_mutating": m.execution_mutating,
                    }
                    for m in self.list_ordered()
                ],
            }
        )

    def export_manifest(self) -> dict[str, Any]:
        return {
            "catalog_version": self.catalog_version,
            "manifest_sha256": self.manifest_sha256,
            "tools": [m.to_dict() for m in self.list_ordered()],
        }
