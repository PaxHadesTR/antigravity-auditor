"""Scoped, generation-aware catalog visibility cache with strict cross-principal/account isolation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time
from typing import Any

from mcp_gateway.authenticated_context import AuthenticatedCallerContext
from mcp_gateway.contracts import ClientCompatibilityProfile


def build_scoped_cache_key(
    *,
    caller: AuthenticatedCallerContext,
    profile: ClientCompatibilityProfile,
    catalog_version: str,
    manifest_sha256: str,
    authz_policy_state: str = "",
) -> str:
    """Compute an isolated, secret-free cache key across all security and compatibility dimensions."""
    app_dim = caller.application_id if caller.verified_application_identity else "UNKNOWN"
    acct_dim = caller.account_context_id or "NONE"
    allowed_users_dim = ",".join(sorted(caller.allowed_user_profile_ids))
    allowed_accts_dim = ",".join(sorted(caller.allowed_account_context_ids))
    scope_hash = hashlib.sha256("|".join(sorted(caller.authorization_scopes)).encode("utf-8")).hexdigest()[:16]
    raw = "|".join(
        [
            caller.principal_id,
            caller.authentication_method.value,
            app_dim,
            acct_dim,
            allowed_users_dim,
            allowed_accts_dim,
            scope_hash,
            f"pgen={caller.policy_generation}",
            f"egen={caller.entitlement_generation}",
            f"authz={authz_policy_state}",
            f"cat={catalog_version}:{manifest_sha256[:16]}",
            f"compat={profile.compatibility_fingerprint[:16]}",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class _CacheEntry:
    cache_key: str
    principal_id: str
    policy_generation: int
    entitlement_generation: int
    manifest_sha256: str
    created_monotonic: float
    tools_payload: list[dict[str, Any]]
    metadata: dict[str, Any]


class CatalogCache:
    """Isolated cache for filtered `tools/list` views (never used to authorize `tools/call`)."""

    def __init__(self, *, ttl_seconds: float = 30.0, max_entries: int = 256) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: dict[str, _CacheEntry] = {}

    def get(
        self,
        *,
        caller: AuthenticatedCallerContext,
        profile: ClientCompatibilityProfile,
        catalog_version: str,
        manifest_sha256: str,
        authz_policy_state: str = "",
        now_monotonic: float | None = None,
    ) -> _CacheEntry | None:
        key = build_scoped_cache_key(
            caller=caller,
            profile=profile,
            catalog_version=catalog_version,
            manifest_sha256=manifest_sha256,
            authz_policy_state=authz_policy_state,
        )
        entry = self._entries.get(key)
        if entry is None:
            return None
        now = time.monotonic() if now_monotonic is None else now_monotonic
        if (now - entry.created_monotonic) > self.ttl_seconds:
            self._entries.pop(key, None)
            return None
        if (
            entry.principal_id != caller.principal_id
            or entry.policy_generation != caller.policy_generation
            or entry.entitlement_generation != caller.entitlement_generation
            or entry.manifest_sha256 != manifest_sha256
        ):
            self._entries.pop(key, None)
            return None
        return entry

    def put(
        self,
        *,
        caller: AuthenticatedCallerContext,
        profile: ClientCompatibilityProfile,
        catalog_version: str,
        manifest_sha256: str,
        tools_payload: list[dict[str, Any]],
        authz_policy_state: str = "",
        metadata: dict[str, Any] | None = None,
        now_monotonic: float | None = None,
    ) -> str:
        key = build_scoped_cache_key(
            caller=caller,
            profile=profile,
            catalog_version=catalog_version,
            manifest_sha256=manifest_sha256,
            authz_policy_state=authz_policy_state,
        )
        if len(self._entries) >= self.max_entries:
            oldest_key = next(iter(self._entries))
            self._entries.pop(oldest_key, None)
        now = time.monotonic() if now_monotonic is None else now_monotonic
        self._entries[key] = _CacheEntry(
            cache_key=key,
            principal_id=caller.principal_id,
            policy_generation=caller.policy_generation,
            entitlement_generation=caller.entitlement_generation,
            manifest_sha256=manifest_sha256,
            created_monotonic=now,
            tools_payload=tools_payload,
            metadata=dict(metadata or {}),
        )
        return key

    def invalidate_principal(self, principal_id: str) -> int:
        to_del = [k for k, v in self._entries.items() if v.principal_id == principal_id]
        for k in to_del:
            self._entries.pop(k, None)
        return len(to_del)

    def invalidate_all(self) -> None:
        self._entries.clear()

    def size(self) -> int:
        return len(self._entries)
