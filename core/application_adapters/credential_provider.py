"""Credential provider boundary for adapter identity proofs (test-only vs disabled production)."""

from __future__ import annotations

import hmac
import hashlib
import secrets
from typing import Protocol

from entitlement_router.privacy import validate_opaque_id


class CredentialProviderUnavailableError(PermissionError):
    """Raised when no active or authorized credential provider is configured."""


class AdapterCredentialProvider(Protocol):
    """Abstract provider for adapter HMAC verification keys (never embeds keys in configs)."""

    @property
    def is_enabled(self) -> bool: ...

    @property
    def is_production_ready(self) -> bool: ...

    def get_key(self, key_id: str, key_version: int) -> bytes | None: ...

    def sign_digest(self, key_id: str, key_version: int, canonical_message: bytes) -> str: ...


class DisabledProductionCredentialProvider:
    """Explicitly disabled production provider until B4-A1/B4-B provisioning boundary is qualified."""

    @property
    def is_enabled(self) -> bool:
        return False

    @property
    def is_production_ready(self) -> bool:
        return False

    def get_key(self, key_id: str, key_version: int) -> bytes | None:
        _ = (key_id, key_version)
        return None

    def sign_digest(self, key_id: str, key_version: int, canonical_message: bytes) -> str:
        _ = (key_id, key_version, canonical_message)
        raise CredentialProviderUnavailableError(
            "PRODUCTION_CREDENTIAL_PROVIDER_DISABLED: Production adapter key provisioning is "
            "disabled until Windows Service qualification (B4-A1/B4-B) completes."
        )

    def __repr__(self) -> str:
        return "DisabledProductionCredentialProvider(is_enabled=False, is_production_ready=False)"


class EphemeralTestCredentialProvider:
    """In-memory ephemeral test-only credential provider (NEVER reads env/config/disk)."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, int], bytes] = {}
        self._adapter_active_key: dict[str, tuple[str, int]] = {}

    @property
    def is_enabled(self) -> bool:
        return True

    @property
    def is_production_ready(self) -> bool:
        return False

    def provision_ephemeral_adapter_key(
        self,
        *,
        adapter_id: str,
        key_id: str,
        key_version: int = 1,
        secret_bytes: bytes | None = None,
    ) -> tuple[str, int]:
        validate_opaque_id(adapter_id, field_name="adapter_id")
        validate_opaque_id(key_id, field_name="key_id")
        if key_version < 1:
            raise ValueError("key_version must be >= 1.")
        raw = secret_bytes if secret_bytes is not None else secrets.token_bytes(32)
        if len(raw) < 16:
            raise ValueError("Ephemeral HMAC key must be at least 16 bytes.")
        self._keys[(key_id, int(key_version))] = bytes(raw)
        self._adapter_active_key[adapter_id] = (key_id, int(key_version))
        return key_id, int(key_version)

    def active_key_for_adapter(self, adapter_id: str) -> tuple[str, int] | None:
        return self._adapter_active_key.get(adapter_id)

    def get_key(self, key_id: str, key_version: int) -> bytes | None:
        return self._keys.get((key_id, int(key_version)))

    def sign_digest(self, key_id: str, key_version: int, canonical_message: bytes) -> str:
        key = self.get_key(key_id, key_version)
        if key is None:
            raise CredentialProviderUnavailableError(
                f"ADAPTER_KEY_NOT_FOUND: key_id='{key_id}' v{key_version} is not provisioned."
            )
        return hmac.new(key, canonical_message, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        return (
            f"EphemeralTestCredentialProvider(is_enabled=True, is_production_ready=False, "
            f"key_count={len(self._keys)})"
        )
