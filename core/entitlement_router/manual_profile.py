"""Versioned manual entitlement profile parser and validator for NEXT-22B (Part 5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from entitlement_router.contracts import (
    strict_bool,
    AccountContextRecord,
    AccountScope,
    ApplicationInstanceRecord,
    AuthenticationMode,
    ConfidenceLevel,
    CostPolicy,
    EntitlementState,
    ModelEffortProfile,
    ModelEntitlementObservation,
    NormalizedEffort,
    QuotaObservation,
    QuotaState,
    SubscriptionSource,
    UserProfileRecord,
    UserRoutingPolicy,
    utc_now_iso,
)
from entitlement_router.privacy import assert_no_secret_intake, validate_opaque_id
from entitlement_router.registry import EntitlementRegistry

MANUAL_PROFILE_SCHEMA_VERSION = "1.0.0"


def load_manual_profile_dict(
    registry: EntitlementRegistry,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Validate and load a versioned manual entitlement profile into the registry.

    Strict invariants:
    - Rejects any secret, token, password, cookie, private key, or PII/email intake.
    - Marks all manual model entitlements and subscription declarations as USER_DECLARED
      (never ACCOUNT_ENUMERATED or SELECTABLE_VERIFIED).
    - Keeps multiple account contexts per application strictly isolated.
    """
    if not isinstance(payload, dict):
        raise ValueError("Manual profile payload must be a JSON object.")

    assert_no_secret_intake(payload)

    version = str(payload.get("schema_version") or "").strip()
    if version != MANUAL_PROFILE_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported manual profile schema_version '{version}'; expected '{MANUAL_PROFILE_SCHEMA_VERSION}'."
        )

    user_id = validate_opaque_id(str(payload.get("user_profile_id") or ""), field_name="user_profile_id")
    registry.register_user(
        UserProfileRecord(
            user_profile_id=user_id,
            label=str(payload["label"]) if payload.get("label") else None,
        )
    )

    observed_at = str(payload.get("declared_at") or utc_now_iso())
    raw_accounts = payload.get("accounts")
    if not isinstance(raw_accounts, list):
        raise ValueError("Manual profile requires an 'accounts' list.")

    loaded_accounts = 0
    loaded_models = 0
    loaded_quotas = 0

    for idx, acct in enumerate(raw_accounts, start=1):
        if not isinstance(acct, dict):
            raise ValueError(f"Account entry #{idx} must be an object.")

        acct_id = validate_opaque_id(
            str(acct.get("account_context_id") or ""),
            field_name=f"accounts[{idx}].account_context_id",
        )
        app_id = str(acct.get("application") or acct.get("application_id") or "").strip()
        if not app_id:
            raise ValueError(f"accounts[{idx}] requires 'application'.")
        provider = str(acct.get("provider") or "unknown").strip().lower()

        app_instance_id = validate_opaque_id(
            str(acct.get("application_instance_id") or f"app-{user_id}-{app_id}".replace("_", "-")),
            field_name=f"accounts[{idx}].application_instance_id",
        )
        if app_instance_id not in registry.applications:
            registry.register_application(
                ApplicationInstanceRecord(
                    application_instance_id=app_instance_id,
                    user_profile_id=user_id,
                    application_id=app_id,
                    installation_state=str(acct.get("installation_state") or "installed"),
                    packaging_mode=str(acct.get("packaging_mode") or "unknown"),
                    observed_at=observed_at,
                    evidence_ref=f"manual:{acct_id}",
                )
            )

        auth_mode = AuthenticationMode.parse(acct.get("authentication_mode"))
        sub_tier = str(acct["subscription_tier"]).strip() if acct.get("subscription_tier") else None
        sub_source = SubscriptionSource.USER_DECLARED if sub_tier else SubscriptionSource.UNKNOWN

        ws_scope = (
            validate_opaque_id(str(acct["workspace_scope"]), field_name="workspace_scope")
            if acct.get("workspace_scope")
            else None
        )
        ws_restrictions = acct.get("workspace_restrictions") or {}
        ws_allowed = tuple(str(m).strip() for m in (ws_restrictions.get("allowed_models") or ()) if str(m).strip())
        ws_blocked = tuple(str(m).strip() for m in (ws_restrictions.get("blocked_models") or ()) if str(m).strip())

        registry.register_account(
            AccountContextRecord(
                account_context_id=acct_id,
                user_profile_id=user_id,
                application_instance_id=app_instance_id,
                application_id=app_id,
                provider=provider,
                authentication_mode=auth_mode,
                account_scope=AccountScope.parse(acct.get("account_scope") or "USER_ACCOUNT"),
                workspace_scope=ws_scope,
                subscription_tier=sub_tier,
                subscription_source=sub_source,
                entitlement_state=EntitlementState.USER_DECLARED,
                workspace_allowed_models=ws_allowed,
                workspace_blocked_models=ws_blocked,
                observed_at=observed_at,
            )
        )
        loaded_accounts += 1

        # Known available models -> strictly USER_DECLARED (never ACCOUNT_ENUMERATED / SELECTABLE_VERIFIED)
        for m_idx, model_id in enumerate(acct.get("known_available_models") or (), start=1):
            mid = str(model_id).strip()
            if not mid:
                continue
            registry.record_entitlement(
                ModelEntitlementObservation(
                    observation_id=f"man-{acct_id}-{m_idx:04d}"[:95],
                    account_context_id=acct_id,
                    application_instance_id=app_instance_id,
                    application_id=app_id,
                    model_id=mid,
                    state=EntitlementState.USER_DECLARED,
                    provenance="USER_DECLARED",
                    confidence=ConfidenceLevel.UNVERIFIED,
                    observed_at=observed_at,
                    evidence_ref=f"manual-profile:{user_id}:{acct_id}",
                    notes="User-declared availability; not independently runtime-verified.",
                )
            )
            loaded_models += 1

        for d_idx, model_id in enumerate(acct.get("disallowed_models") or (), start=1):
            mid = str(model_id).strip()
            if not mid:
                continue
            registry.record_entitlement(
                ModelEntitlementObservation(
                    observation_id=f"man-blk-{acct_id}-{d_idx:04d}"[:95],
                    account_context_id=acct_id,
                    application_instance_id=app_instance_id,
                    application_id=app_id,
                    model_id=mid,
                    state=EntitlementState.POLICY_BLOCKED,
                    provenance="USER_DECLARED",
                    confidence=ConfidenceLevel.HIGH,
                    observed_at=observed_at,
                    evidence_ref=f"manual-profile:{user_id}:{acct_id}",
                    notes="Explicitly disallowed by user manual profile.",
                )
            )

        if acct.get("preferred_reasoning_effort"):
            pref_eff = NormalizedEffort.parse(str(acct["preferred_reasoning_effort"]))
            for model_id in acct.get("known_available_models") or ():
                mid = str(model_id).strip()
                if not mid:
                    continue
                if not registry.get_effort_profile(app_id, mid, acct_id):
                    registry.register_effort_profile(
                        ModelEffortProfile(
                            application_id=app_id,
                            application_model_id=mid,
                            account_context_id=acct_id,
                            supported_efforts=(pref_eff,),
                            raw_supported_efforts=(str(acct["preferred_reasoning_effort"]).strip(),),
                            default_effort=pref_eff,
                            raw_default_effort=str(acct["preferred_reasoning_effort"]).strip(),
                            selected_effort=pref_eff,
                            independently_configurable=False,
                            managed_by_orchestrator=False,
                            provenance="USER_DECLARED",
                            observed_at=observed_at,
                            evidence_ref=f"manual-profile:{user_id}:{acct_id}",
                        )
                    )

        for q_idx, q in enumerate(acct.get("quota_observations") or (), start=1):
            if not isinstance(q, dict):
                continue
            registry.record_quota(
                QuotaObservation(
                    observation_id=f"man-q-{acct_id}-{q_idx:04d}"[:95],
                    account_context_id=acct_id,
                    model_id=str(q["model_id"]).strip() if q.get("model_id") else None,
                    usage_category=str(q.get("usage_category") or "user_declared"),
                    quota_state=QuotaState.parse(q.get("quota_state")),
                    remaining_quantity=q.get("remaining_quantity"),
                    remaining_percentage=q.get("remaining_percentage"),
                    reset_at=q.get("reset_at"),
                    rate_limited=strict_bool(q, "rate_limited", False),
                    observed_at=str(q.get("observed_at") or observed_at),
                    expires_at=q.get("expires_at"),
                    source="USER_DECLARED",
                    evidence_ref=f"manual-profile:{user_id}:{acct_id}",
                )
            )
            loaded_quotas += 1

    # Optional user policy section
    if isinstance(payload.get("policy"), dict) or any(
        k in payload
        for k in (
            "preferred_models",
            "disallowed_models",
            "api_billing_permission",
            "max_permitted_cost_policy",
            "preferred_reasoning_effort",
        )
    ):
        pol_raw = dict(payload.get("policy") or {})
        pol_raw["user_profile_id"] = user_id
        pol_raw.setdefault("policy_id", f"pol-{user_id}")
        if "api_billing_permission" in payload and "api_billing_allowed" not in pol_raw:
            raw_perm = payload["api_billing_permission"]
            if not isinstance(raw_perm, bool):
                # bool("false") is True; only a real boolean may grant API billing.
                raise ValueError("api_billing_permission must be a boolean (true/false).")
            api_perm = raw_perm
            pol_raw["api_billing_allowed"] = api_perm
            pol_raw.setdefault("subscription_only", not api_perm)
        if "max_permitted_cost_policy" in payload and "max_cost_policy" not in pol_raw:
            pol_raw["max_cost_policy"] = payload["max_permitted_cost_policy"]
        if "preferred_models" in payload and "preferred_models" not in pol_raw:
            pol_raw["preferred_models"] = payload["preferred_models"]
        if "disallowed_models" in payload and "blocked_models" not in pol_raw:
            pol_raw["blocked_models"] = payload["disallowed_models"]
        if "preferred_reasoning_effort" in payload and "preferred_effort" not in pol_raw:
            pol_raw["preferred_effort"] = payload["preferred_reasoning_effort"]
        registry.set_policy(UserRoutingPolicy.from_dict(pol_raw))

    return {
        "user_profile_id": user_id,
        "loaded_accounts": loaded_accounts,
        "loaded_models": loaded_models,
        "loaded_quotas": loaded_quotas,
    }


def load_manual_profile_file(registry: EntitlementRegistry, path: Path) -> dict[str, Any]:
    """Load and validate a manual profile JSON file."""
    raw = Path(path).expanduser().resolve().read_text(encoding="utf-8-sig")
    data = json.loads(raw)
    return load_manual_profile_dict(registry, data)
