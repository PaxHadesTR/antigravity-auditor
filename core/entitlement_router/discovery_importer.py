"""Importer bridging NEXT-22A Runtime Discovery evidence into NEXT-22B registries without upgrading provenance."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from model_attestation import MODEL_NAME_NORMALIZATION
from entitlement_router.contracts import (
    AccountContextRecord,
    AccountScope,
    ApplicationInstanceRecord,
    AuthenticationMode,
    ConfidenceLevel,
    EntitlementState,
    ModelEffortProfile,
    ModelEntitlementObservation,
    ModelIdentityRecord,
    NormalizedEffort,
    QuotaObservation,
    QuotaState,
    SubscriptionSource,
    utc_now_iso,
)
from entitlement_router.registry import EntitlementRegistry

_EFFORT_SUFFIX_RE = re.compile(r"-(low|medium|high|xhigh|max|ultra)$", re.IGNORECASE)


def infer_conservative_model_family(
    model_id: str,
    *,
    is_orchestrator: bool = False,
) -> str:
    """Conservatively derive base model family only when explicit in model_id; otherwise UNKNOWN."""
    if is_orchestrator:
        return "UNKNOWN"
    low = (model_id or "").strip().lower()
    if not low:
        return "UNKNOWN"
    base = _EFFORT_SUFFIX_RE.sub("", low)
    if base.startswith(("gemini-", "claude-", "gpt-", "codex-", "o1", "o3", "o4")):
        return base
    return "UNKNOWN"


def _map_availability_to_entitlement_state(availability_state: str, evidence_class: str) -> EntitlementState:
    av = (availability_state or "").strip().lower()
    ev = (evidence_class or "").strip().upper()
    if av == "bundled_catalog" or ev == "BUNDLED_CATALOG":
        return EntitlementState.BUNDLED_CATALOG
    if av == "runtime_observed" or ev == "RUNTIME_OBSERVED":
        return EntitlementState.RUNTIME_OBSERVED
    if av == "account_enumerated" or ev == "ACCOUNT_ENUMERATED":
        return EntitlementState.ACCOUNT_ENUMERATED
    if av == "configured" or ev == "CONFIGURED":
        return EntitlementState.CONFIGURED
    if av == "documented_only" or ev == "DOCUMENTED_CAPABILITY":
        return EntitlementState.DOCUMENTED_ONLY
    if av == "user_reported" or ev == "USER_REPORTED":
        return EntitlementState.USER_DECLARED
    return EntitlementState.UNKNOWN


def import_runtime_discovery_report(
    registry: EntitlementRegistry,
    report: dict[str, Any],
    *,
    user_profile_id: str = "usr-local-default",
    account_id_prefix: str | None = None,
) -> dict[str, Any]:
    """Import a NEXT-22A runtime-discovery.json report preserving exact provenance and timestamps.

    Invariants:
    - BUNDLED_CATALOG stays BUNDLED_CATALOG (never converted to account entitlement).
    - RUNTIME_OBSERVED stays RUNTIME_OBSERVED (never converted to SELECTABLE_VERIFIED).
    - NOT_INSTALLED apps (e.g. claude_code) yield zero fictitious entitlements.
    - Remote connectors NOT_EXPOSED stay UNKNOWN / NOT_EXPOSED.
    """
    run_id = str(report.get("run_id") or "next22a-imported")
    generated_at = str(report.get("generated_at") or utc_now_iso())
    apps = report.get("applications") or {}

    imported_apps = 0
    imported_models = 0
    imported_efforts = 0
    prefix = account_id_prefix or user_profile_id

    for app_id in sorted(apps.keys()):
        app_data = apps[app_id]
        install_state = str(app_data.get("installation_state") or "unknown")
        packaging_mode = str(app_data.get("packaging_mode") or "unknown")
        version_obj = app_data.get("version") or {}
        version_val = version_obj.get("value")
        exes = app_data.get("executables") or []
        exe_basename = exes[0].get("basename") if exes else None
        cli_info = app_data.get("cli") or {}
        if not exe_basename and cli_info.get("path"):
            exe_basename = Path(str(cli_info["path"])).name

        app_instance_id = f"app-{prefix}-{app_id}".replace("_", "-")[:95]
        registry.register_application(
            ApplicationInstanceRecord(
                application_instance_id=app_instance_id,
                user_profile_id=user_profile_id,
                application_id=app_id,
                installation_state=install_state,
                packaging_mode=packaging_mode,
                version=str(version_val) if version_val else None,
                executable_basename=str(exe_basename) if exe_basename else None,
                observed_at=generated_at,
                evidence_ref=f"next22a:{run_id}:{app_id}",
            )
        )
        imported_apps += 1

        # Only register discovered runtime account context for installed / partial apps
        if install_state == "not_installed":
            continue

        acct_id = f"acct-{prefix}-{app_id}-discovered".replace("_", "-")[:95]
        provider = str(app_data.get("application_family") or "unknown")
        if app_id == "codex":
            provider = "openai"
        elif app_id in ("claude_desktop", "claude_code"):
            provider = "anthropic"
        elif app_id == "antigravity":
            provider = "google"

        models_raw = app_data.get("models") or []
        acct_ent_state = (
            EntitlementState.RUNTIME_OBSERVED
            if any(m.get("availability_state") == "runtime_observed" for m in models_raw)
            else (
                EntitlementState.BUNDLED_CATALOG
                if any(m.get("availability_state") == "bundled_catalog" for m in models_raw)
                else EntitlementState.UNKNOWN
            )
        )

        registry.register_account(
            AccountContextRecord(
                account_context_id=acct_id,
                user_profile_id=user_profile_id,
                application_instance_id=app_instance_id,
                application_id=app_id,
                provider=provider,
                authentication_mode=AuthenticationMode.UNKNOWN,
                account_scope=AccountScope.USER_ACCOUNT,
                workspace_scope=None,
                subscription_tier=None,
                subscription_source=SubscriptionSource.UNKNOWN,
                entitlement_state=acct_ent_state,
                observed_at=generated_at,
            )
        )

        # Quota is NOT_EXPOSED in NEXT-22A read-only local discovery
        registry.record_quota(
            QuotaObservation(
                observation_id=f"q-{run_id}-{app_id}-001".replace("_", "-")[:95],
                account_context_id=acct_id,
                model_id=None,
                usage_category="application_discovery",
                quota_state=QuotaState.NOT_EXPOSED,
                observed_at=generated_at,
                source="next22a_runtime_discovery",
                evidence_ref=f"next22a:{run_id}:{app_id}:quota",
            )
        )

        orchestrators_by_id = {
            str(o.get("orchestrator_id")): o
            for o in (app_data.get("orchestrators") or [])
            if isinstance(o, dict) and o.get("orchestrator_id")
        }

        for idx, m in enumerate(models_raw, start=1):
            model_id = str(m.get("model_id") or "").strip()
            if not model_id:
                continue
            m_provider = str(m.get("provider") or provider).lower()
            caps = m.get("capabilities") or {}
            is_orch = bool(caps.get("is_orchestrator_mode")) or (model_id in orchestrators_by_id)
            orch_meta = orchestrators_by_id.get(model_id)
            ent_state = _map_availability_to_entitlement_state(
                str(m.get("availability_state") or ""),
                str(m.get("evidence_class") or ""),
            )
            obs_at = str(m.get("observed_at") or generated_at)
            ev_ref = str(m.get("evidence_id") or f"next22a:{run_id}:{app_id}:{model_id}")

            canonical_mid = MODEL_NAME_NORMALIZATION.get(model_id.lower())
            effort_match = _EFFORT_SUFFIX_RE.search(model_id)
            effort_variant = effort_match.group(1).lower() if effort_match else None
            family = infer_conservative_model_family(model_id, is_orchestrator=is_orch)

            registry.register_model_identity(
                ModelIdentityRecord(
                    application_id=app_id,
                    application_model_id=model_id,
                    provider=m_provider,
                    canonical_model_id=canonical_mid,
                    model_version=None,
                    model_family=family,
                    variant=str(m.get("display_name") or model_id),
                    reasoning_effort_variant=effort_variant,
                    is_orchestrator_wrapper=is_orch,
                    orchestrator_wrapper_identity=(
                        str(orch_meta.get("display_label") or m.get("display_name"))
                        if is_orch
                        else None
                    ),
                )
            )

            conf = (
                ConfidenceLevel.MEDIUM
                if ent_state == EntitlementState.RUNTIME_OBSERVED
                else ConfidenceLevel.LOW
            )
            registry.record_entitlement(
                ModelEntitlementObservation(
                    observation_id=f"ent-{run_id}-{app_id}-{idx:04d}".replace("_", "-")[:95],
                    account_context_id=acct_id,
                    application_instance_id=app_instance_id,
                    application_id=app_id,
                    model_id=model_id,
                    state=ent_state,
                    provenance=str(m.get("evidence_class") or ent_state.value),
                    confidence=conf,
                    observed_at=obs_at,
                    evidence_ref=ev_ref,
                    notes=f"Imported from NEXT-22A catalog_source={m.get('catalog_source')}",
                )
            )
            imported_models += 1

            raw_efforts = tuple(str(e).strip() for e in (m.get("reasoning_efforts") or []) if str(e).strip())
            if is_orch and not raw_efforts:
                sup_efforts: tuple[NormalizedEffort, ...] = (NormalizedEffort.FIXED_INTERNAL,)
                def_effort = NormalizedEffort.FIXED_INTERNAL
                raw_def = None
                indep_cfg = False
                orch_struct = {
                    "routing_observable": bool(orch_meta.get("routing_observable", False)) if orch_meta else False,
                    "exposed_model_identity": orch_meta.get("exposed_model_identity") if orch_meta else None,
                }
            else:
                sup_efforts = tuple(dict.fromkeys(NormalizedEffort.parse(e) for e in raw_efforts))
                raw_def_val = m.get("default_effort")
                raw_def = str(raw_def_val).strip() if raw_def_val else None
                def_effort = NormalizedEffort.parse(raw_def) if raw_def else (
                    sup_efforts[0] if len(sup_efforts) == 1 else NormalizedEffort.UNKNOWN
                )
                indep_cfg = len(sup_efforts) > 1
                orch_struct = None

            registry.register_effort_profile(
                ModelEffortProfile(
                    application_id=app_id,
                    application_model_id=model_id,
                    account_context_id=None,
                    supported_efforts=sup_efforts,
                    raw_supported_efforts=raw_efforts,
                    default_effort=def_effort,
                    raw_default_effort=raw_def,
                    selected_effort=None,  # Active session is NOT_EXPOSED
                    independently_configurable=indep_cfg,
                    managed_by_orchestrator=is_orch,
                    orchestrator_structure=orch_struct,
                    provenance=str(m.get("evidence_class") or ent_state.value),
                    observed_at=obs_at,
                    evidence_ref=ev_ref,
                )
            )
            imported_efforts += 1

    return {
        "run_id": run_id,
        "user_profile_id": user_profile_id,
        "imported_applications": imported_apps,
        "imported_models": imported_models,
        "imported_effort_profiles": imported_efforts,
    }


def load_discovery_report_file(path: Path) -> dict[str, Any]:
    """Load a NEXT-22A runtime-discovery.json file safely."""
    raw = Path(path).expanduser().resolve().read_text(encoding="utf-8-sig")
    data = json.loads(raw)
    if not isinstance(data, dict) or "applications" not in data:
        raise ValueError(f"Invalid NEXT-22A runtime discovery report: {path}")
    return data
