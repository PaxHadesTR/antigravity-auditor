"""Read-only / dry-run CLI command handlers for NEXT-22B `auditor routing ...`."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from entitlement_router.contracts import UserProfileRecord
from entitlement_router.discovery_importer import (
    import_runtime_discovery_report,
    load_discovery_report_file,
)
from entitlement_router.manual_profile import load_manual_profile_file
from entitlement_router.privacy import sanitize_for_output, validate_opaque_id
from entitlement_router.registry import EntitlementRegistry
from entitlement_router.router import CapabilityModelRouter
from runtime_discovery import RuntimeDiscoveryCoordinator


def _open_readonly_sqlite(db_path: Path) -> sqlite3.Connection:
    resolved = db_path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Routing database not found: {resolved}")
    conn = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _build_ephemeral_registry(
    *,
    db_path: str | None = None,
    discovery_file: str | None = None,
    profile_file: str | None = None,
    user_profile_id: str = "usr-local-default",
) -> tuple[EntitlementRegistry, str]:
    validate_opaque_id(user_profile_id, field_name="user_profile_id")
    effective_user_id = user_profile_id

    if db_path:
        conn = _open_readonly_sqlite(Path(db_path))
        try:
            reg = EntitlementRegistry.load_from_db(conn)
        finally:
            conn.close()
    else:
        reg = EntitlementRegistry()

    if discovery_file:
        report = load_discovery_report_file(Path(discovery_file))
        import_runtime_discovery_report(reg, report, user_profile_id=effective_user_id)
    elif not db_path and not profile_file:
        report = RuntimeDiscoveryCoordinator().discover()
        import_runtime_discovery_report(reg, report, user_profile_id=effective_user_id)

    if profile_file:
        res = load_manual_profile_file(reg, Path(profile_file))
        effective_user_id = str(res["user_profile_id"])

    if effective_user_id not in reg.users and not db_path:
        reg.register_user(UserProfileRecord(user_profile_id=effective_user_id))

    return reg, effective_user_id


def render_routing_inspect_text(payload: dict[str, Any]) -> str:
    lines = [
        f"Routing Inspection (user={payload['user_profile_id']})",
        f"Execution Authorized: {payload['execution_authorized']}",
        f"Accounts: {payload['account_count']}",
    ]
    for acct_entry in payload.get("accounts", []):
        acct = acct_entry["account"]
        lines.append(
            f"- {acct['account_context_id']} | app={acct['application_id']} | "
            f"provider={acct['provider']} | auth={acct['authentication_mode']} | "
            f"models={len(acct_entry.get('models', []))}"
        )
    return "\n".join(lines)


def render_route_plan_text(plan: dict[str, Any]) -> str:
    lines = [
        f"Route Plan {plan['decision_id']} (task={plan['task_profile_id']}, risk={plan['risk']})",
        f"Status: {plan['status']} | Execution Authorized: {plan['execution_authorized']}",
        f"Billing: mode={plan['billing']['mode']}, api_billing_allowed={plan['billing']['api_billing_allowed']}, cost_state={plan['billing']['cost_state']}",
        "Roles:",
    ]
    for role_name, info in sorted(plan.get("roles", {}).items()):
        lines.append(
            f"- {role_name}: app={info['application']} model={info['model_id']} "
            f"effort={info['effort']} eligibility={info['eligibility']} ({info['reason']})"
        )
    if plan.get("excluded_candidates"):
        lines.append(f"Excluded Candidates: {len(plan['excluded_candidates'])}")
    return "\n".join(lines)


def execute_routing_command(args: Any) -> dict[str, Any]:
    """Execute a dry-run/read-only `auditor routing ...` subcommand and return sanitized payload."""
    subcmd = args.routing_command

    if subcmd == "explain":
        dec_id = validate_opaque_id(args.decision_id, field_name="decision_id")
        if not args.db:
            raise ValueError("'routing explain' requires --db pointing to a SQLite database containing decisions.")
        conn = _open_readonly_sqlite(Path(args.db))
        try:
            row = conn.execute(
                "SELECT * FROM routing_decisions WHERE decision_id = ?",
                (dec_id,),
            ).fetchone()
            if not row:
                raise LookupError(f"Routing decision not found: {dec_id}")
            plan_data = json.loads(row["plan_json"])
            exp_rows = conn.execute(
                "SELECT * FROM routing_candidate_explanations WHERE decision_id = ? ORDER BY explanation_id ASC",
                (dec_id,),
            ).fetchall()
            return sanitize_for_output(
                {
                    "decision_id": dec_id,
                    "plan": plan_data,
                    "persisted_explanations_count": len(exp_rows),
                }
            )
        finally:
            conn.close()

    reg, eff_user = _build_ephemeral_registry(
        db_path=getattr(args, "db", None),
        discovery_file=getattr(args, "discovery_file", None),
        profile_file=getattr(args, "profile_file", None),
        user_profile_id=getattr(args, "user_profile", "usr-local-default") or "usr-local-default",
    )

    if subcmd == "inspect":
        matrix = reg.export_account_model_matrix(eff_user)
        policy = reg.get_policy(eff_user).to_dict()
        return sanitize_for_output(
            {
                "read_only_planning": True,
                "execution_authorized": False,
                **matrix,
                "policy": policy,
            }
        )

    if subcmd == "accounts":
        accts = [a.to_dict() for a in reg.get_user_accounts(eff_user)]
        return sanitize_for_output(
            {
                "read_only_planning": True,
                "execution_authorized": False,
                "user_profile_id": eff_user,
                "account_count": len(accts),
                "accounts": accts,
            }
        )

    if subcmd == "models":
        acct_id = validate_opaque_id(args.account, field_name="account")
        acct = reg.accounts.get(acct_id)
        if not acct:
            raise LookupError(f"Account context not found: {acct_id}")
        models_out: list[dict[str, Any]] = []
        for mid in reg.list_models_for_account(acct_id):
            eff_ent = reg.get_effective_entitlement(acct_id, mid)
            eff_q = reg.get_effective_quota(acct_id, mid)
            eff_prof = reg.get_effort_profile(acct.application_id, mid, acct_id)
            ident = reg.model_identities.get((acct.application_id, mid))
            models_out.append(
                {
                    "model_id": mid,
                    "provider": ident.provider if ident else acct.provider,
                    "model_family": ident.model_family if ident else "UNKNOWN",
                    "effective_entitlement_state": eff_ent.state.value,
                    "entitlement_stale": eff_ent.is_stale,
                    "provenance": eff_ent.observation.provenance if eff_ent.observation else "UNKNOWN",
                    "evidence_ref": eff_ent.observation.evidence_ref if eff_ent.observation else None,
                    "observed_at": eff_ent.observation.observed_at if eff_ent.observation else None,
                    "quota_state": eff_q.state.value,
                    "quota_stale": eff_q.is_stale,
                    "supported_efforts": [e.value for e in eff_prof.supported_efforts] if eff_prof else ["UNKNOWN"],
                }
            )
        return sanitize_for_output(
            {
                "read_only_planning": True,
                "execution_authorized": False,
                "account": acct.to_dict(),
                "model_count": len(models_out),
                "models": models_out,
            }
        )

    if subcmd == "policy":
        if getattr(args, "policy_command", None) == "show":
            pol = reg.get_policy(eff_user).to_dict()
            return sanitize_for_output(
                {
                    "read_only_planning": True,
                    "execution_authorized": False,
                    "policy": pol,
                }
            )
        raise ValueError(f"Unsupported policy subcommand: {getattr(args, 'policy_command', None)}")

    if subcmd == "plan":
        tp_path = Path(args.task_profile).expanduser().resolve()
        tp_data = json.loads(tp_path.read_text(encoding="utf-8-sig"))
        router = CapabilityModelRouter(reg)
        plan = router.plan(user_profile_id=eff_user, task_profile=tp_data)
        return plan.to_dict()

    raise ValueError(f"Unsupported routing subcommand: {subcmd}")
