"""Authorized read-only NEXT-22B Model Router tool bridge for NEXT-22C MCP Gateway."""

from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Any

from entitlement_router.contracts import UserProfileRecord
from entitlement_router.privacy import sanitize_for_output, validate_opaque_id
from entitlement_router.registry import EntitlementRegistry
from entitlement_router.router import CapabilityModelRouter
from mcp_gateway.authenticated_context import AuthenticatedCallerContext
from mcp_gateway.protocol_adapter import paginate_items


def _open_readonly_sqlite(db_path: Path) -> sqlite3.Connection:
    resolved = db_path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Routing database not found: {resolved}")
    conn = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


class RoutingToolBridge:
    """Exposes NEXT-22B EntitlementRegistry & CapabilityModelRouter strictly in read-only mode."""

    def __init__(
        self,
        *,
        registry: EntitlementRegistry | None = None,
        routing_db_path: Path | None = None,
    ) -> None:
        self._registry = registry
        self._routing_db_path = routing_db_path

    def _get_registry(self) -> EntitlementRegistry:
        if self._registry is not None:
            return self._registry
        if self._routing_db_path is not None and self._routing_db_path.is_file():
            conn = _open_readonly_sqlite(self._routing_db_path)
            try:
                return EntitlementRegistry.load_from_db(conn)
            finally:
                conn.close()
        return EntitlementRegistry()

    def _require_authorized_caller_profiles(
        self,
        caller: AuthenticatedCallerContext,
    ) -> frozenset[str]:
        """Fail closed unless caller is OS/adapter-verified and bound to a non-empty user profile allowlist."""
        if not caller.is_authenticated:
            raise PermissionError("Unauthenticated caller cannot invoke routing tools.")
        if caller.is_unknown_application:
            raise PermissionError("Unverified application identity cannot invoke routing tools.")
        if not caller.allowed_user_profile_ids:
            raise PermissionError("Caller has no bound user_profile_id allowlist; failing closed.")
        return caller.allowed_user_profile_ids

    def _allowed_account_ids(self, caller: AuthenticatedCallerContext) -> set[str]:
        allowed_accts = set(caller.allowed_account_context_ids)
        if caller.account_context_id:
            allowed_accts.add(caller.account_context_id)
        return allowed_accts

    def _scope_explained_plan(
        self,
        plan_dict: dict[str, Any],
        caller: AuthenticatedCallerContext,
        decision_id: str,
        known_account_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Enforce account-context isolation on stored RoutePlan dictionaries."""
        allowed_accts = self._allowed_account_ids(caller)
        if not allowed_accts:
            raise PermissionError("Caller has no bound account_context_id allowlist; failing closed.")

        disallowed_accts: set[str] = set(known_account_ids or ()) - allowed_accts
        scoped = dict(plan_dict)
        roles = scoped.get("roles")
        if isinstance(roles, dict):
            for role_name, assignment in roles.items():
                if isinstance(assignment, dict):
                    acct_id = assignment.get("account_context_id")
                    if acct_id is not None and acct_id not in allowed_accts:
                        raise PermissionError(
                            f"Decision '{decision_id}' role '{role_name}' references account_context_id "
                            f"'{acct_id}' outside caller's authorized scope."
                        )

        for list_key in ("candidate_evaluations", "excluded_candidates"):
            entries = scoped.get(list_key)
            if isinstance(entries, list):
                kept = []
                for item in entries:
                    if not isinstance(item, dict):
                        continue
                    item_acct = item.get("account_context_id")
                    if item_acct in allowed_accts:
                        kept.append(item)
                    elif item_acct:
                        disallowed_accts.add(str(item_acct))
                scoped[list_key] = kept

        fallbacks = scoped.get("fallback_candidates")
        if isinstance(fallbacks, dict):
            filtered_fb: dict[str, list[Any]] = {}
            for role_key, role_items in fallbacks.items():
                kept_fb = []
                for item in (role_items if isinstance(role_items, list) else []):
                    if not isinstance(item, dict):
                        continue
                    item_acct = item.get("account_context_id")
                    if item_acct in allowed_accts:
                        kept_fb.append(item)
                    elif item_acct:
                        disallowed_accts.add(str(item_acct))
                filtered_fb[role_key] = kept_fb
            scoped["fallback_candidates"] = filtered_fb

        ev_refs = scoped.get("evidence_refs")
        if isinstance(ev_refs, list) and disallowed_accts:
            scoped["evidence_refs"] = [
                ref
                for ref in ev_refs
                if not any(dis in str(ref) for dis in disallowed_accts)
            ]
        return scoped

    def _resolve_authorized_user_id(
        self,
        caller: AuthenticatedCallerContext,
        requested_user_id: str | None,
    ) -> str:
        allowed_profiles = self._require_authorized_caller_profiles(caller)
        allowed_users = sorted(allowed_profiles)
        if requested_user_id is not None:
            uid = validate_opaque_id(requested_user_id, field_name="user_profile_id")
            if uid not in allowed_profiles:
                raise PermissionError(f"Caller is not authorized for user_profile_id '{uid}'.")
            return uid
        return allowed_users[0]

    def _filter_authorized_accounts(
        self,
        caller: AuthenticatedCallerContext,
        accounts: list[Any],
    ) -> list[Any]:
        allowed_accts = self._allowed_account_ids(caller)
        if not allowed_accts:
            return []
        return [a for a in accounts if a.account_context_id in allowed_accts]

    def _scoped_registry_for_caller(
        self,
        reg: EntitlementRegistry,
        caller: AuthenticatedCallerContext,
        uid: str,
    ) -> EntitlementRegistry:
        """Return an isolated EntitlementRegistry view containing ONLY uid and permitted accounts."""
        scoped = EntitlementRegistry()
        user_rec = reg.users.get(uid) or UserProfileRecord(user_profile_id=uid)
        scoped.register_user(user_rec)

        auth_accts = self._filter_authorized_accounts(caller, reg.get_user_accounts(uid))
        allowed_acct_ids = {a.account_context_id for a in auth_accts}
        allowed_app_inst_ids = {a.application_instance_id for a in auth_accts}

        for app_inst_id in allowed_app_inst_ids:
            app = reg.applications.get(app_inst_id)
            if app is not None:
                scoped.register_application(app)
        for acct in auth_accts:
            scoped.register_account(acct)
        for obs in reg.entitlement_history:
            if obs.account_context_id in allowed_acct_ids:
                scoped.entitlement_history.append(obs)
        for qobs in reg.quota_history:
            if qobs.account_context_id in allowed_acct_ids:
                scoped.quota_history.append(qobs)
        scoped.model_identities.update(reg.model_identities)
        scoped.capability_evidence.extend(reg.capability_evidence)
        for (app_id, mid, acct_ctx_id), prof in reg.effort_profiles.items():
            if acct_ctx_id is None or acct_ctx_id in allowed_acct_ids:
                scoped.effort_profiles[(app_id, mid, acct_ctx_id)] = prof
        if uid in reg.policies:
            scoped.policies[uid] = reg.policies[uid]
        return scoped

    def handle_tool(
        self,
        handler_key: str,
        args: dict[str, Any],
        caller: AuthenticatedCallerContext,
    ) -> dict[str, Any]:
        allowed_profiles = self._require_authorized_caller_profiles(caller)
        reg = self._get_registry()

        if handler_key == "routing.inspect_profile":
            uid = self._resolve_authorized_user_id(caller, args.get("user_profile_id"))
            if uid not in reg.users:
                reg.register_user(UserProfileRecord(user_profile_id=uid))
            matrix = reg.export_account_model_matrix(uid)
            allowed_accts = set(caller.allowed_account_context_ids)
            if caller.account_context_id:
                allowed_accts.add(caller.account_context_id)
            filtered_accounts = [
                entry
                for entry in matrix.get("accounts", [])
                if entry.get("account", {}).get("account_context_id") in allowed_accts
            ]
            paged_accounts, next_cursor = paginate_items(
                filtered_accounts,
                cursor=args.get("cursor"),
                page_size=int(args.get("limit", 25)),
            )
            policy = reg.get_policy(uid).to_dict()
            return sanitize_for_output(
                {
                    "read_only_planning": True,
                    "execution_authorized": False,
                    "user_profile_id": uid,
                    "account_count": len(filtered_accounts),
                    "accounts": paged_accounts,
                    "policy": policy,
                    "next_cursor": next_cursor,
                }
            )

        if handler_key == "routing.list_accounts":
            uid = self._resolve_authorized_user_id(caller, args.get("user_profile_id"))
            all_accts = self._filter_authorized_accounts(caller, reg.get_user_accounts(uid))
            acct_dicts = [a.to_dict() for a in all_accts]
            paged, next_cursor = paginate_items(
                acct_dicts,
                cursor=args.get("cursor"),
                page_size=int(args.get("limit", 25)),
            )
            return sanitize_for_output(
                {
                    "read_only_planning": True,
                    "execution_authorized": False,
                    "user_profile_id": uid,
                    "account_count": len(acct_dicts),
                    "accounts": paged,
                    "next_cursor": next_cursor,
                }
            )

        if handler_key == "routing.inspect_models":
            acct_id = validate_opaque_id(args["account_context_id"], field_name="account_context_id")
            allowed_accts = self._allowed_account_ids(caller)
            if acct_id not in allowed_accts:
                raise PermissionError(f"Caller is not authorized for account_context_id '{acct_id}'.")
            acct = reg.accounts.get(acct_id)
            if acct is None:
                raise LookupError(f"Account context not found: {acct_id}")
            if acct.user_profile_id not in allowed_profiles:
                raise PermissionError("Account context belongs to an unauthorized user profile.")

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
            paged, next_cursor = paginate_items(
                models_out,
                cursor=args.get("cursor"),
                page_size=int(args.get("limit", 25)),
            )
            return sanitize_for_output(
                {
                    "read_only_planning": True,
                    "execution_authorized": False,
                    "account": acct.to_dict(),
                    "model_count": len(models_out),
                    "models": paged,
                    "next_cursor": next_cursor,
                }
            )

        if handler_key == "routing.plan":
            uid = self._resolve_authorized_user_id(caller, args.get("user_profile_id"))
            scoped_reg = self._scoped_registry_for_caller(reg, caller, uid)
            router = CapabilityModelRouter(scoped_reg)
            plan = router.plan(
                user_profile_id=uid,
                task_profile=dict(args["task_profile"]),
            )
            plan_dict = sanitize_for_output(plan.to_dict())
            # Guarantee execution_authorized remains False
            plan_dict["execution_authorized"] = False
            return plan_dict

        if handler_key == "routing.explain_decision":
            dec_id = validate_opaque_id(args["decision_id"], field_name="decision_id")
            plan_dict: dict[str, Any] | None = None
            dec = reg.decisions.get(dec_id)
            if dec is not None:
                if dec.user_profile_id not in allowed_profiles:
                    raise PermissionError(f"Decision '{dec_id}' belongs to an unauthorized user profile.")
                plan_dict = dec.to_dict()
            elif self._routing_db_path is not None and self._routing_db_path.is_file():
                conn = _open_readonly_sqlite(self._routing_db_path)
                try:
                    row = conn.execute(
                        "SELECT user_profile_id, plan_json FROM routing_decisions WHERE decision_id = ?",
                        (dec_id,),
                    ).fetchone()
                    if row is not None:
                        if row["user_profile_id"] not in allowed_profiles:
                            raise PermissionError(f"Decision '{dec_id}' belongs to an unauthorized user profile.")
                        import json

                        plan_dict = json.loads(row["plan_json"])
                finally:
                    conn.close()
            if plan_dict is None:
                raise LookupError(f"Routing decision not found: {dec_id}")
            plan_dict = self._scope_explained_plan(
                plan_dict,
                caller,
                dec_id,
                known_account_ids=set(reg.accounts.keys()),
            )
            plan_dict["execution_authorized"] = False
            return sanitize_for_output(
                {
                    "read_only_planning": True,
                    "execution_authorized": False,
                    "decision_id": dec_id,
                    "plan": plan_dict,
                }
            )

        raise ValueError(f"Unknown routing handler key: {handler_key}")
