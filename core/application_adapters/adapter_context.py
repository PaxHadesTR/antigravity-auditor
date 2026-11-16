"""Adapter context separation: untrusted hints vs OS/challenge-bound caller identity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from broker.security import ClientIdentity
from mcp_gateway.authenticated_context import (
    AuthenticatedCallerContext,
    CallerIdentityResolver,
    ProtocolContext,
)
from mcp_gateway.contracts import AuthMethod, ProtocolEra
from mcp_gateway.untrusted_hints import UntrustedClientHints

from application_adapters.contracts import (
    AdapterProofVerificationResult,
    IdentityVerificationStatus,
    ProcessObservation,
    SignedAdapterProof,
)
from application_adapters.identity_proof import (
    AdapterChallengeManager,
    ChallengeBoundAdapterProofVerifier,
)


@dataclass(frozen=True)
class UntrustedAdapterHints:
    """Inputs supplied via CLI args, env vars, or MCP clientInfo; zero trust for authz."""

    claimed_application_arg: str | None = None
    claimed_env_application: str | None = None
    mcp_params: dict[str, Any] = field(default_factory=dict)
    grants_authentication: bool = False
    grants_authorization: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "grants_authentication", False)
        object.__setattr__(self, "grants_authorization", False)

    def to_gateway_hints(self) -> UntrustedClientHints:
        return UntrustedClientHints.from_mcp_params(
            self.mcp_params,
            claimed_env_application=self.claimed_env_application,
        )

    def to_diagnostic_dict(self) -> dict[str, Any]:
        gw_hints = self.to_gateway_hints()
        out = gw_hints.to_sanitized_dict()
        out["claimed_application_arg"] = self.claimed_application_arg
        out["grants_authentication"] = False
        out["grants_authorization"] = False
        return out


@dataclass(frozen=True)
class AdapterResolutionBundle:
    caller_context: AuthenticatedCallerContext
    untrusted_hints: UntrustedClientHints
    process_observation: ProcessObservation
    proof_verification: AdapterProofVerificationResult


class AdapterContextResolver:
    """Resolves NEXT-22C AuthenticatedCallerContext from OS + challenge proof while isolating hints."""

    def resolve(
        self,
        *,
        os_identity: ClientIdentity | None,
        process_obs: ProcessObservation,
        challenge_manager: AdapterChallengeManager,
        signed_proof: SignedAdapterProof | None = None,
        untrusted_adapter_hints: UntrustedAdapterHints | None = None,
        claimed_sid: str | None = None,
        permitted_scopes_for_sid: frozenset[str] | None = None,
        allowed_user_profile_ids: frozenset[str] = frozenset(),
        allowed_account_context_ids: frozenset[str] = frozenset(),
        account_context_id: str | None = None,
        workspace_context_id: str | None = None,
        protocol_version: str = "2025-11-25",
        protocol_era: ProtocolEra = ProtocolEra.LEGACY,
    ) -> AdapterResolutionBundle:
        raw_hints = untrusted_adapter_hints or UntrustedAdapterHints()
        gw_hints = raw_hints.to_gateway_hints()

        verifier = ChallengeBoundAdapterProofVerifier(
            challenge_manager=challenge_manager,
            process_obs=process_obs,
        )
        gw_proof = verifier.to_gateway_proof(signed_proof) if signed_proof is not None else None
        identity_resolver = CallerIdentityResolver(adapter_verifier=verifier)

        caller = identity_resolver.resolve_local_windows_caller(
            os_identity=os_identity,
            claimed_sid=claimed_sid,
            adapter_proof=gw_proof,
            untrusted_hints=gw_hints,
            permitted_scopes_for_sid=permitted_scopes_for_sid,
            allowed_user_profile_ids=allowed_user_profile_ids,
            allowed_account_context_ids=allowed_account_context_ids,
            account_context_id=account_context_id,
            workspace_context_id=workspace_context_id,
            protocol_context=ProtocolContext(
                protocol_era=protocol_era,
                protocol_version=protocol_version,
                transport="stdio",
            ),
            auth_method=AuthMethod.LOCAL_WIN32_NAMED_PIPE,
        )

        last_res = None
        if signed_proof is not None and verifier._last_results:
            last_res = verifier._last_results.get(signed_proof.challenge_id)
        if last_res is None:
            last_res = AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.UNVERIFIED,
                reason_code=(
                    "CREDENTIAL_PROVIDER_DISABLED"
                    if not challenge_manager.credential_provider.is_enabled
                    else "MISSING_ADAPTER_PROOF"
                ),
                reason=(
                    "No valid challenge-bound adapter proof verified; caller clamped to UNKNOWN / CORE_READ."
                ),
                audit_evidence={
                    "provider_enabled": challenge_manager.credential_provider.is_enabled,
                    "proof_present": signed_proof is not None,
                    "claimed_application_arg_ignored": bool(raw_hints.claimed_application_arg),
                },
            )

        return AdapterResolutionBundle(
            caller_context=caller,
            untrusted_hints=gw_hints,
            process_observation=process_obs,
            proof_verification=last_res,
        )
