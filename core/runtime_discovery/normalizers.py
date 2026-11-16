"""Model catalog, reasoning effort, and orchestrator normalizers."""

from __future__ import annotations

import json
import re
from typing import Any

from runtime_discovery.contracts import (
    AvailabilityState,
    EvidenceClass,
    NormalizedEffortRecord,
    NormalizedModelRecord,
    ObservationState,
)

_EFFORT_SUFFIX_RE = re.compile(r"-(low|medium|high|xhigh|max|ultra)$", re.IGNORECASE)
_ORCHESTRATOR_PARENS_RE = re.compile(r"\(([^)]+)\)")


def extract_effort_from_slug(model_slug: str) -> str | None:
    """Extract explicit reasoning effort suffix from a model slug when present."""
    m = _EFFORT_SUFFIX_RE.search(model_slug.strip())
    return m.group(1).lower() if m else None


def infer_provider_from_model_id(model_id: str) -> str:
    """Infer upstream model provider family purely from explicit model slug prefix."""
    low = model_id.strip().lower()
    if low.startswith("gemini"):
        return "google"
    if low.startswith("claude"):
        return "anthropic"
    if low.startswith(("gpt-", "o1", "o3", "o4", "codex")):
        return "openai"
    return "unknown"


def parse_agy_models_output(
    stdout: str,
    *,
    observed_at: str,
    evidence_id: str,
) -> tuple[list[NormalizedModelRecord], list[NormalizedEffortRecord], list[dict[str, Any]]]:
    """Parse `agy models` stdout into normalized models, efforts, and orchestrator records."""
    models: list[NormalizedModelRecord] = []
    efforts: list[NormalizedEffortRecord] = []
    orchestrators: list[dict[str, Any]] = []

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "\t" in line:
            slug, display_name = line.split("\t", 1)
        else:
            parts = line.split(None, 1)
            slug = parts[0]
            display_name = parts[1] if len(parts) > 1 else parts[0]

        slug = slug.strip()
        display_name = display_name.strip()
        if not slug or slug.lower().startswith("fetching "):
            continue

        effort = extract_effort_from_slug(slug)
        effort_tuple = (effort,) if effort else ()
        is_orchestrator = "orchestrator" in slug.lower() or "orchestrator" in display_name.lower()

        if is_orchestrator:
            parens = _ORCHESTRATOR_PARENS_RE.search(display_name)
            exposed_identity = parens.group(1).strip() if parens else None
            orchestrators.append(
                {
                    "orchestrator_id": slug,
                    "display_label": display_name,
                    "exposed_model_identity": exposed_identity,
                    "visible_effort_control": effort,
                    "routing_observable": False,
                    "evidence_class": EvidenceClass.RUNTIME_OBSERVED.value,
                    "evidence_id": evidence_id,
                }
            )

        models.append(
            NormalizedModelRecord(
                provider=infer_provider_from_model_id(slug),
                application_id="antigravity",
                model_id=slug,
                display_name=display_name,
                availability_state=AvailabilityState.RUNTIME_OBSERVED,
                evidence_class=EvidenceClass.RUNTIME_OBSERVED,
                catalog_source="agy_models",
                reasoning_efforts=effort_tuple,
                default_effort=None,
                capabilities={"is_orchestrator_mode": is_orchestrator},
                active_session_state=ObservationState.NOT_EXPOSED,
                observed_at=observed_at,
                evidence_id=evidence_id,
            )
        )

        if effort:
            efforts.append(
                NormalizedEffortRecord(
                    application_id="antigravity",
                    effort=effort,
                    model_id=slug,
                    scope="runtime_catalog",
                    source="agy_models",
                    evidence_class=EvidenceClass.RUNTIME_OBSERVED,
                    is_default=False,
                    supported_efforts=effort_tuple,
                    evidence_id=evidence_id,
                )
            )

    models.sort(key=lambda m: m.model_id)
    efforts.sort(key=lambda e: (e.model_id or "", e.effort))
    orchestrators.sort(key=lambda o: o["orchestrator_id"])
    return models, efforts, orchestrators


def parse_agy_help_efforts(
    help_stdout: str,
    *,
    evidence_id: str,
) -> list[NormalizedEffortRecord]:
    """Extract documented CLI `--effort` options from `agy --help` output."""
    efforts: list[NormalizedEffortRecord] = []
    match = re.search(r"--effort\b[^\n]*\(([^)]+)\)", help_stdout)
    if not match:
        return efforts
    choices = tuple(
        part.strip().lower()
        for part in match.group(1).split("|")
        if part.strip()
    )
    for choice in choices:
        efforts.append(
            NormalizedEffortRecord(
                application_id="antigravity",
                effort=choice,
                model_id=None,
                scope="cli_flag_documented",
                source="agy_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED,
                is_default=False,
                supported_efforts=choices,
                evidence_id=evidence_id,
            )
        )
    return efforts


def parse_codex_bundled_models(
    stdout: str,
    *,
    observed_at: str,
    evidence_id: str,
) -> tuple[list[NormalizedModelRecord], list[NormalizedEffortRecord]]:
    """Parse `codex debug models --bundled` JSON strictly as BUNDLED_CATALOG."""
    payload = json.loads(stdout)
    raw_models = payload.get("models") if isinstance(payload, dict) else payload
    if not isinstance(raw_models, list):
        raise ValueError("Expected models array in codex bundled catalog")

    models: list[NormalizedModelRecord] = []
    efforts: list[NormalizedEffortRecord] = []

    for item in raw_models:
        if not isinstance(item, dict):
            continue
        slug = item.get("slug")
        if not isinstance(slug, str) or not slug.strip():
            continue
        slug = slug.strip()
        display_name = str(item.get("display_name") or slug).strip()
        default_effort = item.get("default_reasoning_level")
        if not isinstance(default_effort, str) or not default_effort.strip():
            default_effort = None
        else:
            default_effort = default_effort.strip().lower()

        supported_raw = item.get("supported_reasoning_levels")
        supported_list: list[str] = []
        if isinstance(supported_raw, list):
            for entry in supported_raw:
                if isinstance(entry, dict) and isinstance(entry.get("effort"), str):
                    supported_list.append(entry["effort"].strip().lower())
                elif isinstance(entry, str) and entry.strip():
                    supported_list.append(entry.strip().lower())
        supported_tuple = tuple(dict.fromkeys(supported_list))

        caps: dict[str, Any] = {}
        if isinstance(item.get("context_window"), int):
            caps["context_window"] = item["context_window"]
        if isinstance(item.get("visibility"), str):
            caps["visibility"] = item["visibility"]
        if isinstance(item.get("supported_in_api"), bool):
            caps["supported_in_api"] = item["supported_in_api"]

        models.append(
            NormalizedModelRecord(
                provider="openai",
                application_id="codex",
                model_id=slug,
                display_name=display_name,
                availability_state=AvailabilityState.BUNDLED_CATALOG,
                evidence_class=EvidenceClass.BUNDLED_CATALOG,
                catalog_source="codex_debug_models_bundled",
                reasoning_efforts=supported_tuple,
                default_effort=default_effort,
                capabilities=caps,
                active_session_state=ObservationState.NOT_EXPOSED,
                observed_at=observed_at,
                evidence_id=evidence_id,
            )
        )

        for eff in supported_tuple:
            efforts.append(
                NormalizedEffortRecord(
                    application_id="codex",
                    effort=eff,
                    model_id=slug,
                    scope="bundled_catalog",
                    source="codex_debug_models_bundled",
                    evidence_class=EvidenceClass.BUNDLED_CATALOG,
                    is_default=(eff == default_effort),
                    supported_efforts=supported_tuple,
                    evidence_id=evidence_id,
                )
            )

    models.sort(key=lambda m: m.model_id)
    efforts.sort(key=lambda e: (e.model_id or "", e.effort))
    return models, efforts
