"""Canonical result envelope adaptation, bounded sizing, redaction, and MCP rendering."""

from __future__ import annotations

import json
import re
from typing import Any

from entitlement_router.privacy import sanitize_for_output
from mcp_server import validate_strict_schema
from mcp_gateway.compatibility import evaluate_feature_compatibility
from mcp_gateway.contracts import (
    CanonicalToolManifest,
    ClientCompatibilityProfile,
    GatewayResultEnvelope,
)


def _bound_payload(
    value: Any,
    *,
    max_items: int,
    max_text_chars: int,
    preserve_keys: frozenset[str] = frozenset({"execution_authorized", "decision_id", "status", "ok", "evidence_refs"}),
) -> tuple[Any, bool]:
    """Deterministically bound arrays and long strings while preserving security-critical fields."""
    truncated = False
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k in preserve_keys:
                out[k] = v
                continue
            bounded_v, sub_trunc = _bound_payload(v, max_items=max_items, max_text_chars=max_text_chars)
            out[k] = bounded_v
            truncated = truncated or sub_trunc
        return out, truncated
    if isinstance(value, list):
        if len(value) > max_items:
            truncated = True
            sliced = value[:max_items]
        else:
            sliced = value
        out_list: list[Any] = []
        for item in sliced:
            bounded_i, sub_trunc = _bound_payload(item, max_items=max_items, max_text_chars=max_text_chars)
            out_list.append(bounded_i)
            truncated = truncated or sub_trunc
        return out_list, truncated
    if isinstance(value, str):
        if len(value) > max_text_chars:
            truncated = True
            marker = f"... [truncated {len(value) - max_text_chars} chars]"
            keep = max(32, max_text_chars - len(marker))
            return value[:keep] + marker, True
        return value, False
    return value, False


_SUMMARY_KEYS = (
    "status",
    "ok",
    "execution_authorized",
    "decision_id",
    "project_key",
    "run_id",
    "verification_run_id",
    "account_count",
    "model_count",
    "count",
    "offset",
    "next_offset",
    "next_cursor",
    "warnings",
    "evidence_refs",
    "billing",
    "roles",
)
# Top-level keys the condensed text view must never alter.
_TEXT_VIEW_PRESERVE_KEYS = frozenset({"execution_authorized", "decision_id", "status", "ok", "evidence_refs", "next_offset", "next_cursor"})
_HASH_LIKE = re.compile(r"^[0-9a-f]{24,}$")
_TEXT_VIEW_STRING_CAPS = (512, 256, 160, 96)
_TEXT_VIEW_ITEM_FIELD_MAX = 96
_TEXT_VIEW_HINT = (
    "Text view condensed to fit the client size limit; structuredContent carries the full schema-bounded result. "
    "Narrow the query with filters, or page with limit/offset where the tool supports it."
)


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ": "), sort_keys=True, default=str)


def _map_unpreserved(data: dict[str, Any], fn: Any) -> dict[str, Any]:
    return {k: (v if k in _TEXT_VIEW_PRESERVE_KEYS else fn(v)) for k, v in data.items()}


def _prune_noise(value: Any, omitted: set[str]) -> Any:
    """Drop empty values and opaque hash strings (still present in structuredContent)."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if v is None or v == "" or v == [] or v == {}:
                continue
            if isinstance(v, str) and _HASH_LIKE.match(v):
                omitted.add(str(k))
                continue
            out[k] = _prune_noise(v, omitted)
        return out
    if isinstance(value, list):
        return [_prune_noise(v, omitted) for v in value]
    return value


def _cap_strings(value: Any, cap: int) -> Any:
    if isinstance(value, dict):
        return {k: _cap_strings(v, cap) for k, v in value.items()}
    if isinstance(value, list):
        return [_cap_strings(v, cap) for v in value]
    if isinstance(value, str) and len(value) > cap:
        return value[:cap] + f"...[+{len(value) - cap} chars]"
    return value


def _drop_long_item_fields(value: Any, max_len: int, omitted: set[str]) -> Any:
    """Inside list items, drop long free-text fields so every item's identity still fits."""
    if isinstance(value, dict):
        return {k: _drop_long_item_fields(v, max_len, omitted) for k, v in value.items()}
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            if isinstance(item, dict):
                kept: dict[str, Any] = {}
                for k, v in item.items():
                    if isinstance(v, str) and len(v) > max_len:
                        omitted.add(str(k))
                    else:
                        kept[k] = _drop_long_item_fields(v, max_len, omitted)
                out.append(kept)
            else:
                out.append(_drop_long_item_fields(item, max_len, omitted))
        return out
    return value


def _iter_lists(value: Any, path: str = "") -> Any:
    if isinstance(value, dict):
        for k, v in value.items():
            if not path and k in _TEXT_VIEW_PRESERVE_KEYS:
                continue
            yield from _iter_lists(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, list):
        yield path, value
        for i, v in enumerate(value):
            yield from _iter_lists(v, f"{path}[{i}]")


def _fit_text_view(tool: CanonicalToolManifest, data: dict[str, Any], max_chars: int, *, structured_truncated: bool) -> str | None:
    """Progressively condense ``data`` until it fits ``max_chars`` (ARCH-09 follow-up).

    Order: compact JSON -> drop empty/hash noise -> cap long strings -> drop long free-text
    fields inside list items -> drop trailing items of the largest list one at a time
    (lists are already bounded to max_items). Every reduction is reported in
    ``text_view`` so the reader knows exactly what the text omits.
    """
    omitted_fields: set[str] = set()
    omitted_items: dict[str, int] = {}
    meta: dict[str, Any] = {"complete": False, "hint": _TEXT_VIEW_HINT}
    if structured_truncated:
        meta["structured_content_truncated"] = True

    def render(body: dict[str, Any]) -> str:
        if omitted_fields:
            meta["omitted_fields"] = sorted(omitted_fields)
        if omitted_items:
            meta["omitted_items"] = dict(sorted(omitted_items.items()))
        return _compact_json({"tool": tool.tool_name, "truncated": True, "text_view": meta, **body})

    body: dict[str, Any] = json.loads(_compact_json(data))
    text = render(body)
    if len(text) <= max_chars:
        return text

    body = _map_unpreserved(body, lambda v: _prune_noise(v, omitted_fields))
    text = render(body)
    if len(text) <= max_chars:
        return text

    for cap in _TEXT_VIEW_STRING_CAPS:
        meta["strings_capped_at"] = cap
        text = render(_map_unpreserved(body, lambda v, c=cap: _cap_strings(v, c)))
        if len(text) <= max_chars:
            return text
    body = _map_unpreserved(body, lambda v: _cap_strings(v, _TEXT_VIEW_STRING_CAPS[-1]))

    body = _map_unpreserved(body, lambda v: _drop_long_item_fields(v, _TEXT_VIEW_ITEM_FIELD_MAX, omitted_fields))
    text = render(body)
    while len(text) > max_chars:
        candidates = [(len(_compact_json(lst)), p, lst) for p, lst in _iter_lists(body) if len(lst) > 1]
        if not candidates:
            return None
        _, path, lst = max(candidates, key=lambda t: (t[0], t[1]))
        lst.pop()
        omitted_items[path] = omitted_items.get(path, 0) + 1
        text = render(body)
    return text


def _render_concise_text(
    tool: CanonicalToolManifest,
    data: dict[str, Any],
    *,
    truncated: bool,
) -> str:
    """Human-readable text for MCP ``content``.

    Full pretty JSON when it fits; otherwise compact JSON; otherwise a condensed view that
    reports exactly what was omitted. Only if even that cannot fit is the minimal summary
    returned. (Previously any oversize payload collapsed straight to the minimal summary, so
    clients that only read ``content`` — e.g. Antigravity — saw no data at all.)
    """
    max_chars = max(512, tool.result_size_policy.max_text_chars)
    if not truncated:
        serialized = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
        if len(serialized) <= max_chars:
            return serialized
        compact = _compact_json(data)
        if len(compact) <= max_chars:
            return compact
    fitted = _fit_text_view(tool, data, max_chars, structured_truncated=truncated)
    if fitted is not None:
        return fitted
    summary: dict[str, Any] = {
        "tool": tool.tool_name,
        "truncated": True,
    }
    for key in _SUMMARY_KEYS:
        if key in data:
            summary[key] = data[key]
    return json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)


class OutputAdapter:
    """Adapts canonical handler output into redacted, schema-validated, client-compatible MCP results."""

    def format_result(
        self,
        *,
        tool: CanonicalToolManifest,
        raw_result: Any,
        profile: ClientCompatibilityProfile,
    ) -> dict[str, Any]:
        if not isinstance(raw_result, dict):
            raise ValueError(
                f"Malformed handler output for '{tool.tool_name}': expected JSON object dict, got {type(raw_result).__name__}"
            )

        sanitized = sanitize_for_output(raw_result)
        compat = evaluate_feature_compatibility(profile)
        eff_max_items = min(tool.result_size_policy.max_items, compat.max_items)
        eff_max_chars = min(tool.result_size_policy.max_text_chars, compat.max_text_chars)

        if tool.output_schema is not None:
            validate_strict_schema(sanitized, tool.output_schema, f"output({tool.tool_name})")

        bounded_data, was_truncated = _bound_payload(
            sanitized,
            max_items=eff_max_items,
            max_text_chars=eff_max_chars,
        )
        if was_truncated and isinstance(bounded_data, dict):
            # If output_schema forbids extra properties, keep schema-clean payload for structuredContent
            # and expose explicit truncation metadata in text/envelope metadata.
            pass

        envelope = GatewayResultEnvelope(
            tool_name=tool.tool_name,
            ok=True,
            summary=f"{tool.tool_name}: ok",
            data=bounded_data,
            truncated=was_truncated,
            evidence_refs=tuple(str(x) for x in bounded_data.get("evidence_refs", []) if isinstance(x, str))[:20],
        )
        text_body = _render_concise_text(tool, envelope.data, truncated=envelope.truncated)

        mcp_result: dict[str, Any] = {
            "content": [{"type": "text", "text": text_body}],
            "isError": False,
        }
        if compat.supports_structured_output:
            mcp_result["structuredContent"] = envelope.data
        if envelope.truncated:
            mcp_result["_gatewayMeta"] = {"truncated": True}
        return mcp_result

    def format_error(
        self,
        *,
        message: str,
        error_code: str,
        details: dict[str, Any] | None = None,
        profile: ClientCompatibilityProfile | None = None,
    ) -> dict[str, Any]:
        payload = sanitize_for_output(
            {
                "error": message,
                "error_code": error_code,
                "details": details or {},
            }
        )
        out: dict[str, Any] = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(payload, ensure_ascii=False),
                }
            ],
            "isError": True,
        }
        if profile is not None and evaluate_feature_compatibility(profile).supports_structured_output:
            out["structuredContent"] = payload
        return out
