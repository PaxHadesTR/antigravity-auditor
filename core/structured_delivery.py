"""Antigravity Auditor — structured (MCP-free) result delivery for headless agy sessions.

Headless ``agy -p`` sessions cannot use MCP tools: the CLI auto-denies the permission prompt (verified
2026-11-15). Scheduled primary audits and second-pass verifications therefore return their results as a
single JSON object constrained by ``agy --json-schema``; the control plane parses it and feeds it through
exactly the same server-side handlers the MCP tools use (``auditor_publish_report`` /
``submit_verification_results``), so validation, evidence gates and persistence are unchanged.

Sessions run isolated (``--settings`` denies MCP tools and shell commands) and the payload is validated
twice: against the server's strict schema here, and again by the handler.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from mcp_server import FINDING_ITEM_SCHEMA, VERIFICATION_RESULT_ITEM_SCHEMA, validate_strict_schema

STRUCTURED_DELIVERY_VERSION = "1.0.0"

PRIMARY_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {"type": "array", "items": FINDING_ITEM_SCHEMA, "maxItems": 500},
    },
}

VERIFICATION_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verification_results"],
    "properties": {
        "verification_results": {"type": "array", "items": VERIFICATION_RESULT_ITEM_SCHEMA, "maxItems": 500},
        "verifier_discovered_findings": {"type": "array", "items": FINDING_ITEM_SCHEMA, "maxItems": 100},
    },
}

# Keywords of the server's strict validator that are not standard JSON Schema (or that agy may reject).
_NON_STANDARD = {"format", "nullable"}


class StructuredDeliveryError(ValueError):
    """The agent's answer could not be parsed or failed schema validation."""


def to_agent_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Convert a server strict schema into standard JSON Schema for ``agy --json-schema``.

    ``nullable: true`` becomes a ``["<type>", "null"]`` type union; ``format`` (custom) is dropped. The server
    still validates the parsed payload with the original strict schema.
    """
    def convert(node: Any) -> Any:
        if isinstance(node, list):
            return [convert(n) for n in node]
        if not isinstance(node, dict):
            return node
        out = {k: convert(v) for k, v in node.items() if k not in _NON_STANDARD}
        if node.get("nullable") is True and isinstance(node.get("type"), str):
            out["type"] = [node["type"], "null"]
            if "enum" in out:
                out["enum"] = list(out["enum"]) + [None]
        return out

    return convert(copy.deepcopy(schema))


def write_agent_schema(directory: Path, name: str, schema: dict[str, Any]) -> Path:
    path = Path(directory) / f"{name}.schema.json"
    path.write_text(json.dumps(to_agent_json_schema(schema)), encoding="utf-8")
    return path


def structured_output_from_events(events: Any) -> dict[str, Any] | None:
    """The ``structured_output`` object agy attaches to its final ``result`` event when ``--json-schema``
    is used (already parsed and schema-checked by agy). In long multi-step sessions the plain ``response``
    text can differ from what the agent submitted via its ``finish`` call, so this is authoritative."""
    for event in reversed(list(events or [])):
        if not isinstance(event, dict):
            continue
        result = event.get("result")
        if (event.get("event") or event.get("type")) == "result" and isinstance(result, dict):
            out = result.get("structured_output")
            return out if isinstance(out, dict) else None
    return None


def agent_result_payload(dispatch_result: Any) -> dict[str, Any] | str:
    """Preferred raw payload of a dispatch: agy's structured_output if present, else the response text."""
    structured = structured_output_from_events(getattr(dispatch_result, "events", None))
    return structured if structured is not None else (getattr(dispatch_result, "response_text", "") or "")


def parse_structured_result(text: str | dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Validated payload from an already-parsed object (agy structured_output) or the first complete JSON
    object in ``text``; always checked against the server's strict ``schema``."""
    from model_probes import extract_json_object

    payload = text if isinstance(text, dict) else extract_json_object(text or "")
    if payload is None:
        raise StructuredDeliveryError("The agent did not return a JSON object.")
    try:
        validate_strict_schema(payload, schema, "agent_result")
    except ValueError as exc:
        raise StructuredDeliveryError(f"Agent result failed schema validation: {exc}") from exc
    return payload


# --- prompt adaptation ---------------------------------------------------------------------------------

def _replace_once(text: str, old: str, new: str) -> str:
    """Replace the control-plane line (the first occurrence: it precedes any repository or finding text)."""
    if old not in text:
        raise RuntimeError(f"Structured-delivery prompt adaptation failed: marker not found: {old[:60]!r}")
    return text.replace(old, new, 1)


PRIMARY_STRUCTURED_CONTRACT = """RESULT CONTRACT (STRUCTURED OUTPUT - NO MCP TOOLS):
Do NOT call MCP tools, do NOT write files and do NOT invoke shell commands. MCP tools are disabled in this session.
Your FINAL answer must be ONLY one JSON object of the form {"findings": [ ... ]}; it is validated against an
enforced JSON schema and then submitted by the Auditor control plane on your behalf.
PRECEDENCE: wherever the trusted audit protocol above says to call `auditor_publish_report` or other MCP tools,
this final JSON answer replaces that call in this session. Each finding item must include:"""

PRIMARY_STRUCTURED_RULES = """MANDATORY RESULT RULES:
1. INSPECT ALL RELEVANT FILES FIRST: Inspect all candidate source files from the PRECOMPUTED REPOSITORY FILE MANIFEST using `read_file` before writing the final answer.
2. ONE CONSOLIDATED ANSWER: Return ALL candidate findings across the entire repository in the single final JSON object. If no defects are found, return {"findings": []}.
3. NO PLACEHOLDER PAYLOADS: Items containing placeholder strings (e.g. "dummy", "test", "TODO", "TBD", "N/A", "placeholder", "xxx") or repeated filler are rejected by server-side validation.
4. JSON ONLY: No prose, no Markdown fences, no second JSON object.
5. SYMBOLS ARE CODE IDENTIFIERS: `symbol` must name a function, method or class that exists in a source file. For
   non-code files (Markdown, text, configuration, lock files) set `symbol` to null; never put a file name in `symbol`.
   Findings whose symbol cannot be verified deterministically block finalization of the whole report.
All report files and persistence are recorded deterministically outside the monitored repository by the Auditor control plane.
"""


def adapt_primary_prompt_for_structured_delivery(prompt: str) -> str:
    out = _replace_once(
        prompt,
        "3. MCP DATA EXCHANGE: Use registered MCP tools (`auditor_get_context`, `auditor_publish_report`) to query audit context and submit candidate findings.",
        "3. NO MCP TOOLS: MCP tools are disabled in this session. All audit context you need is provided in this prompt; return your findings as the final JSON answer described below.",
    )
    # rindex: the contract follows the repository manifest / git summaries, which may contain the same words.
    start = out.rindex("FINDING SUBMISSION CONTRACT:")
    end = out.index("- findings: JSON array of finding items. Each item must include:", start)
    end_line = out.index("\n", end) + 1
    out = out[:start] + PRIMARY_STRUCTURED_CONTRACT + "\n" + out[end_line:]
    rules = out.index("MANDATORY PUBLICATION RULES:")
    return out[:rules] + PRIMARY_STRUCTURED_RULES


VERIFICATION_STRUCTURED_CONTRACT = """REQUIRED RESULT CONTRACT (STRUCTURED OUTPUT - NO MCP TOOLS):
Do NOT call MCP tools, do NOT write files and do NOT invoke shell commands. MCP tools are disabled in this session.
Your FINAL answer must be ONLY one JSON object of the form
{"verification_results": [ ... ], "verifier_discovered_findings": [ ... ]}
validated against an enforced JSON schema and submitted by the Auditor control plane on your behalf (with your
runtime-attested conversation and model identity). PRECEDENCE: wherever the trusted verification protocol above
says to call `auditor_get_verification_context` or `auditor_submit_verification`, this prompt's context and your
final JSON answer replace those calls in this session. Provide exactly one verification result per candidate. Each
verification result item must include:
  candidate_finding_id (string), verdict ("CONFIRMED" | "PARTIALLY_CONFIRMED" | "REJECTED" | "UNVERIFIABLE"),
  verified_severity ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"),
  verified_confidence ("CONFIRMED" | "LIKELY" | "SPECULATIVE"),
  technical_rationale (string),
  source_evidence: object with file_path (string), line_start (integer), line_end (integer), symbol (string or null), excerpt (string or null),
  remediation_review (string),
  acceptance_criteria (string).
`verifier_discovered_findings` is optional (use [] if none). JSON only: no prose, no Markdown fences.
Deterministic finalization and persistence will be executed by the Auditor control plane.
"""


def adapt_verification_prompt_for_structured_delivery(prompt: str, audit_run_id: str, verification_run_id: str) -> str:
    out = _replace_once(
        prompt,
        f'1. Call MCP tool `auditor_get_verification_context` with `audit_run_id="{audit_run_id}"` and `verification_run_id="{verification_run_id}"`.',
        "1. Use the candidate claims and snapshot context provided in this prompt (MCP tools are disabled in this session).",
    )
    # rindex: the contract follows the candidate claims, whose text may quote these words.
    start = out.rindex("REQUIRED SUBMISSION CONTRACT:")
    return out[:start] + VERIFICATION_STRUCTURED_CONTRACT
