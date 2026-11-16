"""Sanitized MCP configuration metadata parsers and 17-dimension capability builders."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime_discovery.contracts import (
    CapabilityEntry,
    CapabilityStatus,
    EvidenceClass,
    SanitizedMcpServerRecord,
    TransportType,
    default_mcp_capabilities,
)
from runtime_discovery.redaction import (
    canonical_sanitized_sha256,
    extract_env_var_names,
    extract_header_names,
    extract_safe_hostname,
    is_sensitive_key,
    safe_command_basename,
)
from runtime_discovery.windows_detection import safe_read_text

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]


_AUTH_HEADER_NAMES = frozenset(
    {"authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token"}
)


def classify_transport(
    explicit_type: Any,
    *,
    has_command: bool,
    has_url: bool,
    default_url_transport: TransportType = TransportType.HTTP,
) -> TransportType:
    """Normalize MCP transport classification without guessing unsupported schemes."""
    if isinstance(explicit_type, str) and explicit_type.strip():
        norm = explicit_type.strip().lower().replace("-", "_")
        if norm == "stdio":
            return TransportType.STDIO
        if norm in ("streamable_http", "streamablehttp"):
            return TransportType.STREAMABLE_HTTP
        if norm == "sse":
            return TransportType.SSE
        if norm == "http":
            return TransportType.HTTP
        return TransportType.UNKNOWN
    if has_command and not has_url:
        return TransportType.STDIO
    if has_url and not has_command:
        return default_url_transport
    return TransportType.UNKNOWN


def _detect_auth_configured(
    raw_entry: dict[str, Any],
    header_names: tuple[str, ...],
    env_var_names: tuple[str, ...],
    raw_url: str | None,
) -> bool:
    for h in header_names:
        if h.lower() in _AUTH_HEADER_NAMES or "auth" in h.lower() or "token" in h.lower():
            return True
    for e in env_var_names:
        if is_sensitive_key(e):
            return True
    for key in (
        "bearer_token_env_var",
        "oauth",
        "oauth_client_id",
        "oauth_resource",
        "auth",
        "credentials",
        "token",
    ):
        val = raw_entry.get(key)
        if val not in (None, "", False, {}, []):
            return True
    if raw_url and "@" in raw_url.split("://", 1)[-1].split("/", 1)[0]:
        return True
    return False


def project_sanitized_mcp_server(
    name: str,
    raw_entry: Any,
    *,
    scope: str,
    source_path: str,
    default_url_transport: TransportType = TransportType.HTTP,
    evidence_id: str = "",
) -> SanitizedMcpServerRecord | None:
    """Create a secret-free projection of a single MCP server configuration entry."""
    if not isinstance(raw_entry, dict):
        return None

    cmd_val = raw_entry.get("command")
    cmd_basename = safe_command_basename(cmd_val)
    has_command = bool(cmd_basename)

    raw_url: str | None = None
    for url_key in ("url", "serverUrl", "endpoint", "httpUrl"):
        val = raw_entry.get(url_key)
        if isinstance(val, str) and val.strip():
            raw_url = val.strip()
            break
    # Also handle nested transport object in `codex mcp list --json`
    transport_obj = raw_entry.get("transport")
    explicit_type = raw_entry.get("type") or raw_entry.get("transportType")
    if isinstance(transport_obj, dict):
        if not explicit_type:
            explicit_type = transport_obj.get("type")
        if not cmd_basename and transport_obj.get("command") is not None:
            cmd_basename = safe_command_basename(transport_obj.get("command"))
            has_command = bool(cmd_basename)
        if not raw_url and isinstance(transport_obj.get("url"), str):
            raw_url = transport_obj.get("url").strip()
        env_obj = transport_obj.get("env") or raw_entry.get("env")
        headers_obj = transport_obj.get("http_headers") or transport_obj.get("headers") or raw_entry.get("headers")
        bearer_env = transport_obj.get("bearer_token_env_var") or raw_entry.get("bearer_token_env_var")
    else:
        env_obj = raw_entry.get("env")
        headers_obj = raw_entry.get("headers") or raw_entry.get("http_headers")
        bearer_env = raw_entry.get("bearer_token_env_var")

    has_url = bool(raw_url)
    endpoint_hostname = extract_safe_hostname(raw_url) if raw_url else None
    transport = classify_transport(
        explicit_type,
        has_command=has_command,
        has_url=has_url,
        default_url_transport=default_url_transport,
    )

    env_names = list(extract_env_var_names(env_obj))
    if isinstance(bearer_env, str) and bearer_env.strip():
        env_names.append(bearer_env.strip())
    if isinstance(raw_entry.get("env_vars"), list):
        for item in raw_entry["env_vars"]:
            if isinstance(item, str) and item.strip():
                env_names.append(item.strip())
    env_tuple = tuple(sorted(set(env_names)))

    header_tuple = extract_header_names(headers_obj)
    if isinstance(transport_obj, dict) and isinstance(transport_obj.get("env_http_headers"), dict):
        header_tuple = tuple(sorted(set(header_tuple) | set(transport_obj["env_http_headers"].keys())))
    if isinstance(raw_entry.get("env_http_headers"), dict):
        header_tuple = tuple(sorted(set(header_tuple) | set(raw_entry["env_http_headers"].keys())))

    auth_configured = _detect_auth_configured(raw_entry, header_tuple, env_tuple, raw_url)
    if isinstance(transport_obj, dict) and transport_obj.get("bearer_token_env_var"):
        auth_configured = True

    enabled: bool | None = None
    if isinstance(raw_entry.get("enabled"), bool):
        enabled = raw_entry["enabled"]
    elif isinstance(raw_entry.get("disabled"), bool):
        enabled = not raw_entry["disabled"]

    return SanitizedMcpServerRecord(
        name=str(name),
        transport=transport,
        has_command=has_command,
        command_basename=cmd_basename,
        has_url=has_url,
        endpoint_hostname=endpoint_hostname,
        env_var_names=env_tuple,
        header_names=header_tuple,
        auth_configured=auth_configured,
        scope=scope,
        enabled=enabled,
        source_path=source_path,
        connection_status=CapabilityStatus.CONFIGURED,
        evidence_class=EvidenceClass.CONFIGURED,
        evidence_id=evidence_id,
    )


def parse_json_mcp_config(
    path: Path,
    *,
    root: Path | None,
    scope: str,
    default_url_transport: TransportType = TransportType.HTTP,
    project_filter_path: Path | None = None,
) -> dict[str, Any]:
    """Read and sanitize a JSON MCP config file (never returning raw config contents)."""
    text, err = safe_read_text(path, root=root)
    source_meta: dict[str, Any] = {
        "path": str(path),
        "scope": scope,
        "exists": err not in ("NOT_FOUND",),
        "status": "parsed" if err is None else err.lower(),
        "sanitized_projection_sha256": None,
    }
    if err is not None or text is None:
        return {"source": source_meta, "servers": [], "error": None if err == "NOT_FOUND" else err}

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        source_meta["status"] = "invalid_json"
        return {"source": source_meta, "servers": [], "error": "INVALID_JSON"}

    if not isinstance(parsed, dict):
        source_meta["status"] = "invalid_structure"
        return {"source": source_meta, "servers": [], "error": "INVALID_STRUCTURE"}

    servers: list[SanitizedMcpServerRecord] = []
    mcp_servers = parsed.get("mcpServers")
    if isinstance(mcp_servers, dict):
        for srv_name in sorted(mcp_servers.keys()):
            rec = project_sanitized_mcp_server(
                str(srv_name),
                mcp_servers[srv_name],
                scope=scope,
                source_path=str(path),
                default_url_transport=default_url_transport,
            )
            if rec is not None:
                servers.append(rec)

    # For Claude Code ~/.claude.json, optionally extract ONLY matching project's mcpServers
    if project_filter_path is not None and isinstance(parsed.get("projects"), dict):
        norm_target = str(project_filter_path.resolve()).lower().replace("\\", "/")
        for proj_key, proj_val in parsed["projects"].items():
            if not isinstance(proj_val, dict):
                continue
            norm_key = str(proj_key).rstrip("\\/").lower().replace("\\", "/")
            if norm_key == norm_target and isinstance(proj_val.get("mcpServers"), dict):
                for srv_name in sorted(proj_val["mcpServers"].keys()):
                    rec = project_sanitized_mcp_server(
                        str(srv_name),
                        proj_val["mcpServers"][srv_name],
                        scope="local",
                        source_path=str(path),
                        default_url_transport=default_url_transport,
                    )
                    if rec is not None:
                        servers.append(rec)

    projection = [s.to_dict() for s in servers]
    source_meta["sanitized_projection_sha256"] = canonical_sanitized_sha256(projection)
    return {"source": source_meta, "servers": servers, "error": None}


def parse_codex_toml_mcp_config(
    path: Path,
    *,
    root: Path | None,
    scope: str,
) -> dict[str, Any]:
    """Read and sanitize Codex config.toml without exposing secrets or raw config."""
    text, err = safe_read_text(path, root=root)
    source_meta: dict[str, Any] = {
        "path": str(path),
        "scope": scope,
        "exists": err not in ("NOT_FOUND",),
        "status": "parsed" if err is None else err.lower(),
        "sanitized_projection_sha256": None,
    }
    if err is not None or text is None:
        return {
            "source": source_meta,
            "servers": [],
            "model_config": {},
            "error": None if err == "NOT_FOUND" else err,
        }

    if tomllib is None:
        source_meta["status"] = "toml_parser_unavailable"
        return {
            "source": source_meta,
            "servers": [],
            "model_config": {},
            "error": "TOML_PARSER_UNAVAILABLE",
        }

    try:
        parsed = tomllib.loads(text)
    except Exception:
        source_meta["status"] = "invalid_toml"
        return {"source": source_meta, "servers": [], "model_config": {}, "error": "INVALID_TOML"}

    if not isinstance(parsed, dict):
        source_meta["status"] = "invalid_structure"
        return {"source": source_meta, "servers": [], "model_config": {}, "error": "INVALID_STRUCTURE"}

    servers: list[SanitizedMcpServerRecord] = []
    mcp_servers = parsed.get("mcp_servers")
    if isinstance(mcp_servers, dict):
        for srv_name in sorted(mcp_servers.keys()):
            rec = project_sanitized_mcp_server(
                str(srv_name),
                mcp_servers[srv_name],
                scope=scope,
                source_path=str(path),
                default_url_transport=TransportType.STREAMABLE_HTTP,
            )
            if rec is not None:
                servers.append(rec)

    # Extract ONLY allowlisted non-secret model/effort settings
    model_config: dict[str, Any] = {}
    for key in ("model", "model_reasoning_effort", "model_reasoning_summary", "model_verbosity"):
        val = parsed.get(key)
        if isinstance(val, str) and val.strip():
            model_config[key] = val.strip()

    projection = {
        "servers": [s.to_dict() for s in servers],
        "model_config": model_config,
    }
    source_meta["sanitized_projection_sha256"] = canonical_sanitized_sha256(projection)
    return {
        "source": source_meta,
        "servers": servers,
        "model_config": model_config,
        "error": None,
    }


def parse_codex_mcp_list_json(stdout: str, *, source_label: str = "codex mcp list --json") -> list[SanitizedMcpServerRecord]:
    """Parse output of `codex mcp list --json` into sanitized server projections."""
    data = json.loads(stdout)
    if not isinstance(data, list):
        raise ValueError("Expected JSON list from codex mcp list --json")
    servers: list[SanitizedMcpServerRecord] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        rec = project_sanitized_mcp_server(
            name.strip(),
            item,
            scope="runtime_merged",
            source_path=source_label,
            default_url_transport=TransportType.STREAMABLE_HTTP,
        )
        if rec is not None:
            servers.append(rec)
    servers.sort(key=lambda s: (s.name, s.scope))
    return servers


def build_mcp_section(
    *,
    servers: list[SanitizedMcpServerRecord],
    config_sources: list[dict[str, Any]],
    supported_transports: list[str] | None = None,
    supported_transports_evidence: EvidenceClass = EvidenceClass.UNKNOWN,
    oauth_support: bool | None = None,
    oauth_evidence: EvidenceClass = EvidenceClass.UNKNOWN,
    extra_notes: dict[str, CapabilityEntry] | None = None,
) -> dict[str, Any]:
    """Assemble the normalized MCP section and 17-dimension capability map."""
    caps = default_mcp_capabilities()
    configured_transports = sorted({s.transport.value for s in servers})
    caps["transports_configured"] = CapabilityEntry(
        value=configured_transports,
        status=CapabilityStatus.CONFIGURED if configured_transports else CapabilityStatus.UNKNOWN,
        evidence_class=EvidenceClass.CONFIGURED if configured_transports else EvidenceClass.UNKNOWN,
    ).to_dict()

    if supported_transports is not None:
        caps["transports_supported"] = CapabilityEntry(
            value=sorted(set(supported_transports)),
            status=CapabilityStatus.SUPPORTED,
            evidence_class=supported_transports_evidence,
        ).to_dict()

    if oauth_support is not None:
        caps["oauth_remote_auth_support"] = CapabilityEntry(
            value=oauth_support,
            status=CapabilityStatus.SUPPORTED if oauth_support else CapabilityStatus.UNKNOWN,
            evidence_class=oauth_evidence,
        ).to_dict()

    if extra_notes:
        for dim, entry in extra_notes.items():
            if dim in caps:
                caps[dim] = entry.to_dict()

    all_transports = sorted(set(configured_transports))
    return {
        "configured": len(servers) > 0,
        "transports": all_transports,
        "protocol_versions": [],
        "features": {
            "oauth_remote_auth_configured": any(s.auth_configured for s in servers),
        },
        "capabilities": caps,
        "servers": [s.to_dict() for s in sorted(servers, key=lambda x: (x.scope, x.name))],
        "config_sources": config_sources,
    }
