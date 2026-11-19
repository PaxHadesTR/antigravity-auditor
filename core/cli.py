from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agentapi import AgentApiAdapter
from db import (
    authorize_execution,
    backup_database,
    check_database_integrity,
    connect,
    ingest_findings,
    initialize,
    record_event,
    recover_stale_runs,
    save_decisions,
    verify_backup_restore,
)
from executor import execute_approved_findings, start_isolated_execution
from mcp_server import main as mcp_serve_main
from mcp_server import register_mcp_server_config
from recovery import (
    check_disk_space,
    compute_repo_fingerprint,
    detect_moved_repositories,
    detect_project_id_for_path,
    discover_antigravity_projects,
    run_health_and_recovery,
)
from review import (
    assert_not_markdown_checkbox,
    generate_review_report,
)
from skills import format_trusted_skill_section, install_global_skills_safely, inventory, load_trusted_skill_content, relevant_skill_instruction, sanitize_skill_inventory_for_model
from telemetry import StructuredAuditLogger
from model_policy import (
    POLICY_VERSION,
    ExecutionIntent,
    ModelId,
    ModelRoutingRequest,
    RoutingStatus,
    TaskType,
    route_model,
)
from model_registry import RoutingTableError, approved_model_slugs, current_host_app, discover_dispatch_backends, get_active_routing_table
from model_budget import ArgonBudgetConfig, ModelBudgetTracker, build_minimized_evidence_package
from model_attestation import attest_conversation_model
from agy_adapter import AntigravityCliAdapter, PRIMARY_AUDIT_TIMEOUT_SECONDS
from runtime_discovery import (
    RuntimeDiscoveryCoordinator,
    render_application_inventory_markdown,
)
from entitlement_router.cli_handlers import (
    execute_routing_command,
    render_route_plan_text,
    render_routing_inspect_text,
)
from verification import (
    VerificationWorker,
    _is_link_or_junction_within_repo,
    build_verification_prompt,
    compute_clean_working_tree_hash,
    configure_verifier_sidecar,
    finalize_verified_report,
    generate_all_verifier_sidecars,
    get_quality_report,
    get_verification_status,
    get_verifier_worker_status,
    is_forbidden_evidence_path,
    recover_verification_job,
    submit_verification_results,
    transition_audit_run_status,
)

ROOT = Path(os.environ.get("ANTIGRAVITY_AUDITOR_HOME", str(Path(__file__).resolve().parents[1]))).resolve()
APP_HOME = ROOT
DB_PATH = Path(os.environ.get("ANTIGRAVITY_AUDITOR_DB", str(APP_HOME / "database" / "auditor.db"))).resolve()
JSONL_PATH = APP_HOME / "logs" / "audit-events.jsonl"
GEMINI_HOME = Path(os.environ.get("ANTIGRAVITY_GEMINI_HOME", str(Path.home() / ".gemini"))).resolve()
CONFIG_PATH = Path(os.environ.get("ANTIGRAVITY_CONFIG_PATH", str(GEMINI_HOME / "config" / "config.json"))).resolve()
MCP_CONFIG_PATH = Path(os.environ.get("ANTIGRAVITY_MCP_CONFIG_PATH", str(GEMINI_HOME / "config" / "mcp_config.json"))).resolve()
SIDECAR_ROOT = Path(os.environ.get("ANTIGRAVITY_SIDECAR_ROOT", str(GEMINI_HOME / "config" / "sidecars"))).resolve()

LOGGER = StructuredAuditLogger(app_home=APP_HOME)


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower()).strip("-")
    if not value:
        raise ValueError("Project key must contain letters or numbers.")
    return value[:48]


SAFE_READONLY_GIT_COMMANDS: frozenset[tuple[str, ...]] = frozenset({
    ("rev-parse", "HEAD"),
    ("rev-parse", "--abbrev-ref", "HEAD"),
    ("rev-parse", "--show-toplevel"),
    ("branch", "--show-current"),
    ("status", "--porcelain"),
    ("status", "--porcelain", "-uall"),
    ("diff", "--stat"),
    ("diff", "--stat", "--cached"),
    ("diff", "--name-status"),
    ("diff", "--name-status", "--cached"),
    ("log", "-1", "--format=%H %s"),
    ("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
})


def safe_git_query(repo: Path, *args: str) -> str:
    """Execute allowlisted read-only git queries with shell=False and strict validation."""
    if not isinstance(repo, Path):
        repo = Path(repo)
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError(f"Repository path is not a valid directory: {repo}")

    tuple_args = tuple(args)
    if tuple_args not in SAFE_READONLY_GIT_COMMANDS:
        raise ValueError(f"Disallowed git command: git {' '.join(args)}. Allowed read-only queries only.")

    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=20,
            shell=False,
            cwd=str(repo),
            encoding="utf-8",
            errors="replace",
        )
        if "-z" in args:
            return result.stdout if result.returncode == 0 else ""
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def git_value(repo: Path, *args: str) -> str:
    return safe_git_query(repo, *args)


MAX_MANIFEST_ENTRIES: int = 500
MAX_MANIFEST_BYTES: int = 48 * 1024  # 48 KB (49,152 bytes)

KNOWN_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".tiff", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".dmg",
    ".class", ".jar", ".war", ".pyc", ".pyo", ".pyd",
    ".o", ".obj", ".a", ".lib",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
})


def generate_repo_file_manifest(repo: Path) -> dict[str, Any]:
    """Deterministically enumerate repository files via allowlisted git ls-files without mutating repo or reading content.

    Invariants:
    - shell=False, explicit repo cwd and timeout.
    - Parse NUL-separated paths safely.
    - Normalize repository-relative paths, reject absolute paths and '..' traversal.
    - Verify entries resolve inside repository root and do not follow symlinks/junctions.
    - Exclude .git internals, .antigravity-audit internal state, and git-ignored files.
    - Exclude known credential and secret files from model-facing manifest.
    - Detect unsupported/binary files by extension without reading content.
    - Never read file content.
    - Bounded: max 500 entries, max 48 KB serialized manifest content.
    - If truncated, explicitly mark repository inspection coverage as incomplete.
    """
    if not isinstance(repo, Path):
        repo = Path(repo)
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError(f"Repository path is not a valid directory: {repo}")

    raw_output = safe_git_query(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    raw_paths = [p for p in raw_output.split("\0") if p]

    total_discovered = 0
    excluded_sensitive_count = 0
    unsupported_binary_count = 0
    is_truncated = False
    entries: list[dict[str, Any]] = []
    current_serialized_bytes = 0

    for raw_path in raw_paths:
        # Reject absolute paths or Windows drive letters
        if raw_path.startswith(("/", "\\")):
            continue
        if len(raw_path) > 1 and raw_path[1] == ":" and raw_path[0].isalpha():
            continue

        # Normalize repository-relative paths
        norm_path = raw_path.replace("\\", "/").strip()
        if norm_path.startswith("./"):
            norm_path = norm_path[2:]
        norm_path = norm_path.lstrip("/")
        if not norm_path:
            continue

        parts = Path(norm_path).parts
        # Reject '..' traversal
        if not parts or ".." in parts:
            continue

        # Exclude .git internals and internal auditor state
        if any(part in (".git", ".antigravity-audit") for part in parts):
            continue

        entry_path = repo / norm_path
        # Do not follow symlinks or junctions
        if _is_link_or_junction_within_repo(repo, entry_path):
            continue

        # Verify entry resolves strictly inside repository root
        try:
            resolved_entry = entry_path.resolve()
            resolved_entry.relative_to(repo)
        except (ValueError, OSError):
            continue

        # Verify it is a regular file and get size without reading content
        try:
            if not entry_path.is_file():
                continue
            size_bytes = entry_path.stat().st_size
        except (OSError, ValueError):
            continue

        total_discovered += 1

        # Exclude sensitive and credential files
        if is_forbidden_evidence_path(norm_path):
            excluded_sensitive_count += 1
            continue

        ext = Path(norm_path).suffix.lower()
        file_type = ext if ext else "unknown"

        # Detect unsupported/binary files by extension without reading content
        if ext in KNOWN_BINARY_EXTENSIONS:
            unsupported_binary_count += 1
            continue

        # Candidate entry
        entry_line = f"- relative_path: {norm_path} | file_size_bytes: {size_bytes} | file_type: {file_type}\n"
        line_bytes = len(entry_line.encode("utf-8"))

        # Enforce bounds: max 500 entries, max 48 KB serialized manifest content
        # Reserve 1500 bytes for headers, rules, warnings, and footers
        if len(entries) >= MAX_MANIFEST_ENTRIES or (current_serialized_bytes + line_bytes + 1500) > MAX_MANIFEST_BYTES:
            is_truncated = True
            continue

        entries.append({
            "relative_path": norm_path,
            "file_size_bytes": size_bytes,
            "file_type": file_type,
        })
        current_serialized_bytes += line_bytes

    coverage_status = "INCOMPLETE (MANIFEST TRUNCATED)" if is_truncated else "COMPLETE"
    return {
        "total_discovered": total_discovered,
        "included_count": len(entries),
        "excluded_sensitive_count": excluded_sensitive_count,
        "unsupported_binary_count": unsupported_binary_count,
        "is_truncated": is_truncated,
        "coverage_status": coverage_status,
        "entries": entries,
    }


def format_repo_file_manifest_section(manifest: dict[str, Any]) -> str:
    """Format precomputed repository file manifest as a clearly delimited prompt section."""
    total = manifest.get("total_discovered", 0)
    included = manifest.get("included_count", len(manifest.get("entries", [])))
    sensitive = manifest.get("excluded_sensitive_count", 0)
    binary = manifest.get("unsupported_binary_count", 0)
    is_truncated = manifest.get("is_truncated", False)
    coverage = "INCOMPLETE (MANIFEST TRUNCATED)" if is_truncated else "COMPLETE"
    trunc_status = "TRUNCATED" if is_truncated else "NOT TRUNCATED"

    lines = [
        "=== PRECOMPUTED REPOSITORY FILE MANIFEST ===",
        "# Deterministic repository file enumeration precomputed by the Python control plane.",
        f"# TOTAL_DISCOVERED_FILES: {total}",
        f"# INCLUDED_FILES: {included}",
        f"# EXCLUDED_SENSITIVE_FILES: {sensitive}",
        f"# UNSUPPORTED_BINARY_FILES: {binary}",
        f"# TRUNCATION_STATUS: {trunc_status}",
        f"# REPOSITORY_COVERAGE: {coverage}",
        "",
        "DISCOVERY & INSPECTION RULES:",
        "1. These paths were enumerated by the deterministic control plane.",
        "2. The model must use exact relative paths with supported read-only `read_file`.",
        "3. Directory enumeration is unnecessary.",
        "4. Shell and terminal commands are forbidden.",
        "5. Git commands are forbidden.",
        "6. Subagent delegation for repository discovery is forbidden.",
        "7. Inspect source files listed in the manifest.",
        "8. Do not inspect excluded sensitive files.",
        "9. If the manifest is truncated, report incomplete coverage.",
    ]

    if is_truncated:
        lines.extend([
            "",
            "WARNING: The repository file manifest was truncated because the repository exceeds manifest limits.",
            "Repository inspection coverage is INCOMPLETE. You MUST report incomplete coverage in your final audit findings.",
        ])

    lines.extend([
        "",
        "MANIFEST ENTRIES:",
    ])

    for entry in manifest.get("entries", []):
        rpath = entry.get("relative_path", "")
        size = entry.get("file_size_bytes", 0)
        ftype = entry.get("file_type", "")
        lines.append(f"- relative_path: {rpath} | file_size_bytes: {size} | file_type: {ftype}")

    lines.append("=== END PRECOMPUTED REPOSITORY FILE MANIFEST ===")
    return "\n".join(lines)


def get_precomputed_repo_metadata(repo: Path) -> dict[str, Any]:
    """Precompute read-only git metadata using allowlisted deterministic queries."""
    if not isinstance(repo, Path):
        repo = Path(repo)
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError(f"Repository path is not a valid directory: {repo}")

    head_commit = safe_git_query(repo, "rev-parse", "HEAD")
    branch = (
        safe_git_query(repo, "branch", "--show-current")
        or safe_git_query(repo, "rev-parse", "--abbrev-ref", "HEAD")
        or "HEAD"
    )
    porcelain_status = safe_git_query(repo, "status", "--porcelain")
    is_clean = (porcelain_status == "")
    staged_summary = safe_git_query(repo, "diff", "--stat", "--cached")
    unstaged_summary = safe_git_query(repo, "diff", "--stat")
    untracked_summary = safe_git_query(repo, "status", "--porcelain", "-uall")
    manifest = generate_repo_file_manifest(repo)

    return {
        "head_commit": head_commit,
        "branch": branch,
        "is_clean": is_clean,
        "porcelain_status": porcelain_status,
        "staged_summary": staged_summary or "(none)",
        "unstaged_summary": unstaged_summary or "(none)",
        "untracked_summary": untracked_summary or "(none)",
        "manifest": manifest,
        "file_manifest": manifest,
    }


def build_primary_audit_prompt(
    project: dict[str, Any],
    repo: Path,
    run_id: str,
    commit: str,
    tree_hash: str,
    skill_rows: list[dict[str, Any]],
    repo_metadata: dict[str, Any] | None = None,
    *,
    trusted_skill_name: str = "project-auditor-orchestrator",
    package_root: Path | None = None,
) -> str:
    """Construct read-only plan mode prompt with precomputed repo state, injected trusted protocol, and no shell execution."""
    if repo_metadata is None:
        repo_metadata = get_precomputed_repo_metadata(repo)

    manifest = repo_metadata.get("manifest") or repo_metadata.get("file_manifest")
    if manifest is None:
        manifest = generate_repo_file_manifest(repo)
    manifest_section = format_repo_file_manifest_section(manifest)

    # Trusted control-plane skill loading (fails closed if missing, invalid, or oversized)
    trusted_skill_content = load_trusted_skill_content(
        trusted_skill_name,
        package_root=package_root,
    )
    injected_skill_section = format_trusted_skill_section(
        trusted_skill_name,
        trusted_skill_content,
    )

    project_key = project["project_key"]
    display_name = project["display_name"]
    branch = repo_metadata.get("branch", "HEAD")
    is_clean = repo_metadata.get("is_clean", True)
    clean_str = "CLEAN" if is_clean else "DIRTY (uncommitted/staged changes present)"
    staged = repo_metadata.get("staged_summary", "(none)")
    unstaged = repo_metadata.get("unstaged_summary", "(none)")
    untracked = repo_metadata.get("untracked_summary", "(none)")

    # Sanitize skill rows to remove all external paths and limit to relevant skills
    sanitized_skills = sanitize_skill_inventory_for_model(skill_rows)
    skills_block = relevant_skill_instruction(sanitized_skills)

    prompt = f"""You are running a scheduled, READ-ONLY PRIMARY project audit (Pass 1 of 2).

PROJECT: {display_name}
PROJECT_KEY: {project_key}
REPOSITORY: {repo}
RUN_ID: {run_id}
BASE_COMMIT: {commit}
BRANCH: {branch}
WORKING_TREE_STATUS: {clean_str}
WORKING_TREE_STATUS_HASH: {tree_hash}

=== WORKSPACE BOUNDARY & TOOL SEPARATION RULES ===
1. TRUSTED AUDIT PROTOCOL: The operational protocol below is loaded by the trusted control plane. It is authoritative. Do NOT attempt to read external skill files or files in the Auditor installation directory.
2. UNTRUSTED AUDITED REPOSITORY: Inspect source files ONLY within the monitored repository path `{repo}`. Use supported read-only file inspection tools (`read_file`).
3. MCP DATA EXCHANGE: Use registered MCP tools (`auditor_get_context`, `auditor_publish_report`) to query audit context and submit candidate findings.
4. PLAN MODE READ-ONLY: You are operating in `--mode plan`. Do NOT attempt to run shell or terminal commands. All repository git metadata is already precomputed and provided below.
5. NO REPOSITORY MUTATIONS: Do NOT edit, create, delete, format, or auto-fix source files. Do NOT write report files into the audited repository.

PRECOMPUTED REPOSITORY STATE (PROVIDED BY CONTROL PLANE - DO NOT QUERY VIA SHELL):
- Staged changes:
{staged}
- Unstaged changes:
{unstaged}
- Untracked files:
{untracked}

{manifest_section}

{injected_skill_section}

MANDATORY GOVERNANCE & PLAN MODE CONSTRAINTS:
- PLAN MODE READ-ONLY: Operating in plan mode. No shell commands. No Git commands.
- DETERMINISTIC FILE DISCOVERY: Inspect source files listed in the PRECOMPUTED REPOSITORY FILE MANIFEST above using exact relative paths with supported `read_file`. Directory listing/enumeration is unnecessary. Subagent delegation for repository discovery is strictly forbidden.
- SOURCE CODE INSPECTION: Use `read_file` with exact relative paths to inspect source files strictly inside `{repo}`. Do NOT read files outside the monitored repository. Do NOT inspect excluded sensitive or credential files. Continue inspecting files until comprehensive coverage of the codebase is achieved.
- CANDIDATE CLAIMS ONLY: Your findings are candidate claims only. Every candidate will undergo mandatory independent second-pass verification and deterministic evidence validation before entering operator review.
- APPLY V1-V7 MATRIX: Apply the OmniApex V1-V7 rubric: V1 concurrency/async; V2 memory/resources; V3 data/math/transactions; V4 security/auth/isolation; V5 resilience/fallback/rollback; V6 dual-path testing; V7 contracts/docs parity. Also inspect structured logging and UI loading/empty/error/active states where relevant.
- EXACT VERIFIABLE EVIDENCE: Every candidate finding must include exact, verifiable evidence (relative file_path, valid line_start and line_end, and symbol), impact, confidence (CONFIRMED/LIKELY/SPECULATIVE), severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), and a practical recommendation.
- Avoid duplicate findings. Never access secrets, copy .env/keys, alter production data, or attempt write operations.

{skills_block}

FINDING SUBMISSION CONTRACT:
Do NOT write files into the target repository. Do NOT invoke shell commands.
To submit candidate findings, invoke the MCP tool `auditor_publish_report` with:
- project_key: "{project_key}"
- run_id: "{run_id}"
- findings: JSON array of finding items. Each item must include:
  finding_id (stable string), fingerprint (stable string), title, category, severity, confidence, file_path (relative string), symbol (string or null), line_start (integer), line_end (integer), evidence, impact, recommendation.

FIELD SPECIFICATIONS & ALLOWED ENUM VALUES:
- finding_id: Stable alphanumeric identifier unique within this run (e.g. "SEC-SQLI-001").
- fingerprint: Stable deduplication key based on root cause (e.g. "sqli-user-store-query").
- title: Concise, descriptive title of the specific defect (must not be empty or placeholder).
- category: Defect category string matching the V1-V7 rubric (e.g. "INJECTION", "SECURITY", "CONCURRENCY", "DATA_INTEGRITY").
- severity: Allowed enum values: "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO".
- confidence: Allowed enum values: "CONFIRMED", "LIKELY", "SPECULATIVE".
- file_path: Exact repository-relative path matching a file in the PRECOMPUTED REPOSITORY FILE MANIFEST (e.g. "src/user_store.py"), or null if repository-wide.
- symbol: Name of affected function, method, class, or symbol (e.g. "authenticate_user"), or null.
- line_start: 1-based starting line number (integer >= 1) in file_path, or null if repo-wide.
- line_end: 1-based ending line number (integer >= line_start) in file_path, or null if repo-wide.
- evidence: Verbatim source code excerpt demonstrating the vulnerability at the exact line range.
- impact: Concrete technical, security, and operational impact of the vulnerability.
- recommendation: Specific, safe, and actionable remediation guidance with code examples.

COMPLETE VALID FINDING EXAMPLE:
{{
  "finding_id": "SEC-SQLI-001",
  "fingerprint": "sqli-user-store-authenticate",
  "title": "SQL Injection in User Authentication Query",
  "category": "INJECTION",
  "severity": "CRITICAL",
  "confidence": "CONFIRMED",
  "file_path": "src/user_store.py",
  "symbol": "authenticate_user",
  "line_start": 42,
  "line_end": 45,
  "evidence": "query = f\"SELECT * FROM users WHERE username = '{{username}}' AND password = '{{password}}'\"\ncursor.execute(query)",
  "impact": "Unauthenticated attackers can bypass authentication and extract or modify user credentials via arbitrary SQL injection.",
  "recommendation": "Use parameterized queries with bound placeholders instead of raw string interpolation: cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))"
}}

MANDATORY PUBLICATION RULES:
1. INSPECT ALL RELEVANT FILES BEFORE PUBLISHING: Inspect all candidate source files from the PRECOMPUTED REPOSITORY FILE MANIFEST using `read_file` before making any publication call. Do not submit prematurely after reading only one file.
2. SINGLE CONSOLIDATED PUBLICATION: Submit ALL identified candidate findings across the entire repository in ONE consolidated call to `auditor_publish_report`. If no defects are found, submit `findings: []`.
3. NOT A PROBE OR DISCOVERY TOOL: `auditor_publish_report` is NOT a schema-discovery, testing, or connectivity probe tool. The schema is fully specified above. Never invoke it with test, dummy, or exploratory arguments.
4. NO PLACEHOLDER PAYLOADS: Submissions containing placeholder strings (e.g. "dummy", "test", "TODO", "TBD", "N/A", "placeholder", "xxx") or repeated filler characters/tokens will be rejected immediately by server-side validation.
5. NO PARTIAL OR INCREMENTAL REPLACEMENTS: Do NOT publish a partial batch intending to submit another later. A submission locks the audit run for second-pass verification; any subsequent publication with a different payload will be rejected as an idempotency conflict.
If no defects are found, submit an empty array `[]` via `auditor_publish_report`.
All report files and persistence will be recorded deterministically outside the monitored repository by the Auditor control plane.
"""
    return prompt


def working_tree_hash(repo: Path) -> str:
    """Fingerprint tracked diffs plus safe untracked files without storing their contents."""
    return compute_clean_working_tree_hash(repo)


def ensure_json_object(path: Path) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return {}
    raw_text = path.read_text(encoding="utf-8-sig").strip()
    if not raw_text:
        return {}
    try:
        value = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"Expected a JSON object in {path}; left unchanged.")
    return value


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def copy_tree_no_overwrite(source: Path, destination: Path) -> list[str]:
    copied: list[str] = []
    if not source.is_dir():
        return copied
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = destination / item.name
        if target.exists():
            continue
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)
        copied.append(str(target))
    return copied


def resolve_agentapi_command(prompt: str) -> list[str]:
    """Resolve Antigravity agentapi invocation safely on Windows without shell=True."""
    adapter = AgentApiAdapter()
    try:
        return adapter.build_command(prompt)
    except FileNotFoundError:
        exe = os.environ.get("ANTIGRAVITY_AGENTAPI_EXE", "").strip()
        if exe:
            return [exe, "new-conversation", prompt]
        return ["agentapi", "new-conversation", prompt]


def _windows_task_in_use() -> bool:
    from weekly_scheduler import uses_windows_task

    return uses_windows_task(APP_HOME)


def register(args: argparse.Namespace) -> None:
    key = slug(args.key)
    repo = Path(args.path).expanduser().resolve()
    if not repo.is_dir():
        raise RuntimeError(f"Project path does not exist: {repo}")
    top_level = git_value(repo, "rev-parse", "--show-toplevel")
    if not top_level:
        raise RuntimeError(
            "The selected path is not inside a Git repository. Register the repository root or a folder inside it."
        )
    root = Path(top_level).resolve()
    repo_fp = compute_repo_fingerprint(root)

    project_id = (args.project_id or "").strip()
    if not project_id:
        detected = detect_project_id_for_path(root)
        project_id = detected or "PENDING"

    health = "PENDING_PROJECT_ID" if project_id in ("PENDING", "UNKNOWN") else "HEALTHY"
    sidecar_id = f"{key}-audit"
    sidecar_dir = SIDECAR_ROOT / sidecar_id
    sidecar_file = sidecar_dir / "sidecar.json"
    python_exe = sys.executable
    sidecar = {
        "description": f"Scheduled read-only audit dispatcher for {args.name or root.name}",
        "builtin": "schedule",
        "args": [args.cron, python_exe, str(ROOT / "core" / "cli.py"), "scheduled-audit", "--project", key],
        "restart_policy": "always",
        "display_name": f"{args.name or root.name} Audit",
    }

    if project_id not in ("PENDING", "UNKNOWN") and not _windows_task_in_use():
        if sidecar_file.exists():
            try:
                existing_sidecar = json.loads(sidecar_file.read_text(encoding="utf-8-sig"))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Existing Sidecar JSON is invalid; left unchanged: {sidecar_file}") from exc
            if existing_sidecar != sidecar:
                raise RuntimeError(
                    f"Sidecar already exists with different settings: {sidecar_file}. Back it up or rename it before retrying."
                )

        config = ensure_json_object(CONFIG_PATH)
        sidecars = config.setdefault("sidecars", {})
        if not isinstance(sidecars, dict):
            raise RuntimeError("config.json 'sidecars' value is not an object; left unchanged.")
        expected = {"enabled": True, "projectId": project_id}
        current = sidecars.get(sidecar_id)
        if current is not None and current != expected:
            raise RuntimeError(f"config.json already has a different '{sidecar_id}' entry. It was not overwritten.")

    with connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO projects(
                project_key, display_name, repo_path, antigravity_project_id,
                schedule_cron, repo_fingerprint, health_status
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_key) DO UPDATE SET
                display_name=excluded.display_name,
                repo_path=excluded.repo_path,
                antigravity_project_id=excluded.antigravity_project_id,
                schedule_cron=excluded.schedule_cron,
                repo_fingerprint=excluded.repo_fingerprint,
                health_status=excluded.health_status,
                enabled=1,
                updated_at=CURRENT_TIMESTAMP""",
            (key, args.name or root.name, str(root), project_id, args.cron, repo_fp, health),
        )
        record_event(
            conn,
            "PROJECT_REGISTERED",
            project_key=key,
            details={
                "repo_path": str(root),
                "antigravity_project_id": project_id,
                "schedule_cron": args.cron,
                "repo_fingerprint": repo_fp,
                "health_status": health,
            },
            jsonl_path=JSONL_PATH,
        )
        conn.commit()

    if args.copy_omniapex_rules:
        source = Path.home() / ".gemini" / "universal-kit" / ".agents" / "rules"
        bundled = ROOT / "integrations" / "omniapex" / ".agents" / "rules"
        source_rules = source if source.is_dir() and any(source.glob("*.md")) else bundled
        if source_rules.is_dir():
            target_dir = root / ".agents" / "rules"
            target_dir.mkdir(parents=True, exist_ok=True)
            for rule in source_rules.glob("*.md"):
                target = target_dir / rule.name
                if not target.exists():
                    shutil.copy2(rule, target)
                elif target.read_bytes() != rule.read_bytes():
                    conflict = target_dir / f"{rule.stem}.omniapex-imported{rule.suffix}"
                    if not conflict.exists():
                        shutil.copy2(rule, conflict)

    from weekly_scheduler import uses_windows_task

    if project_id not in ("PENDING", "UNKNOWN") and uses_windows_task(APP_HOME):
        LOGGER.console(
            f"Registered: {key}\nRepository: {root}\nProject ID: {project_id}\n"
            "Weekly audit: the Windows scheduled task (cli.py schedule status) audits every enabled project."
        )
    elif project_id not in ("PENDING", "UNKNOWN"):
        # Both files were validated above and are written atomically; registration is idempotent, so a
        # failure here leaves a state that a plain re-run of `register` completes.
        try:
            if not sidecar_file.exists():
                write_json_atomic(sidecar_file, sidecar)
            config = ensure_json_object(CONFIG_PATH)
            sidecars = config.setdefault("sidecars", {})
            sidecars[sidecar_id] = {"enabled": True, "projectId": project_id}
            write_json_atomic(CONFIG_PATH, config)
        except OSError as exc:
            raise RuntimeError(
                f"Project '{key}' was saved, but its Sidecar registration failed ({exc}). "
                "Fix the cause and re-run the same `register` command to complete it."
            ) from exc
        LOGGER.console(
            f"Registered: {key}\nRepository: {root}\nProject ID: {project_id}\nSidecar: {sidecar_file}\nRestart Antigravity to load the Sidecar."
        )
    else:
        LOGGER.console(
            f"Registered (pending Project ID): {key}\nRepository: {root}\nSidecar registration deferred until --project-id is supplied."
        )


MODELS_SYNC_SIDECAR_ID = "auditor-models-sync"


def schedule_models_sync(*, project_key: str, cron: str = "30 3 * * 1", remove: bool = False) -> dict[str, Any]:
    """Create (or remove) the Antigravity Sidecar that runs `models sync --probe --propose` on a schedule.

    A Sidecar is attached to an Antigravity project, so a registered project with a known Project ID is
    required. The Sidecar only creates proposals; approving a routing table stays human-only."""
    sidecar_dir = SIDECAR_ROOT / MODELS_SYNC_SIDECAR_ID
    sidecar_file = sidecar_dir / "sidecar.json"
    config = ensure_json_object(CONFIG_PATH)
    sidecars = config.setdefault("sidecars", {})
    if not isinstance(sidecars, dict):
        raise RuntimeError("config.json 'sidecars' value is not an object; left unchanged.")

    if remove:
        removed = []
        if sidecars.pop(MODELS_SYNC_SIDECAR_ID, None) is not None:
            write_json_atomic(CONFIG_PATH, config)
            removed.append(str(CONFIG_PATH))
        if sidecar_file.exists():
            sidecar_file.unlink()
            removed.append(str(sidecar_file))
            try:
                sidecar_dir.rmdir()
            except OSError:
                pass
        return {"status": "REMOVED" if removed else "NOT_PRESENT", "changed": removed}

    with connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT antigravity_project_id FROM projects WHERE project_key=?", (project_key,)
        ).fetchone()
    if not row:
        raise RuntimeError(f"Project '{project_key}' is not registered.")
    project_id = str(row["antigravity_project_id"] or "").strip()
    if not project_id or project_id in ("PENDING", "UNKNOWN"):
        raise RuntimeError(f"Project '{project_key}' has no Antigravity Project ID; register it with --project-id first.")

    sidecar = {
        "description": "Weekly model catalogue sync, probes and routing-table proposal for Antigravity Auditor",
        "builtin": "schedule",
        "args": [cron, sys.executable, str(ROOT / "core" / "cli.py"), "models", "sync", "--probe", "--propose"],
        "restart_policy": "always",
        "display_name": "Antigravity Auditor Model Sync",
    }
    expected_entry = {"enabled": True, "projectId": project_id}
    if sidecar_file.exists():
        try:
            existing = json.loads(sidecar_file.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Existing Sidecar JSON is invalid; left unchanged: {sidecar_file}") from exc
        if existing != sidecar:
            raise RuntimeError(f"Sidecar already exists with different settings: {sidecar_file}. Remove it first (--remove).")
    current = sidecars.get(MODELS_SYNC_SIDECAR_ID)
    if current is not None and current != expected_entry:
        raise RuntimeError(f"config.json already has a different '{MODELS_SYNC_SIDECAR_ID}' entry. Remove it first (--remove).")
    changed = []
    if not sidecar_file.exists():
        write_json_atomic(sidecar_file, sidecar)
        changed.append(str(sidecar_file))
    if current is None:
        sidecars[MODELS_SYNC_SIDECAR_ID] = expected_entry
        write_json_atomic(CONFIG_PATH, config)
        changed.append(str(CONFIG_PATH))
    return {
        "status": "SCHEDULED" if changed else "UNCHANGED",
        "sidecar": MODELS_SYNC_SIDECAR_ID,
        "cron": cron,
        "project_key": project_key,
        "changed": changed,
        "note": "Restart Antigravity to load a new Sidecar.",
    }


def sync_inventory(project_key: str | None = None) -> list[dict[str, str]]:
    repo = None
    if project_key:
        with connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT repo_path FROM projects WHERE project_key=?",
                (project_key,),
            ).fetchone()
        if not row:
            raise RuntimeError(f"Unknown project: {project_key}")
        repo = Path(row["repo_path"])
    rows = inventory(repo, project_key=project_key)
    scopes_to_replace = {"global", "universal-kit-source"}
    if project_key:
        scopes_to_replace.add(f"workspace:{project_key}")
    with connect(DB_PATH) as conn:
        for scope_name in scopes_to_replace:
            conn.execute("DELETE FROM skill_inventory WHERE scope=?", (scope_name,))
        conn.executemany(
            """INSERT OR REPLACE INTO skill_inventory(scope, skill_name, path, sha256, description)
               VALUES(?, ?, ?, ?, ?)""",
            [(r["scope"], r["name"], r["path"], r["sha256"], r["description"]) for r in rows],
        )
        conn.commit()
    return rows


def dispatch(
    project_key: str, *, stale_timeout_seconds: int | None = None, supersede_run_id: str | None = None,
    manual: bool = False,
) -> dict[str, Any] | None:
    recover_stale_runs(
        DB_PATH,
        project_key=project_key,
        stale_timeout_seconds=stale_timeout_seconds,
        jsonl_path=JSONL_PATH,
    )
    moved = detect_moved_repositories(DB_PATH, project_key=project_key, jsonl_path=JSONL_PATH)
    if moved and moved[0]["health_status"] == "MOVED_OR_MISSING":
        raise RuntimeError(f"Cannot dispatch audit for '{project_key}': {moved[0]['reason']}")

    with connect(DB_PATH) as conn:
        project = conn.execute(
            "SELECT * FROM projects WHERE project_key=? AND enabled=1",
            (project_key,),
        ).fetchone()
        if not project:
            raise RuntimeError(f"Project not found or disabled: {project_key}")
        if project["antigravity_project_id"] in ("PENDING", "UNKNOWN", ""):
            raise RuntimeError(f"Project '{project_key}' has pending Antigravity Project ID; register with --project-id first.")

        active = conn.execute(
            """SELECT run_id, status FROM audit_runs
               WHERE project_key=? AND status IN (
                   'PREFLIGHT','PRIMARY_AUDIT_RUNNING','DISPATCHED','ANALYZING',
                   'VERIFICATION_PENDING','VERIFICATION_DISPATCHING','VERIFICATION_RUNNING',
                   'EVIDENCE_VALIDATION','READY_FOR_REVIEW','PENDING_APPROVAL'
               ) AND run_id != ?""",
            (project_key, supersede_run_id or ""),
        ).fetchone()
        if active:
            LOGGER.console(f"Skipping; project already has active run {active['run_id']} ({active['status']}).")
            return
        fixing = conn.execute(
            "SELECT exec_id FROM execution_runs WHERE project_key=? AND status IN ('PREFLIGHT','RUNNING','VERIFYING')",
            (project_key,),
        ).fetchone()
        if fixing:
            LOGGER.console(f"Skipping; a fix ({fixing['exec_id']}) is running on the project.")
            return

        max_retries = int(project["max_retries"] or 2)

    repo = Path(project["repo_path"])
    check_disk_space(repo, min_free_mb=int(project["min_free_mb"] or 500))
    commit = git_value(repo, "rev-parse", "HEAD")
    if not commit:
        raise RuntimeError("Git HEAD could not be resolved; refusing to dispatch audit.")
    tree_hash = working_tree_hash(repo)

    with connect(DB_PATH) as conn:
        failed_same_state = conn.execute(
            """SELECT COUNT(*) FROM audit_runs
               WHERE project_key=? AND status='FAILED' AND base_commit=? AND working_tree_hash=?
                 AND COALESCE(error, '') NOT LIKE 'PROVIDER_QUOTA_EXHAUSTED%'""",
            (project_key, commit, tree_hash),
        ).fetchone()[0]
        if int(failed_same_state) > max_retries and not manual:
            raise RuntimeError(
                f"Bounded retry limit ({max_retries}) reached for commit {commit[:10]} in project '{project_key}'. "
                f"Check the reason of the failed runs; then `python core/cli.py audit-now --project {project_key}` "
                "(or auditor_audit_now) retries anyway, or a new commit resets the limit."
            )

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    superseded: dict[str, Any] | None = None
    with connect(DB_PATH) as conn:
        if supersede_run_id:
            superseded = _supersede_unreviewed_run(conn, project_key, supersede_run_id)
        conn.execute(
            """INSERT INTO audit_runs(
                run_id, project_key, status, base_commit, working_tree_hash,
                retry_count, max_retries, heartbeat_at
            ) VALUES(?, ?, 'PREFLIGHT', ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (run_id, project_key, commit, tree_hash, int(failed_same_state), max_retries),
        )
        record_event(
            conn,
            "AUDIT_PREFLIGHT",
            project_key=project_key,
            run_id=run_id,
            details={
                "commit": commit,
                "working_tree_hash": tree_hash,
                "retry_count": int(failed_same_state),
                "max_retries": max_retries,
            },
            jsonl_path=JSONL_PATH,
        )
        conn.commit()

    skill_rows = sync_inventory(project_key)
    repo_metadata = get_precomputed_repo_metadata(repo)
    prompt = build_primary_audit_prompt(
        project=dict(project),
        repo=repo,
        run_id=run_id,
        commit=commit,
        tree_hash=tree_hash,
        skill_rows=skill_rows,
        repo_metadata=repo_metadata,
    )
    # Headless agy cannot use MCP tools, so the scheduled audit returns findings as structured JSON that the
    # control plane submits through the same auditor_publish_report handler (structured_delivery.py).
    from structured_delivery import (
        PRIMARY_RESULT_SCHEMA,
        adapt_primary_prompt_for_structured_delivery,
        parse_structured_result,
        write_agent_schema,
    )

    prompt = adapt_primary_prompt_for_structured_delivery(prompt)
    with connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE audit_runs SET status='PRIMARY_AUDIT_RUNNING', heartbeat_at=CURRENT_TIMESTAMP WHERE run_id=?",
            (run_id,),
        )
        conn.commit()
    try:
        router_req = ModelRoutingRequest(
            task_type=TaskType.PRIMARY_AUDIT,
            severity="NORMAL",
            audit_run_id=run_id,
        )
        decision = route_model(router_req, db_path=DB_PATH)
        if decision.is_blocked:
            raise RuntimeError(f"Primary audit routing blocked: {decision.blocked_reason}")

        adapter = AntigravityCliAdapter()
        exe = adapter.discover_executable()
        if not exe:
            raise FileNotFoundError(
                "Antigravity CLI executable (agy.exe) not found; primary audit requires AntigravityCliAdapter."
            )

        import tempfile

        from primary_lenses import PRIMARY_LENS_TIMEOUT_SECONDS, active_lenses, lens_prompt, merge_lens_findings
        from structured_delivery import agent_result_payload

        lenses = active_lenses()
        model_id = decision.selected_model.value if decision.selected_model else None

        def _one_pass(pass_prompt: str, timeout: int) -> Any:
            result = _start_pass(pass_prompt, timeout)
            # The backend sometimes refuses to open a conversation under parallel load ("empty conversation id");
            # that is not the model's answer, so one delayed retry is cheap and safe.
            if not result.ok and "empty conversation id" in f"{result.error_message} {result.stderr}".lower():
                time.sleep(15)
                result = _start_pass(pass_prompt, timeout)
            return result

        def _start_pass(pass_prompt: str, timeout: int) -> Any:
            with tempfile.TemporaryDirectory(prefix="auditor-primary-") as schema_dir:
                return adapter.start_new_conversation(
                    pass_prompt,
                    cwd=repo,
                    project_id=str(project["antigravity_project_id"]),
                    task_type=TaskType.PRIMARY_AUDIT,
                    model_id=model_id,
                    audit_run_id=run_id,
                    db_path=DB_PATH,
                    timeout_seconds=timeout,
                    isolated=True,
                    json_schema_path=write_agent_schema(Path(schema_dir), "primary-findings", PRIMARY_RESULT_SCHEMA),
                )

        if not lenses:
            passes = [("single", _one_pass(prompt, PRIMARY_AUDIT_TIMEOUT_SECONDS))]
        else:
            # Independent passes with their own focus, in parallel; their candidates are merged below.
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=len(lenses)) as pool:
                futures = [
                    (lens["key"], pool.submit(_one_pass, lens_prompt(prompt, lens, i, len(lenses)),
                                              PRIMARY_LENS_TIMEOUT_SECONDS))
                    for i, lens in enumerate(lenses, 1)
                ]
                passes = []
                for key, fut in futures:
                    try:
                        passes.append((key, fut.result()))
                    except Exception as exc:  # noqa: BLE001 - one failed pass must not hide the others
                        passes.append((key, exc))

        lens_payloads: list[tuple[str, list[dict[str, Any]]]] = []
        pass_errors: list[str] = []
        quota_error: Any = None
        res = None
        for key, outcome in passes:
            if not lenses and not isinstance(outcome, Exception):  # single pass: the original errors, unchanged
                if outcome.status == "PROVIDER_QUOTA_EXHAUSTED":
                    raise ProviderQuotaExhausted(outcome.error_message or "Provider quota exhausted.",
                                                 outcome.retry_after_seconds)
                if not outcome.ok or not outcome.conversation_id:
                    raise RuntimeError(outcome.error_message
                                       or f"Antigravity CLI dispatch failed with status {outcome.status}.")
            if isinstance(outcome, Exception):
                pass_errors.append(f"{key}: {type(outcome).__name__}: {outcome}")
                continue
            if outcome.status == "PROVIDER_QUOTA_EXHAUSTED":
                quota_error = quota_error or outcome
                pass_errors.append(f"{key}: provider quota exhausted")
                continue
            if not outcome.ok or not outcome.conversation_id:
                pass_errors.append(f"{key}: " + (outcome.error_message or f"dispatch failed ({outcome.status})"))
                continue
            try:
                parsed = parse_structured_result(agent_result_payload(outcome), PRIMARY_RESULT_SCHEMA)
            except Exception as exc:  # noqa: BLE001
                if not lenses:
                    raise
                pass_errors.append(f"{key}: invalid result: {exc}")
                continue
            lens_payloads.append((key, parsed["findings"]))
            res = res or outcome
            if lenses:
                with connect(DB_PATH) as conn:
                    record_event(conn, "PRIMARY_PASS_FINISHED", project_key=project_key, run_id=run_id,
                                 details={"lens": key, "conversation": outcome.conversation_id,
                                          "model": outcome.observed_model or outcome.requested_model,
                                          "candidates": len(parsed["findings"])}, jsonl_path=JSONL_PATH)
                    conn.commit()
        if res is None:
            if quota_error is not None:
                raise ProviderQuotaExhausted(quota_error.error_message or "Provider quota exhausted.",
                                             quota_error.retry_after_seconds)
            raise RuntimeError("; ".join(pass_errors) or "Antigravity CLI dispatch failed.")
        if pass_errors:
            with connect(DB_PATH) as conn:
                record_event(conn, "PRIMARY_PASS_FAILED", project_key=project_key, run_id=run_id, level="WARNING",
                             details={"errors": pass_errors, "completed_passes": [k for k, _ in lens_payloads]},
                             jsonl_path=JSONL_PATH)
                conn.commit()
        conversation_id = res.conversation_id
        primary_model = res.observed_model or res.requested_model
        primary_attestation = res.attestation_status

        with connect(DB_PATH) as conn:
            conn.execute(
                """UPDATE audit_runs
                   SET agent_conversation_id=?, primary_model=?, primary_model_attestation=?, heartbeat_at=CURRENT_TIMESTAMP
                   WHERE run_id=?""",
                (conversation_id, primary_model, primary_attestation, run_id),
            )
            record_event(
                conn,
                "AGENT_DISPATCHED",
                project_key=project_key,
                run_id=run_id,
                details={
                    "agent_output": conversation_id,
                    "model": primary_model,
                    "attestation_status": primary_attestation,
                },
                jsonl_path=JSONL_PATH,
            )
            conn.commit()
        payload = {"findings": lens_payloads[0][1] if not lenses else merge_lens_findings(lens_payloads)}
        from mcp_server import AuditorMCPDispatcher

        published = AuditorMCPDispatcher(db_path=DB_PATH, app_home=APP_HOME).call_tool(
            "auditor_publish_report",
            {"project_key": project_key, "run_id": run_id, "findings": payload["findings"]},
        )
        LOGGER.console(
            f"Primary audit {run_id} for {project_key} via {primary_model} "
            f"(conversation={conversation_id}, attestation={primary_attestation}) returned "
            f"{len(payload['findings'])} candidate finding(s); run is {published['status']}."
        )
        return {"run_id": run_id, "status": published["status"],
                "verification_run_id": published.get("verification_run_id"),
                "candidate_count": len(payload["findings"])}
    except Exception as exc:
        with connect(DB_PATH) as conn:
            conn.execute(
                "UPDATE audit_runs SET status='FAILED', finished_at=CURRENT_TIMESTAMP, error=? WHERE run_id=?",
                (str(exc), run_id),
            )
            if superseded:
                _restore_superseded_run(conn, project_key, superseded)
            quota = isinstance(exc, ProviderQuotaExhausted)
            record_event(
                conn,
                "DISPATCH_WAITING_PROVIDER_QUOTA" if quota else "DISPATCH_FAILED",
                project_key=project_key,
                run_id=run_id,
                level="WARNING" if quota else "ERROR",
                details={"error": str(exc)},
                jsonl_path=JSONL_PATH,
            )
            conn.commit()
        raise


SCHEDULED_RETRY_MAX_WAIT_SECONDS = 300
_sleep = time.sleep


def _resumable_verification_run(project_key: str) -> dict[str, Any] | None:
    """Latest run of the project that is still waiting for second-pass verification *and* has a verification
    job that can still make progress; stale runs are recovered first."""
    recover_stale_runs(DB_PATH, project_key=project_key, jsonl_path=JSONL_PATH)
    with connect(DB_PATH) as conn:
        run = conn.execute(
            """SELECT r.run_id FROM audit_runs r
               WHERE r.project_key=? AND r.status IN ('VERIFICATION_PENDING', 'VERIFICATION_DISPATCHING')
                 AND EXISTS (
                     SELECT 1 FROM verification_dispatch_queue q
                     WHERE q.audit_run_id = r.run_id
                       AND q.status IN ('QUEUED', 'RETRYABLE_FAILURE', 'CLAIMED', 'DISPATCHING')
                       AND q.attempt_count < q.max_attempts
                 )
               ORDER BY r.started_at DESC LIMIT 1""",
            (project_key,),
        ).fetchone()
        if not run:
            return None
        vrun = conn.execute(
            """SELECT verification_run_id FROM audit_verification_runs
               WHERE audit_run_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (run["run_id"],),
        ).fetchone()
    return {
        "status": "VERIFICATION_PENDING",
        "run_id": str(run["run_id"]),
        "verification_run_id": str(vrun["verification_run_id"]) if vrun else None,
        "resumed": True,
    }


def _seconds_until_retry(run_id: str) -> float | None:
    """Seconds until the run's RETRYABLE_FAILURE verification job may be retried (0 if due), else None."""
    with connect(DB_PATH) as conn:
        row = conn.execute(
            """SELECT next_attempt_at FROM verification_dispatch_queue
               WHERE audit_run_id=? AND status='RETRYABLE_FAILURE' AND attempt_count < max_attempts
               ORDER BY updated_at DESC LIMIT 1""",
            (run_id,),
        ).fetchone()
    if not row:
        return None
    try:
        due = datetime.fromisoformat(str(row["next_attempt_at"]))
    except (TypeError, ValueError):
        return 0.0
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    return max(0.0, (due - datetime.now(timezone.utc)).total_seconds())


class ProviderQuotaExhausted(RuntimeError):
    """The provider refused the primary audit (quota / rate limit). The failed run does not count toward the
    bounded retry limit; the next scheduled run tries again."""

    def __init__(self, message: str, retry_after_seconds: int | None = None) -> None:
        super().__init__(message if message.startswith("PROVIDER_QUOTA_EXHAUSTED") else f"PROVIDER_QUOTA_EXHAUSTED: {message}")
        self.retry_after_seconds = retry_after_seconds


_REVIEW_WAITING_STATUSES = ("READY_FOR_REVIEW", "PENDING_APPROVAL")


def _weekly_gate(project_key: str, *, manual: bool) -> dict[str, Any] | None:
    """Token saving: a scheduled run does nothing while the previous report still waits for the user, or when the
    code has not changed since the last finished audit. A manual audit replaces a report nobody acted on."""
    with connect(DB_PATH) as conn:
        waiting = conn.execute(
            f"""SELECT run_id, status FROM audit_runs
                WHERE project_key=? AND status IN ({','.join('?' for _ in _REVIEW_WAITING_STATUSES)})
                ORDER BY started_at DESC, rowid DESC LIMIT 1""",
            (project_key, *_REVIEW_WAITING_STATUSES),
        ).fetchone()
        if waiting and not manual:
            return {"result": "SKIPPED_AWAITING_REVIEW", "run_id": waiting["run_id"],
                    "hint": f"Review run {waiting['run_id']}, or start a new audit now: "
                            f"python core/cli.py audit-now --project {project_key}"}
        if waiting and manual:
            # replaced only when the new audit has passed its preflight (dispatch), and restored if it fails
            return {"supersede_run_id": str(waiting["run_id"])}
        if manual:
            return None
        last = conn.execute(
            """SELECT r.run_id, r.base_commit, r.working_tree_hash, p.repo_path FROM audit_runs r
               JOIN projects p ON p.project_key = r.project_key
               WHERE r.project_key=? AND r.status IN ('COMPLETED', 'PARTIAL', 'READY_FOR_REVIEW')
               ORDER BY r.started_at DESC, r.rowid DESC LIMIT 1""",
            (project_key,),
        ).fetchone()
    if last and last["base_commit"]:
        repo = Path(last["repo_path"])
        try:
            same = (git_value(repo, "rev-parse", "HEAD") == last["base_commit"]
                    and working_tree_hash(repo) == last["working_tree_hash"])
        except Exception:  # noqa: BLE001 - an unreadable repo is reported by dispatch()
            same = False
        if same:
            return {"result": "SKIPPED_NO_CHANGES", "run_id": last["run_id"],
                    "hint": f"No code change since run {last['run_id']}; force one with: "
                            f"python core/cli.py audit-now --project {project_key}"}
    return None


def _supersede_unreviewed_run(conn: Any, project_key: str, run_id: str) -> dict[str, Any]:
    """Archive a report the user never acted on so a manual audit can replace it. Open findings stay open and are
    matched again by the new run; non-APPLY decisions live on in the findings' lifecycle. Returns what
    :func:`_restore_superseded_run` needs if the new audit fails."""
    now = datetime.now(timezone.utc)
    for appr in conn.execute(
        "SELECT approval_id, expires_at FROM execution_approvals WHERE run_id=? AND status='AUTHORIZED'", (run_id,)
    ).fetchall():
        try:
            exp = datetime.fromisoformat(str(appr["expires_at"]).replace("Z", "+00:00"))
            exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if exp <= now:
            conn.execute("UPDATE execution_approvals SET status='EXPIRED' WHERE approval_id=?", (appr["approval_id"],))
    busy = conn.execute(
        """SELECT 'execution' FROM execution_runs WHERE run_id=? AND status IN ('PREFLIGHT','RUNNING','VERIFYING')
           UNION ALL
           SELECT 'approval' FROM execution_approvals WHERE run_id=? AND status='AUTHORIZED'""",
        (run_id, run_id),
    ).fetchone()
    if busy:
        raise RuntimeError(
            f"Run {run_id} has a {'running fix' if busy[0] == 'execution' else 'pending fix approval'}; "
            "finish or cancel it before starting a new audit."
        )
    prev = conn.execute("SELECT status, error FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
    dec_rows = [int(r[0]) for r in conn.execute(
        "SELECT rowid FROM decisions WHERE run_id=? AND decision='APPLY' AND superseded=0", (run_id,)).fetchall()]
    transition_audit_run_status(
        conn, run_id, "ARCHIVED", error="SUPERSEDED_BY_MANUAL_AUDIT", reason="SUPERSEDED_BY_MANUAL_AUDIT",
        finished=True, actor="user", jsonl_path=JSONL_PATH,
    )
    if dec_rows:
        conn.execute(f"UPDATE decisions SET superseded=1 WHERE rowid IN ({','.join('?' for _ in dec_rows)})", dec_rows)
    record_event(conn, "AUDIT_RUN_SUPERSEDED", project_key=project_key, run_id=run_id, level="WARNING",
                 details={"reason": "manual audit requested"}, jsonl_path=JSONL_PATH)
    return {"run_id": run_id, "status": str(prev["status"]), "error": prev["error"], "decision_rowids": dec_rows}


def _restore_superseded_run(conn: Any, project_key: str, info: dict[str, Any]) -> None:
    """The replacing audit failed: give the user their report (and APPLY decisions) back."""
    conn.execute("UPDATE audit_runs SET status=?, error=?, finished_at=NULL WHERE run_id=?",
                 (info["status"], info["error"], info["run_id"]))
    rows = info.get("decision_rowids") or []
    if rows:
        conn.execute(f"UPDATE decisions SET superseded=0 WHERE rowid IN ({','.join('?' for _ in rows)})", rows)
    record_event(conn, "AUDIT_RUN_SUPERSEDE_REVERTED", project_key=project_key, run_id=info["run_id"],
                 level="WARNING", details={"reason": "the replacing audit failed"}, jsonl_path=JSONL_PATH)


def scheduled_audit(project_key: str, *, max_verification_jobs: int = 5, manual: bool = False) -> dict[str, Any]:
    """Run the pipeline under the project's audit process lock (the same lock auditor_audit_now writes), so a chat
    request sees a weekly or terminal audit as running instead of starting a second one."""
    from audit_launcher import _launched_process, _lock_path, _process_start

    lock = _lock_path(APP_HOME, project_key)
    other = _launched_process(APP_HOME, project_key)
    owned = other is None or int(other.get("pid") or 0) == os.getpid()
    if owned:
        try:
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text(json.dumps({"pid": os.getpid(), "process_start": _process_start(os.getpid()),
                                        "started_at": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                                        **({"log": other.get("log")} if other else {})}), encoding="utf-8")
        except OSError:
            owned = False
    try:
        return _scheduled_audit(project_key, max_verification_jobs=max_verification_jobs, manual=manual)
    finally:
        if owned:
            try:
                if int(json.loads(lock.read_text(encoding="utf-8")).get("pid") or 0) == os.getpid():
                    lock.unlink()
            except (OSError, ValueError):
                pass


def _scheduled_audit(project_key: str, *, max_verification_jobs: int = 5, manual: bool = False) -> dict[str, Any]:
    """Weekly pipeline run by the project's Antigravity Sidecar: primary audit -> second-pass verification ->
    finalization, all headless with structured (MCP-free) delivery. Each step reports its own outcome; a
    failure stops the chain with an explicit status rather than leaving work silently pending."""
    summary: dict[str, Any] = {"project_key": project_key, "started_at": datetime.now(timezone.utc).isoformat()}
    if manual and os.environ.get("ANTIGRAVITY_AUDITOR_SKIP_CATALOG_SYNC") != "1":
        # Notice new models between weekly runs (only lists models; probing/proposals stay in the weekly run).
        try:
            from model_catalog import sync_catalog as _sync_catalog

            summary["model_catalog"] = _sync_catalog(DB_PATH, timeout_seconds=60).get("status")
        except Exception as exc:  # noqa: BLE001 - never block an audit on the catalogue
            summary["model_catalog"] = f"ERROR: {type(exc).__name__}"
    # A previous weekly run that stopped in verification (e.g. a retryable dispatch failure) holds the project's
    # active-run lock; resume it instead of failing every following week.
    try:
        primary = _resumable_verification_run(project_key)
        if primary is None:
            gate = _weekly_gate(project_key, manual=manual)
            supersede = (gate or {}).get("supersede_run_id")
            if gate is not None and not supersede:
                summary.update(gate)
                return summary
            extra: dict[str, Any] = {"manual": True} if manual else {}
            primary = (dispatch(project_key, supersede_run_id=supersede, **extra) if supersede
                       else dispatch(project_key, **extra))
    except ProviderQuotaExhausted as exc:
        summary["primary"] = {"status": "FAILED", "error": str(exc)[:500], "retry_after_seconds": exc.retry_after_seconds}
        summary["result"] = "PRIMARY_WAITING_PROVIDER_QUOTA"
        return summary
    except Exception as exc:  # noqa: BLE001 - reported (agy missing, signed out, repo moved, disk guard ...)
        from runtime_discovery.redaction import redact_report_text

        summary["primary"] = {"status": "FAILED", "error": redact_report_text(f"{type(exc).__name__}: {exc}")[:500]}
        summary["result"] = "PRIMARY_FAILED"
        try:
            with connect(DB_PATH) as conn:
                record_event(conn, "AUDIT_START_FAILED", project_key=project_key,
                             details={"error": summary["primary"]["error"], "manual": manual}, jsonl_path=JSONL_PATH)
                conn.commit()
        except Exception:  # noqa: BLE001 - the summary still carries the error
            pass
        return summary
    summary["primary"] = primary
    if not primary or primary.get("status") != "VERIFICATION_PENDING":
        summary["result"] = "PRIMARY_NOT_READY_FOR_VERIFICATION"
        return summary
    run_id = primary["run_id"]
    worker = VerificationWorker(DB_PATH, app_home=APP_HOME, project_key=project_key, jsonl_path=JSONL_PATH)
    jobs: list[dict[str, Any]] = []
    verification_run_id = primary.get("verification_run_id")
    # The primary verification plus at most one follow-up round for verifier-discovered findings (-DISC).
    for _round in range(2):
        submitted = _run_verification_jobs(worker, run_id, jobs, max_verification_jobs)
        summary["verification"] = jobs
        if not submitted:
            last = jobs[-1] if jobs else {}
            parked = last.get("retry_at") if last.get("status") == "WAITING_PROVIDER_QUOTA" else _parked_for_provider_quota(run_id)
            if parked:
                summary["result"] = "VERIFICATION_WAITING_PROVIDER_QUOTA"
                summary["retry_at"] = parked
            else:
                summary["result"] = "VERIFICATION_NOT_SUBMITTED"
            return summary
        try:
            finalized = finalize_verified_report(
                DB_PATH,
                audit_run_id=run_id,
                verification_run_id=verification_run_id,
                jsonl_path=JSONL_PATH,
            )
        except Exception as exc:  # noqa: BLE001 - reported, the run keeps its verification state for review
            summary["finalize_error"] = str(exc)[:500]
            summary["result"] = "FINALIZE_BLOCKED"
            return summary
        summary["finalize"] = finalized
        followup = (finalized or {}).get("followup_verification_run_id") if isinstance(finalized, dict) else None
        if not followup:
            summary["result"] = "FINALIZED"
            return summary
        verification_run_id = followup
    summary["result"] = "FOLLOWUP_VERIFICATION_PENDING"
    return summary


def _parked_for_provider_quota(run_id: str) -> str | None:
    """next_attempt_at of the run's verification job if it is waiting for the provider quota, else None."""
    try:
        with connect(DB_PATH) as conn:
            row = conn.execute(
                """SELECT next_attempt_at FROM verification_dispatch_queue
                   WHERE audit_run_id=? AND status='RETRYABLE_FAILURE' AND last_error_code='PROVIDER_QUOTA_EXHAUSTED'
                   ORDER BY updated_at DESC LIMIT 1""",
                (run_id,),
            ).fetchone()
    except sqlite3.Error:
        return None
    return str(row["next_attempt_at"]) if row else None


def _run_verification_jobs(
    worker: Any, run_id: str, jobs: list[dict[str, Any]], max_verification_jobs: int
) -> bool:
    """Process the run's verification jobs until one is submitted (True) or nothing more can run (False).
    A RETRYABLE_FAILURE is retried after its back-off (bounded) within the same scheduled run."""
    for _ in range(max(1, max_verification_jobs)):
        job = worker.process_one_job()
        if job is not None:
            jobs.append({k: job.get(k) for k in ("audit_run_id", "status", "structured_submission", "error", "error_code", "retry_at")})
            if job.get("audit_run_id") == run_id and job.get("structured_submission") in ("SUBMITTED", "REJECTED", "ERROR"):
                return job.get("structured_submission") == "SUBMITTED"
            if job.get("status") not in ("RETRYABLE_FAILURE", "WAITING_PROVIDER_QUOTA"):
                continue
        # Nothing claimable now, or the attempt just failed retryably: wait for the run's retry back-off.
        wait_s = _seconds_until_retry(run_id)
        if wait_s is None or wait_s > SCHEDULED_RETRY_MAX_WAIT_SECONDS:
            return False
        _sleep(wait_s + 1)
    return False


def publish_report(args: argparse.Namespace) -> None:
    if getattr(args, "file", None):
        file_path = Path(args.file).expanduser().resolve()
        findings = json.loads(file_path.read_text(encoding="utf-8-sig"))
        report_dir = file_path.parent
    elif getattr(args, "findings_json", None):
        raw_payload = json.loads(args.findings_json)
        findings = raw_payload.get("findings", raw_payload) if isinstance(raw_payload, dict) else raw_payload
        report_dir = (APP_HOME / "reports" / args.run_id).resolve()
        report_dir.mkdir(parents=True, exist_ok=True)
        from runtime_discovery.redaction import redact_report_obj

        (report_dir / "findings.json").write_text(
            json.dumps(redact_report_obj(findings), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    else:
        raise RuntimeError("Provide either --file or --findings-json.")

    with connect(DB_PATH) as conn:
        proj = conn.execute("SELECT repo_path FROM projects WHERE project_key=?", (args.project,)).fetchone()
        repo_path = Path(proj["repo_path"]) if proj and proj["repo_path"] else None

    stats = ingest_findings(
        DB_PATH,
        project_key=args.project,
        run_id=args.run_id,
        findings=findings,
        report_dir=report_dir,
        repo_path=repo_path,
        jsonl_path=JSONL_PATH,
    )
    review_path = report_dir / "review-report.md"
    generate_review_report(
        DB_PATH,
        project_key=args.project,
        run_id=args.run_id,
        output_path=review_path,
    )
    LOGGER.console(
        f"Submitted {stats['unique_in_run']} primary candidate finding(s) for run {args.run_id} "
        f"(verification_run_id: {stats['verification_run_id']}, job_id: {stats['verification_job_id']}). "
        f"Preliminary report: {review_path}. Status: VERIFICATION_PENDING."
    )


def show_status(args: argparse.Namespace) -> None:
    detect_moved_repositories(DB_PATH, project_key=args.project, jsonl_path=JSONL_PATH)
    with connect(DB_PATH) as conn:
        if args.project:
            rows = conn.execute(
                """SELECT p.project_key, p.display_name, p.repo_path, p.health_status,
                          r.run_id, r.status, r.started_at, r.finished_at
                   FROM projects p
                   LEFT JOIN audit_runs r ON r.run_id=(
                       SELECT run_id FROM audit_runs x WHERE x.project_key=p.project_key ORDER BY x.started_at DESC LIMIT 1
                   )
                   WHERE p.project_key=?""",
                (args.project,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT p.project_key, p.display_name, p.repo_path, p.health_status,
                          r.run_id, r.status, r.started_at, r.finished_at
                   FROM projects p
                   LEFT JOIN audit_runs r ON r.run_id=(
                       SELECT run_id FROM audit_runs x WHERE x.project_key=p.project_key ORDER BY x.started_at DESC LIMIT 1
                   )
                   ORDER BY p.project_key"""
            ).fetchall()
    for row in rows:
        LOGGER.console(
            f"{row['project_key']} | {row['display_name']} | {row['health_status']} | "
            f"{row['status'] or 'NO AUDITS'} | {row['run_id'] or '-'} | {row['repo_path']}"
        )
    if not rows:
        LOGGER.console("No registered projects.")


def dispatch_routed_task(
    *,
    prompt: str,
    task_type: TaskType | str,
    cwd: Path | str | None = None,
    audit_run_id: str | None = None,
    verification_run_id: str | None = None,
    finding_fingerprint: str | None = None,
    severity: str = "MEDIUM",
    finding_category: str | None = None,
    evidence_gate_status: str = "UNCHECKED",
    execution_intent: ExecutionIntent | str = ExecutionIntent.ROUTINE_VERIFICATION,
    explicit_operator_escalation: bool = False,
    operator_escalation_reason: str | None = None,
    db_path: Path | None = DB_PATH,
    budget_tracker: ModelBudgetTracker | None = None,
    adapter: AntigravityCliAdapter | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Shared dispatcher interface for routine and critical tasks."""
    req = ModelRoutingRequest(
        task_type=task_type,
        severity=severity,
        finding_category=finding_category,
        evidence_gate_status=evidence_gate_status,
        execution_intent=execution_intent,
        audit_run_id=audit_run_id,
        finding_fingerprint=finding_fingerprint,
        explicit_operator_escalation=explicit_operator_escalation,
        operator_escalation_reason=operator_escalation_reason,
    )
    decision = route_model(req, db_path=DB_PATH)
    if decision.is_blocked:
        return {
            "ok": False,
            "status": decision.routing_status.value,
            "blocked": True,
            "blocked_reason": decision.blocked_reason or decision.decision_reason,
            "decision": decision.to_dict(),
        }

    cli_adapter = adapter or AntigravityCliAdapter()
    tracker = budget_tracker or ModelBudgetTracker(db_path=db_path)
    effective_timeout = timeout_seconds
    if effective_timeout is None and task_type in (TaskType.PRIMARY_AUDIT, TaskType.PRIMARY_AUDIT.value, "PRIMARY_AUDIT"):
        effective_timeout = PRIMARY_AUDIT_TIMEOUT_SECONDS
    res = cli_adapter.start_new_conversation(
        prompt,
        cwd=cwd,
        task_type=task_type,
        model_id=decision.selected_model.value if decision.selected_model else None,
        severity=severity,
        finding_category=finding_category,
        evidence_gate_status=evidence_gate_status,
        execution_intent=execution_intent,
        audit_run_id=audit_run_id,
        verification_run_id=verification_run_id,
        finding_fingerprint=finding_fingerprint,
        explicit_operator_escalation=explicit_operator_escalation,
        operator_escalation_reason=operator_escalation_reason,
        budget_tracker=tracker,
        db_path=db_path,
        timeout_seconds=effective_timeout,
    )
    return {
        "ok": res.ok,
        "status": res.status,
        "blocked": False,
        "decision": decision.to_dict(),
        "dispatch_result": res.to_dict(),
    }


def _apply_preview(project_key: str, run_id: str) -> list[dict[str, Any]]:
    """Findings with an active APPLY decision for the run (what an authorization would cover)."""
    from apply_policy import apply_candidates

    with connect(DB_PATH) as conn:
        return apply_candidates(conn, project_key, run_id)


def _csv(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


def apply_policy_command(args: argparse.Namespace) -> None:
    """`apply-policy show|set|remove|check`: the optional APPLY auto-approval policy (human-only writes)."""
    import apply_policy as ap

    cmd = args.policy_command
    if cmd == "show":
        with connect(DB_PATH) as conn:
            if args.project:
                policy, source = ap.get_policy(conn, args.project)
                out: Any = {"project_key": args.project, "effective_policy": policy, "source": source}
            else:
                out = {"stored": ap.list_policies(conn), "default": ap.DEFAULT_POLICY}
        LOGGER.console(json.dumps(out, ensure_ascii=False, indent=2))
        return
    if cmd == "check":
        with connect(DB_PATH) as conn:
            ev = ap.evaluate(conn, args.project, args.run_id)
        LOGGER.console(json.dumps(ev, ensure_ascii=False, indent=2, default=str))
        return
    key = args.project
    if key != ap.GLOBAL_KEY:
        with connect(DB_PATH) as conn:
            if not conn.execute("SELECT 1 FROM projects WHERE project_key=?", (key,)).fetchone():
                raise SystemExit(f"Unknown project '{key}' (use '*' for the default policy of all projects).")
    if cmd == "remove":
        decided_by = _require_interactive_confirmation("POLICY-REMOVE", key)
        with connect(DB_PATH) as conn:
            removed = ap.remove_policy(conn, key)
            record_event(conn, "APPLY_POLICY_REMOVED", project_key=None if key == ap.GLOBAL_KEY else key,
                         level="WARNING", details={"policy_key": key, "by": decided_by, "removed": removed},
                         jsonl_path=JSONL_PATH)
            conn.commit()
        LOGGER.console(json.dumps({"policy_key": key, "removed": removed}, indent=2))
        return
    # set: start from the stored policy of this key (or the effective one for a new key) and apply the flags
    with connect(DB_PATH) as conn:
        base = ap.stored_policy(conn, key) or ap.get_policy(conn, key)[0]
    new = dict(base)
    if args.enable:
        new["enabled"] = True
    if args.disable:
        new["enabled"] = False
    for flag, field in (("max_findings", "max_findings"), ("max_changed_files", "max_changed_files"),
                        ("max_per_day", "max_per_day")):
        if getattr(args, flag) is not None:
            new[field] = getattr(args, flag)
    for flag in ("severities", "categories_allow", "categories_deny", "paths_allow", "paths_deny"):
        val = _csv(getattr(args, flag))
        if val is not None:
            new[flag] = val
    if args.expires_in_days is not None:
        new["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=args.expires_in_days)).isoformat()
    if args.no_expiry:
        new["expires_at"] = None
    if args.allow_single_model:
        new["allow_single_model_verification"] = True
    if args.require_cross_model:
        new["allow_single_model_verification"] = False
    try:
        normalized = ap.validate_policy(new)
    except ValueError as exc:
        raise SystemExit(f"Invalid policy: {exc}")
    LOGGER.console(json.dumps({"policy_key": key, "before": base, "after": normalized}, ensure_ascii=False, indent=2))
    decided_by = _require_interactive_confirmation("POLICY", key)
    with connect(DB_PATH) as conn:
        ap.set_policy(conn, key, normalized, updated_by=decided_by)
        record_event(conn, "APPLY_POLICY_SET", project_key=None if key == ap.GLOBAL_KEY else key, level="WARNING",
                     details={"policy_key": key, "by": decided_by, "policy": normalized}, jsonl_path=JSONL_PATH)
        conn.commit()
    LOGGER.console(json.dumps({"policy_key": key, "saved": normalized}, ensure_ascii=False, indent=2))


def _require_interactive_yes(question: str) -> str:
    """Human-only gate: an interactive terminal and an explicit y/yes (e/evet). Returns the OS user."""
    import getpass

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        LOGGER.console(json.dumps({"error": "This command requires an interactive terminal; refusing non-interactive use."}))
        raise SystemExit(3)
    answer = input(f"{question} [y/N]: ").strip().lower()
    if answer not in ("y", "yes", "e", "evet"):
        LOGGER.console(json.dumps({"error": "Not confirmed; nothing changed."}))
        raise SystemExit(3)
    return getpass.getuser()


def project_settings_command(args: argparse.Namespace) -> None:
    import shlex

    from project_settings import get_settings, set_settings

    with connect(DB_PATH) as conn:
        current = get_settings(conn, args.project)
    if args.settings_command == "show":
        LOGGER.console(json.dumps(current, ensure_ascii=False, indent=2))
        return
    test_command = shlex.split(args.test_command, posix=False) if args.test_command else None
    if test_command:
        test_command = [a[1:-1] if len(a) > 1 and a[0] == a[-1] and a[0] in "\"'" else a for a in test_command]
    changes = {k: v for k, v in {
        "approval_mode": args.approval_mode, "delivery_mode": args.delivery_mode, "test_command": test_command,
        "clear_test_command": args.clear_test_command or None, "test_timeout_seconds": args.test_timeout,
    }.items() if v is not None}
    if not changes:
        raise SystemExit("Nothing to change; see --help.")
    LOGGER.console(json.dumps({"project": args.project, "current": current, "change": changes}, ensure_ascii=False, indent=2))
    # The test command is run by the auditor after every fix, so changing it (or the approval mode) is human-only.
    _require_interactive_yes("Apply these settings?")
    with connect(DB_PATH) as conn:
        res = set_settings(conn, args.project, **changes)
        conn.commit()
    LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))


def _require_interactive_confirmation(verb: str, target: str) -> str:
    """Human-only gate for routing-table decisions: an interactive terminal and a typed confirmation.

    Headless agents (agy -p, MCP tools, scheduled tasks) have no TTY and are refused. Returns the
    operating-system user recorded as ``decided_by``.
    """
    import getpass

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        LOGGER.console(json.dumps({"error": f"{verb} requires an interactive terminal; refusing non-interactive use."}))
        raise SystemExit(3)
    expected = f"{verb} {target}"
    typed = input(f"Type '{expected}' to confirm: ").strip()
    if typed != expected:
        LOGGER.console(json.dumps({"error": "Confirmation text did not match; nothing changed."}))
        raise SystemExit(3)
    return getpass.getuser()


def main() -> None:
    parser = argparse.ArgumentParser(description="Antigravity Auditor deterministic core")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize local SQLite database and apply migrations")

    reg = sub.add_parser("register", help="Register a Git repository (the weekly task audits it; older installs get a Sidecar)")
    reg.add_argument("--key", required=True)
    reg.add_argument("--path", required=True)
    reg.add_argument("--project-id", required=False, default="")
    reg.add_argument("--name")
    reg.add_argument("--cron", default="0 4 * * 1")
    reg.add_argument("--copy-omniapex-rules", action="store_true")

    sub.add_parser("discover-projects", help="Discover Antigravity projects from ~/.gemini/config/projects")

    sched = sub.add_parser("scheduled-audit", help="Weekly headless pipeline: primary audit, verification, finalization")
    sched.add_argument("--project", required=True)
    sched.add_argument("--max-verification-jobs", type=int, default=5)
    now_p = sub.add_parser("audit-now", help="Run the audit pipeline now (replaces a report nobody acted on; "
                                             "ignores the no-change skip)")
    now_p.add_argument("--project", required=True)
    now_p.add_argument("--max-verification-jobs", type=int, default=5)
    sch = sub.add_parser("schedule", help="Weekly Windows scheduled task: model sync + audits of all enabled projects")
    sch_sub = sch.add_subparsers(dest="schedule_command", required=True)
    sch_in = sch_sub.add_parser("install", help="Create/update the task (replaces the auditor's Antigravity Sidecars)")
    sch_in.add_argument("--day", default="MON", help="MON..SUN (default MON)")
    sch_in.add_argument("--time", default="04:00", help="HH:MM local time (default 04:00)")
    sch_in.add_argument("--keep-sidecars", action="store_true", help="do not remove the auditor's Sidecars")
    sch_sub.add_parser("status")
    sch_sub.add_parser("remove")
    sub.add_parser("weekly", help=argparse.SUPPRESS)  # what the scheduled task runs
    deliv = sub.add_parser("deliver", help=argparse.SUPPRESS)  # background step queued by finalize (auto_merge)
    deliv.add_argument("--exec", dest="exec_id", required=True)
    disp = sub.add_parser("dispatch", help="Dispatch a scheduled read-only primary audit")
    disp.add_argument("--project", required=True)
    disp.add_argument("--stale-seconds", type=int, default=None)

    pub = sub.add_parser("publish-report", help="Submit primary candidate findings.json and enqueue verification")
    pub.add_argument("--project", required=True)
    pub.add_argument("--run-id", required=True)
    pub.add_argument("--file", default=None, help="Path to findings.json")
    pub.add_argument("--findings-json", default=None, help="Inline JSON array or object containing primary candidate findings")

    rep = sub.add_parser("generate-report", help="Generate Markdown review report for a run")
    rep.add_argument("--project", required=True)
    rep.add_argument("--run-id", required=True)
    rep.add_argument("--output")

    # Phase 5 & 6 Verification CLI commands
    vw = sub.add_parser("verifier-worker", help="Run the persistent read-only verification worker Sidecar")
    vw.add_argument("--project", help="Restrict worker to a specific registered project key")
    vw.add_argument("--once", action="store_true", help="Claim and process at most one verification job then exit")
    vw.add_argument("--poll-interval", type=float, default=5.0)
    vw.add_argument("--lease-seconds", type=int, default=1200)
    vw.add_argument("--worker-id", default=None)

    vs = sub.add_parser("verifier-status", help="Inspect verification worker queue status and Sidecar configuration")
    vs.add_argument("--project")
    vs.add_argument("--run-id")

    gvp = sub.add_parser("generate-verification-prompt", help="Generate a manual second-pass verification prompt")
    gvp.add_argument("--project")
    gvp.add_argument("--run-id", required=True)
    gvp.add_argument("--verification-run-id")
    gvp.add_argument("--output")

    vctx = sub.add_parser("verification-context", help="Retrieve structured JSON verification context payload")
    vctx.add_argument("--run-id", required=True)
    vctx.add_argument("--verification-run-id", required=True)
    vctx.add_argument("--output", help="Optional output JSON file path")

    evs = sub.add_parser("enable-verifier-sidecar", help="Enable the verifier worker Sidecar for a registered project")
    evs.add_argument("--project", required=True)

    dvs = sub.add_parser("disable-verifier-sidecar", help="Safely disable the verifier worker Sidecar for a project")
    dvs.add_argument("--project", required=True)

    gvs = sub.add_parser("generate-verifier-sidecars", help="Generate verifier Sidecar JSON files without enabling them")
    gvs.add_argument("--project")
    gvs.add_argument("--disabled", action="store_true", default=True)

    rvj = sub.add_parser("recover-verification", help="Recover blocked, uncertain, or unverifiable verification jobs")
    rvj.add_argument("--project", required=True)
    rvj.add_argument("--run-id", required=True)
    rvj.add_argument(
        "--action",
        required=True,
        choices=["attach-conversation", "requeue", "archive-unverifiable", "archive-run"],
    )
    rvj.add_argument("--conversation-id")
    rvj.add_argument("--candidate-id")

    subv = sub.add_parser("submit-verification", help="Submit second-pass verification verdicts via CLI")
    subv.add_argument("--project", required=True)
    subv.add_argument("--run-id", required=True)
    subv.add_argument("--verification-run-id", required=True)
    subv.add_argument("--conversation-id", required=True)
    subv.add_argument("--file", help="Path to JSON file containing verification_results array")
    subv.add_argument("--results-json", help="Inline JSON array of verification_results")
    subv.add_argument("--model-id")
    subv.add_argument("--agent-id")
    subv.add_argument("--mechanism", default="cli")
    subv.add_argument("--subagent-invocations", type=int, default=0)

    finv = sub.add_parser("finalize-verified-report", help="Run evidence gate and finalize verified report")
    finv.add_argument("--project")
    finv.add_argument("--run-id", required=True)
    finv.add_argument("--verification-run-id", required=True)

    qrep = sub.add_parser("quality-report", help="Display audit quality metrics and history")
    qrep.add_argument("--project")
    qrep.add_argument("--run-id")

    dec = sub.add_parser("save-decisions", help="Save review decisions without authorizing execution")
    dec.add_argument("--project", required=True)
    dec.add_argument("--run-id", required=True)
    dec.add_argument("--file", help="Path to JSON file containing decisions array")
    dec.add_argument("--decisions-json", help="Inline JSON array of decisions")
    dec.add_argument("--actor", default="user")

    for name, help_text in (
        ("approve", "Approve the saved APPLY decisions of the latest report (interactive y/N)"),
        ("authorize-execution", "Same as approve"),
    ):
        auth = sub.add_parser(name, help=help_text)
        auth.add_argument("--project", required=True)
        auth.add_argument("--run-id", default=None, help="default: the latest report waiting for review")
        auth.add_argument("--confirm", default=None, help=argparse.SUPPRESS)  # legacy; an interactive confirmation is required
        auth.add_argument("--authorized-by", default="user")
        auth.add_argument("--ttl-seconds", type=int, default=86400)

    pset = sub.add_parser("project-settings", help="Approval mode and the test command the auditor runs after a fix")
    pset_sub = pset.add_subparsers(dest="settings_command", required=True)
    pshow = pset_sub.add_parser("show")
    pshow.add_argument("--project", required=True)
    pupd = pset_sub.add_parser("set")
    pupd.add_argument("--project", required=True)
    pupd.add_argument("--approval-mode", choices=("simple", "strict"))
    pupd.add_argument("--delivery-mode", choices=("local", "auto_merge"),
                      help="auto_merge: push, open a PR, wait for CI and merge when every gate passes")
    pupd.add_argument("--test-command", help='e.g. "python -m pytest -q" (split like a shell command line)')
    pupd.add_argument("--clear-test-command", action="store_true", help="detect the command from the repository again")
    pupd.add_argument("--test-timeout", type=int, help="seconds (30-7200, default 600)")

    pol = sub.add_parser("apply-policy", help="Optional APPLY auto-approval policy (show/set/remove/check)")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)
    pol_show = pol_sub.add_parser("show", help="Show the effective policy of a project, or all stored policies")
    pol_show.add_argument("--project")
    pol_check = pol_sub.add_parser("check", help="Dry run: would the policy auto-approve this run's APPLY decisions?")
    pol_check.add_argument("--project", required=True)
    pol_check.add_argument("--run-id", required=True)
    pol_rm = pol_sub.add_parser("remove", help="Remove a stored policy (interactive confirmation)")
    pol_rm.add_argument("--project", required=True, help="Project key, or '*' for the default of all projects")
    pol_set = pol_sub.add_parser("set", help="Create or change a policy (interactive confirmation)")
    pol_set.add_argument("--project", required=True, help="Project key, or '*' for the default of all projects")
    pol_en = pol_set.add_mutually_exclusive_group()
    pol_en.add_argument("--enable", action="store_true")
    pol_en.add_argument("--disable", action="store_true")
    pol_set.add_argument("--max-findings", type=int)
    pol_set.add_argument("--max-changed-files", type=int)
    pol_set.add_argument("--max-per-day", type=int)
    pol_set.add_argument("--severities", help="Comma list, e.g. LOW,MEDIUM")
    pol_set.add_argument("--categories-allow", help="Comma list; empty string clears")
    pol_set.add_argument("--categories-deny", help="Comma list; empty string clears")
    pol_set.add_argument("--paths-allow", help="Comma list of globs (e.g. src/**,tests/**); empty string clears")
    pol_set.add_argument("--paths-deny", help="Comma list of globs; empty string clears")
    pol_single = pol_set.add_mutually_exclusive_group()
    pol_single.add_argument("--allow-single-model", action="store_true",
                            help="Also auto-approve findings verified without an independent second model")
    pol_single.add_argument("--require-cross-model", action="store_true")
    pol_exp = pol_set.add_mutually_exclusive_group()
    pol_exp.add_argument("--expires-in-days", type=int)
    pol_exp.add_argument("--no-expiry", action="store_true")

    exe = sub.add_parser("execute-approved", help="Start or run isolated worktree execution for an approval token")
    exe.add_argument("--project", required=True)
    exe.add_argument("--approval-token", required=True)
    exe.add_argument("--start-only", action="store_true", help="Only create isolated worktree and initialize execution")

    rec = sub.add_parser("recover", help="Run stale lock recovery, moved-repo detection, and backup verification")
    rec.add_argument("--project")
    rec.add_argument("--stale-seconds", type=int, default=None)
    rec.add_argument("--force-stale", action="store_true")
    rec.add_argument("--no-backup", action="store_true")

    bkp = sub.add_parser("backup", help="Create and verify an online SQLite database backup")
    bkp.add_argument("--output-dir")

    vbkp = sub.add_parser("verify-backup", help="Verify a backup database file and test restoration")
    vbkp.add_argument("--file", required=True)
    vbkp.add_argument("--restore-to")

    sub.add_parser("integrity-check", help="Run SQLite integrity_check and foreign_key_check")
    sub.add_parser("register-mcp", help="Register Antigravity Auditor MCP server in ~/.gemini/config/mcp_config.json")
    sub.add_parser("mcp-serve", help="Run the Antigravity Auditor MCP server over stdio")

    status = sub.add_parser("status", help="Show registered projects and latest run")
    status.add_argument("--project")

    inv = sub.add_parser("inventory-skills", help="Scan Antigravity global and workspace skills")
    inv.add_argument("--project")

    igs = sub.add_parser("install-global-skills", help="Install bundle skills safely without overwriting customized global skills")
    igs.add_argument("--target-root", default=str(Path.home() / ".gemini" / "config" / "skills"))
    igs.add_argument("--backup-root")
    igs.add_argument("--include-omniapex", action="store_true")

    # Task-Based Model Router CLI commands
    mr = sub.add_parser("model-route", help="Evaluate deterministic model routing policy for a task")
    mr.add_argument("--task", default="ROUTINE_VERIFICATION", help="Task type (e.g. PRIMARY_AUDIT, ROUTINE_VERIFICATION, CRITICAL_VERIFICATION, etc.)")
    mr.add_argument("--severity", default="MEDIUM", help="Finding severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    mr.add_argument("--category", help="Finding category (e.g. DATABASE_INTEGRITY, RCE, etc.)")
    mr.add_argument("--evidence-gate", default="UNCHECKED", help="Evidence gate status (PASSED, FAILED, UNCHECKED)")
    mr.add_argument("--escalate", action="store_true", help="Explicit human operator escalation")
    mr.add_argument("--escalate-reason", help="Reason for operator escalation")

    ms = sub.add_parser("model-status", help="Show Antigravity CLI adapter and model routing status")

    mdl = sub.add_parser("models", help="Dynamic model routing: backend model catalogue and routing-table health")
    mdl_sub = mdl.add_subparsers(dest="models_command", required=True)
    mdl_sync = mdl_sub.add_parser("sync", help="Run `agy models`, persist a snapshot if the list changed, report table health")
    mdl_sync.add_argument("--timeout", type=int, default=90, help="Timeout in seconds for `agy models`")
    mdl_sync.add_argument("--probe", action="store_true", help="Probe policy-allowed, non-scarce models without a probe result")
    mdl_sync.add_argument("--research-new", action="store_true",
                          help="Run web research when a catalogue model line is not covered by the latest research")
    mdl_sync.add_argument("--propose", action="store_true", help="After syncing (and probing), store a routing-table proposal if the evidence warrants one")
    mdl_prop = mdl_sub.add_parser("propose", help="Compute and store a routing-table proposal from catalogue, probes and research")
    mdl_pr = mdl_sub.add_parser("proposal", help="Show, approve or reject the pending routing-table proposal (approval is human-only)")
    mdl_pr_sub = mdl_pr.add_subparsers(dest="proposal_command", required=True)
    mdl_pr_sub.add_parser("show", help="Show the pending proposal and table history")
    mdl_pr_ap = mdl_pr_sub.add_parser("approve", help="Activate a proposal (interactive terminal + typed confirmation required)")
    mdl_pr_ap.add_argument("version_id")
    mdl_pr_ap.add_argument("--note", default=None)
    mdl_pr_rj = mdl_pr_sub.add_parser("reject", help="Reject a proposal (interactive terminal + typed confirmation required)")
    mdl_pr_rj.add_argument("version_id")
    mdl_pr_rj.add_argument("--note", default=None)
    mdl_tbl = mdl_sub.add_parser("revert-to-seed", help="Deactivate the approved table so the seed applies (interactive)")
    mdl_probe = mdl_sub.add_parser("probe", help="Probe models with the deterministic fixture suite (spends model quota)")
    mdl_probe.add_argument("--model", action="append", default=None, help="Model slug to probe (repeatable); default: all eligible")
    mdl_probe.add_argument("--include-scarce", action="store_true", help="Allow probing scarce models (Gemini 4 Argon quota)")
    mdl_probe.add_argument("--reprobe", action="store_true", help="Probe even if the model already has a result")
    mdl_probe.add_argument("--max", type=int, default=4, help="Maximum number of probes in this run")
    mdl_probe.add_argument("--timeout", type=int, default=300, help="Per-probe timeout in seconds")
    mdl_res = mdl_sub.add_parser("research", help="Web research about catalogue model lines (untrusted evidence; spends model quota)")
    mdl_res.add_argument("--timeout", type=int, default=600, help="Research session timeout in seconds")
    mdl_sched = mdl_sub.add_parser(
        "schedule", help="Create or remove the Antigravity Sidecar running `models sync --probe --propose` weekly"
    )
    mdl_sched.add_argument("--project", help="Registered project whose Antigravity Project ID hosts the Sidecar")
    mdl_sched.add_argument("--cron", default="30 3 * * 1", help="Cron schedule (default: Mondays 03:30)")
    mdl_sched.add_argument("--remove", action="store_true", help="Remove the Sidecar and its config.json entry")
    mdl_ov = mdl_sub.add_parser("overview", help="Read-only overview (no backend CLI execution)")
    mdl_ov.add_argument("--no-models", action="store_true", help="Omit the per-model catalogue listing")

    ma = sub.add_parser("model-attest", help="Independently attest conversation model identity via local SQLite db")
    ma.add_argument("--conversation-id", required=True, help="Conversation UUID to attest")
    ma.add_argument("--expected-model", required=True, help="Expected Gemini model identifier")
    ma.add_argument("--conversations-dir", help="Optional override for conversation databases directory")

    mb = sub.add_parser("model-budget", help="Inspect model token budget usage for an audit run")
    mb.add_argument("--run-id", required=True, help="Audit run ID")
    mb.add_argument("--model", help="Optional model filter")

    mdisp = sub.add_parser("model-dispatch", help="Dispatch a task through the deterministic Model Router")
    mdisp.add_argument("--task", required=True, help="Task type (e.g. ROUTINE_RED_TEAM, CRITICAL_RED_TEAM, REPAIR_PLANNING, TEST_SCENARIO_GENERATION)")
    mdisp.add_argument("--prompt", required=True, help="Prompt text or path to prompt file")
    mdisp.add_argument("--cwd", help="Working directory for CLI process")
    mdisp.add_argument("--run-id", help="Audit run ID for budget and accounting")
    mdisp.add_argument("--verification-run-id", help="Verification run ID")
    mdisp.add_argument("--fingerprint", help="Finding fingerprint")
    mdisp.add_argument("--severity", default="MEDIUM", help="Finding severity")
    mdisp.add_argument("--category", help="Finding category")
    mdisp.add_argument("--evidence-gate", default="UNCHECKED", help="Evidence gate status (PASSED/FAILED/UNCHECKED)")
    mdisp.add_argument("--intent", default="ROUTINE_VERIFICATION", help="Execution intent (ROUTINE_VERIFICATION/PRELIMINARY_ANALYSIS/REQUIRED_CRITICAL_VERIFICATION)")
    mdisp.add_argument("--escalate", action="store_true", help="Explicit operator escalation")
    mdisp.add_argument("--escalate-reason", help="Reason for operator escalation")
    mdisp.add_argument("--timeout", type=int, default=120, help="Process timeout seconds")

    # NEXT-22A Read-Only Multi-Application Runtime Discovery
    rt = sub.add_parser("runtime", help="Read-only runtime discovery operations (no production DB access)")
    rt_sub = rt.add_subparsers(dest="runtime_command", required=True)
    rt_disc = rt_sub.add_parser("discover", help="Discover installed AI applications, models, efforts, and MCP metadata")
    rt_disc.add_argument("--json", action="store_true", help="Output deterministic JSON report to stdout")
    rt_disc.add_argument("--output", help="Optional external output file or directory path for discovery report")
    rt_disc.add_argument("--project-path", help="Optional project directory to inspect project-scoped MCP/model configs")
    rt_disc.add_argument("--run-id", help="Optional explicit run identifier")
    rt_disc.add_argument("--timeout", type=float, default=8.0, help="Per-command bounded timeout in seconds")

    # NEXT-22B User-Aware Entitlement Registry & Capability-Based Model Router (planning-only)
    rc = sub.add_parser("routing", help="Read-only/dry-run user entitlement & capability routing planner")
    rc_sub = rc.add_subparsers(dest="routing_command", required=True)

    def _add_routing_common_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--db", help="Optional read-only SQLite DB path (never touches production DB)")
        p.add_argument("--discovery-file", help="Optional NEXT-22A runtime-discovery.json file")
        p.add_argument("--profile-file", help="Optional manual entitlement profile JSON file")
        p.add_argument("--user-profile", default="usr-local-default", help="Opaque user profile ID")
        p.add_argument("--json", action="store_true", help="Output deterministic JSON to stdout")

    rc_insp = rc_sub.add_parser("inspect", help="Inspect accounts, model entitlements, quotas, and policy")
    _add_routing_common_flags(rc_insp)

    rc_accts = rc_sub.add_parser("accounts", help="List isolated per-application account contexts")
    _add_routing_common_flags(rc_accts)

    rc_models = rc_sub.add_parser("models", help="Inspect model entitlements for a specific opaque account ID")
    rc_models.add_argument("--account", required=True, help="Opaque account_context_id")
    _add_routing_common_flags(rc_models)

    rc_pol = rc_sub.add_parser("policy", help="Inspect user routing policy")
    rc_pol_sub = rc_pol.add_subparsers(dest="policy_command", required=True)
    rc_pol_show = rc_pol_sub.add_parser("show", help="Show active user routing policy")
    _add_routing_common_flags(rc_pol_show)

    rc_plan = rc_sub.add_parser("plan", help="Generate a dry-run capability-based route plan for a task profile")
    rc_plan.add_argument("--task-profile", required=True, help="Path to JSON task profile")
    _add_routing_common_flags(rc_plan)

    rc_exp = rc_sub.add_parser("explain", help="Explain a persisted routing decision from a disposable DB")
    rc_exp.add_argument("--decision-id", required=True, help="Opaque routing decision ID")
    rc_exp.add_argument("--db", required=True, help="Read-only SQLite DB path")
    rc_exp.add_argument("--json", action="store_true", help="Output deterministic JSON to stdout")

    args = parser.parse_args()
    if args.command == "routing":
        payload = execute_routing_command(args)
        if getattr(args, "json", False) or args.routing_command not in ("inspect", "plan"):
            LOGGER.console(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        elif args.routing_command == "inspect":
            LOGGER.console(render_routing_inspect_text(payload))
        else:
            LOGGER.console(render_route_plan_text(payload))
        return

    if args.command == "runtime":
        if args.runtime_command == "discover":
            proj_path = Path(args.project_path).expanduser().resolve() if args.project_path else None
            coordinator = RuntimeDiscoveryCoordinator(timeout_seconds=args.timeout)
            report = coordinator.discover(project_path=proj_path, run_id=args.run_id)
            json_text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
            if args.output:
                out_target = Path(args.output).expanduser().resolve()
                if out_target.suffix.lower() == ".md":
                    out_target.parent.mkdir(parents=True, exist_ok=True)
                    out_target.write_text(render_application_inventory_markdown(report), encoding="utf-8")
                elif out_target.suffix.lower() == ".json":
                    out_target.parent.mkdir(parents=True, exist_ok=True)
                    out_target.write_text(json_text + "\n", encoding="utf-8")
                else:
                    out_target.mkdir(parents=True, exist_ok=True)
                    (out_target / "runtime-discovery.json").write_text(json_text + "\n", encoding="utf-8")
            if args.json:
                LOGGER.console(json_text)
            elif args.output:
                LOGGER.console(str(Path(args.output).expanduser().resolve()))
            else:
                LOGGER.console(render_application_inventory_markdown(report))
        return

    if args.command == "integrity-check":
        # Before initialize(): a damaged database must be reported, not crash the migration step.
        res = check_database_integrity(DB_PATH)
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
        if not res["ok"]:
            raise SystemExit(1)
        return

    initialize(DB_PATH)
    from model_registry import configure_routing_store

    configure_routing_store(DB_PATH)

    if args.command == "init":
        LOGGER.console(f"Database initialized: {DB_PATH}")
    elif args.command == "register":
        register(args)
    elif args.command == "discover-projects":
        items = discover_antigravity_projects()
        LOGGER.console(json.dumps(items, ensure_ascii=False, indent=2))
    elif args.command in ("scheduled-audit", "audit-now"):
        summary = scheduled_audit(args.project, max_verification_jobs=args.max_verification_jobs,
                                  manual=args.command == "audit-now")
        LOGGER.console(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
        if summary.get("result") not in ("FINALIZED", "SKIPPED_AWAITING_REVIEW", "SKIPPED_NO_CHANGES"):
            raise SystemExit(2)
    elif args.command == "schedule":
        import weekly_scheduler as ws

        cli_path = Path(__file__).resolve()
        if args.schedule_command == "install":
            result = ws.install(APP_HOME, cli_path, day=args.day, time=args.time)
            if not args.keep_sidecars:
                from db import connect as _db_connect

                with _db_connect(DB_PATH) as conn:
                    keys = [r[0] for r in conn.execute("SELECT project_key FROM projects").fetchall()]
                result["sidecars"] = ws.remove_legacy_sidecars(APP_HOME, SIDECAR_ROOT, CONFIG_PATH, keys)
        elif args.schedule_command == "status":
            result = {"marker": ws.uses_windows_task(APP_HOME), **ws.status()}
        else:
            result = ws.remove(APP_HOME)
        LOGGER.console(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.command == "weekly":
        from weekly_scheduler import run_weekly

        result = run_weekly(APP_HOME, DB_PATH, Path(__file__).resolve(), jsonl_path=JSONL_PATH)
        LOGGER.console(json.dumps(result, ensure_ascii=False, indent=2))
        if any(step["exit_code"] != 0 for step in result["steps"]):
            raise SystemExit(1)  # the scheduled task's "last result" then shows the run had a problem
    elif args.command == "deliver":
        from auto_delivery import run_delivery

        result = run_delivery(DB_PATH, args.exec_id, jsonl_path=JSONL_PATH)
        LOGGER.console(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    elif args.command == "dispatch":
        dispatch(args.project, stale_timeout_seconds=args.stale_seconds)
    elif args.command == "publish-report":
        publish_report(args)
    elif args.command == "generate-report":
        out = Path(args.output).resolve() if args.output else None
        text = generate_review_report(DB_PATH, project_key=args.project, run_id=args.run_id, output_path=out)
        LOGGER.console(str(out) if out else text)
    elif args.command == "verifier-worker":
        worker = VerificationWorker(
            DB_PATH,
            app_home=APP_HOME,
            project_key=args.project,
            worker_id=args.worker_id,
            lease_seconds=args.lease_seconds,
            jsonl_path=JSONL_PATH,
        )
        processed = worker.run_loop(once=args.once, poll_interval_seconds=args.poll_interval)
        LOGGER.console(json.dumps({"processed": processed}, ensure_ascii=False, indent=2))
    elif args.command == "verifier-status":
        if args.run_id:
            res = get_verification_status(DB_PATH, audit_run_id=args.run_id)
        else:
            res = get_verifier_worker_status(
                DB_PATH,
                project_key=args.project,
                sidecar_root=SIDECAR_ROOT,
                config_path=CONFIG_PATH,
            )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "generate-verification-prompt":
        prompt_text = build_verification_prompt(
            DB_PATH,
            audit_run_id=args.run_id,
            verification_run_id=args.verification_run_id,
            app_home=APP_HOME,
        )
        if args.output:
            out_file = Path(args.output).expanduser().resolve()
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(prompt_text, encoding="utf-8")
            LOGGER.console(str(out_file))
        else:
            LOGGER.console(prompt_text)
    elif args.command == "verification-context":
        from verification import get_verification_context

        ctx = get_verification_context(
            DB_PATH,
            audit_run_id=args.run_id,
            verification_run_id=args.verification_run_id,
        )
        ctx_json = json.dumps(ctx, ensure_ascii=False, indent=2, default=str)
        if args.output:
            out_file = Path(args.output).expanduser().resolve()
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(ctx_json, encoding="utf-8")
            LOGGER.console(str(out_file))
        else:
            LOGGER.console(ctx_json)
    elif args.command == "enable-verifier-sidecar":
        res = configure_verifier_sidecar(
            DB_PATH,
            project_key=slug(args.project),
            sidecar_root=SIDECAR_ROOT,
            config_path=CONFIG_PATH,
            cli_path=ROOT / "core" / "cli.py",
            python_exe=sys.executable,
            enable=True,
            register_in_config=True,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "disable-verifier-sidecar":
        res = configure_verifier_sidecar(
            DB_PATH,
            project_key=slug(args.project),
            sidecar_root=SIDECAR_ROOT,
            config_path=CONFIG_PATH,
            cli_path=ROOT / "core" / "cli.py",
            python_exe=sys.executable,
            enable=False,
            register_in_config=True,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "generate-verifier-sidecars":
        if args.project:
            info = configure_verifier_sidecar(
                DB_PATH,
                project_key=slug(args.project),
                sidecar_root=SIDECAR_ROOT,
                config_path=CONFIG_PATH,
                cli_path=ROOT / "core" / "cli.py",
                python_exe=sys.executable,
                enable=False,
                register_in_config=False,
            )
            LOGGER.console(json.dumps({"generated_count": 1, "skipped_count": 0, "generated": [info], "skipped": []}, ensure_ascii=False, indent=2))
        else:
            res = generate_all_verifier_sidecars(
                DB_PATH,
                sidecar_root=SIDECAR_ROOT,
                config_path=CONFIG_PATH,
                cli_path=ROOT / "core" / "cli.py",
                python_exe=sys.executable,
                enable=False,
                register_in_config=False,
            )
            LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "recover-verification":
        res = recover_verification_job(
            DB_PATH,
            project_key=slug(args.project),
            audit_run_id=args.run_id,
            action=args.action,
            verifier_conversation_id=args.conversation_id,
            candidate_finding_id=args.candidate_id,
            jsonl_path=JSONL_PATH,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "submit-verification":
        if args.file:
            raw_v = Path(args.file).expanduser().resolve().read_text(encoding="utf-8-sig")
        elif args.results_json:
            raw_v = args.results_json
        else:
            raise RuntimeError("Provide either --file or --results-json.")
        parsed_v = json.loads(raw_v)
        if isinstance(parsed_v, dict):
            results_arr = parsed_v.get("verification_results", [])
            disc_arr = parsed_v.get("verifier_discovered_findings")
            meta_obj = parsed_v.get("verifier_metadata") or {}
        else:
            results_arr = parsed_v
            disc_arr = None
            meta_obj = {}
        if args.model_id:
            meta_obj["verifier_model_id"] = args.model_id
        if args.agent_id:
            meta_obj["verifier_agent_id"] = args.agent_id
        meta_obj.setdefault("invocation_mechanism", args.mechanism)
        meta_obj.setdefault("actual_subagent_invocations", args.subagent_invocations)

        res = submit_verification_results(
            DB_PATH,
            audit_run_id=args.run_id,
            verification_run_id=args.verification_run_id,
            verifier_conversation_id=args.conversation_id,
            verifier_metadata=meta_obj,
            verification_results=results_arr,
            verifier_discovered_findings=disc_arr,
            jsonl_path=JSONL_PATH,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "finalize-verified-report":
        res = finalize_verified_report(
            DB_PATH,
            audit_run_id=args.run_id,
            verification_run_id=args.verification_run_id,
            jsonl_path=JSONL_PATH,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "quality-report":
        res = get_quality_report(
            DB_PATH,
            project_key=args.project,
            audit_run_id=args.run_id,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "save-decisions":
        if args.file:
            raw = Path(args.file).read_text(encoding="utf-8-sig")
        elif args.decisions_json:
            raw = args.decisions_json
        else:
            raise RuntimeError("Provide either --file or --decisions-json.")
        assert_not_markdown_checkbox(raw, "save-decisions input")
        payload = json.loads(raw)
        res = save_decisions(
            DB_PATH,
            project_key=args.project,
            run_id=args.run_id,
            decisions=payload,
            actor=args.actor,
            jsonl_path=JSONL_PATH,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command in ("authorize-execution", "approve"):
        # Human-only gate (APPLY without Windows Hello): an interactive terminal plus a y/N confirmation after
        # seeing exactly which findings will be fixed. Agents (MCP, headless agy, scheduled tasks) have no TTY.
        from db import connect as _db_connect
        from project_settings import resolve_run_id

        if not args.run_id:
            with _db_connect(DB_PATH) as conn:
                args.run_id = resolve_run_id(conn, args.project, None)
        preview = _apply_preview(args.project, args.run_id)
        LOGGER.console(json.dumps({"project": args.project, "run_id": args.run_id, "apply": preview}, ensure_ascii=False, indent=2))
        if not preview:
            raise SystemExit("No findings have an active APPLY decision for this run; nothing to authorize.")
        from db import connect as _db_connect

        with _db_connect(DB_PATH) as conn:
            anomaly = conn.execute("SELECT evidence_anomaly_json FROM audit_runs WHERE run_id=?",
                                   (args.run_id,)).fetchone()
        if anomaly and anomaly[0]:
            LOGGER.console(json.dumps({"warning": (
                "Evidence anomaly in this run: the verifier quoted code that does not exist for the findings below, "
                "which were rejected. Its other confirmations deserve extra scrutiny."),
                "rejected": json.loads(anomaly[0])}, ensure_ascii=False, indent=2))
        single = [str(f["finding_id"]) for f in preview if not int(f.get("model_independent") or 0)]
        if single:
            LOGGER.console(json.dumps({"warning": (
                "These findings were verified without an independent second model (same model line, or models "
                "not attested); review the resulting branch with extra care."), "finding_ids": single}, indent=2))
        decided_by = _require_interactive_yes(f"Fix these {len(preview)} finding(s) of {args.run_id} in an isolated worktree?")
        res = authorize_execution(
            DB_PATH,
            project_key=args.project,
            run_id=args.run_id,
            authorized_by=decided_by,
            ttl_seconds=args.ttl_seconds,
            confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
            jsonl_path=JSONL_PATH,
            expected_finding_ids=[str(f["finding_id"]) for f in preview],
        )
        res = {k: v for k, v in res.items() if k != "approval_token"}
        res["next_step"] = (
            f"In Antigravity, tell the agent: \"start the approved fix for {args.project}\" "
            f"(it finds this approval by itself; valid until {res.get('expires_at')})."
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "apply-policy":
        apply_policy_command(args)
    elif args.command == "project-settings":
        project_settings_command(args)
    elif args.command == "execute-approved":
        if args.start_only:
            res = start_isolated_execution(
                DB_PATH,
                project_key=args.project,
                approval_token=args.approval_token,
                worktrees_root=APP_HOME / "worktrees",
                jsonl_path=JSONL_PATH,
            )
        else:
            res = execute_approved_findings(
                DB_PATH,
                project_key=args.project,
                approval_token=args.approval_token,
                worktrees_root=APP_HOME / "worktrees",
                checkpoints_root=APP_HOME / "checkpoints",
                quarantine_root=APP_HOME / "quarantine",
                jsonl_path=JSONL_PATH,
            )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "recover":
        if args.force_stale:
            stale = recover_stale_runs(
                DB_PATH,
                project_key=args.project,
                stale_timeout_seconds=args.stale_seconds,
                force=True,
                jsonl_path=JSONL_PATH,
            )
            LOGGER.console(json.dumps(stale, ensure_ascii=False, indent=2))
        else:
            res = run_health_and_recovery(
                DB_PATH,
                project_key=args.project,
                stale_timeout_seconds=args.stale_seconds,
                create_verified_backup=not args.no_backup,
                jsonl_path=JSONL_PATH,
            )
            LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "backup":
        out_dir = Path(args.output_dir).resolve() if args.output_dir else None
        b_path = backup_database(DB_PATH, backup_dir=out_dir, jsonl_path=JSONL_PATH)
        verify = verify_backup_restore(b_path)
        LOGGER.console(json.dumps(verify, ensure_ascii=False, indent=2))
    elif args.command == "verify-backup":
        restore_to = Path(args.restore_to).resolve() if args.restore_to else None
        res = verify_backup_restore(Path(args.file).resolve(), restore_target=restore_to)
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "integrity-check":
        res = check_database_integrity(DB_PATH)
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
        if not res["ok"]:
            raise SystemExit(1)
    elif args.command == "register-mcp":
        res = register_mcp_server_config(
            MCP_CONFIG_PATH,
            app_home=APP_HOME,
            python_exe=sys.executable,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "mcp-serve":
        mcp_serve_main()
    elif args.command == "status":
        show_status(args)
    elif args.command == "inventory-skills":
        rows = sync_inventory(args.project)
        for row in rows:
            LOGGER.console(f"{row['scope']} | {row['name']} | {row['path']}")
        LOGGER.console(f"Total discovered skills: {len(rows)}")
    elif args.command == "install-global-skills":
        src_dirs = [ROOT / "global-skills"]
        if args.include_omniapex:
            src_dirs.append(ROOT / "integrations" / "omniapex" / ".agents" / "skills")
        b_root = Path(args.backup_root).expanduser().resolve() if args.backup_root else None
        res = install_global_skills_safely(
            src_dirs,
            Path(args.target_root).expanduser().resolve(),
            backup_root=b_root,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.command == "model-route":
        req = ModelRoutingRequest(
            task_type=args.task,
            severity=args.severity,
            finding_category=args.category,
            evidence_gate_status=args.evidence_gate,
            explicit_operator_escalation=args.escalate,
            operator_escalation_reason=args.escalate_reason,
        )
        decision = route_model(req, db_path=DB_PATH)
        LOGGER.console(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
    elif args.command == "model-status":

        def _safe_routing_table_dict() -> dict:
            try:
                return get_active_routing_table().to_dict()
            except RoutingTableError as exc:
                return {"error": "ROUTING_TABLE_UNAVAILABLE", "detail": str(exc)}

        def _safe_approved_models() -> list:
            try:
                return approved_model_slugs()
            except RoutingTableError:
                return []

        adapter = AntigravityCliAdapter()
        exe = adapter.discover_executable()
        status_info = {
            "adapter": "AntigravityCliAdapter",
            "cli_executable": str(exe) if exe else None,
            "cli_available": exe is not None and exe.is_file(),
            "policy_version": POLICY_VERSION,
            "host_app": current_host_app(),
            "routing_table": _safe_routing_table_dict(),
            "approved_models": _safe_approved_models(),
            "dispatch_backends": [
                {"backend": b.backend, "available": b.available, "detail": b.detail}
                for b in discover_dispatch_backends()
            ],
            "repair_worker_writable_dispatch": "DISABLED",
            "permission_mode": "plan",
            "cross_model_verification_required": True,
        }
        LOGGER.console(json.dumps(status_info, ensure_ascii=False, indent=2))
    elif args.command == "models":
        from model_catalog import catalog_overview, routing_table_health, sync_catalog

        initialize(DB_PATH)
        if args.models_command == "sync":
            result = sync_catalog(DB_PATH, timeout_seconds=args.timeout)
            result["table_health"] = routing_table_health(DB_PATH)
            if args.probe and result["status"] != "ERROR":
                # Not only when this sync saw the change: an earlier sync (e.g. before a manual audit) may have
                # recorded the new models already. Models that already have a probe result are skipped.
                from model_probes import probe_models

                result["probes"] = probe_models(DB_PATH, include_scarce=False, only_unprobed=True)
            if getattr(args, "research_new", False) and result["status"] != "ERROR":
                from model_research import run_research, unresearched_lines

                missing = unresearched_lines(DB_PATH)
                if missing:  # a new model line can only be proposed once research has placed it
                    res = run_research(DB_PATH)
                    result["research"] = {"status": res.get("status"), "report_id": res.get("report_id"),
                                          "lines": missing}
            if args.propose and result["status"] != "ERROR":
                from model_routing_proposals import create_proposal

                result["proposal"] = create_proposal(DB_PATH)
            LOGGER.console(json.dumps(result, ensure_ascii=False, indent=2))
            if result["status"] == "ERROR" or result["table_health"]["status"] in ("STALE", "INVALID"):
                raise SystemExit(2)
        elif args.models_command == "probe":
            from model_probes import probe_models

            result = probe_models(
                DB_PATH,
                models=args.model,
                include_scarce=args.include_scarce,
                only_unprobed=not args.reprobe,
                max_probes=args.max,
                timeout_seconds=args.timeout,
            )
            LOGGER.console(json.dumps(result, ensure_ascii=False, indent=2))
            if any(r["status"] in ("ERROR", "FAILED", "ATTESTATION_FAILED") for r in result["results"]):
                raise SystemExit(2)
        elif args.models_command == "schedule":
            if not args.remove and not args.project:
                raise SystemExit("models schedule requires --project (or --remove).")
            result = schedule_models_sync(project_key=args.project or "", cron=args.cron, remove=args.remove)
            LOGGER.console(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.models_command == "research":
            from model_research import run_research

            result = run_research(DB_PATH, timeout_seconds=args.timeout)
            LOGGER.console(json.dumps(result, ensure_ascii=False, indent=2))
            if result["status"] != "COMPLETED":
                raise SystemExit(2)
        elif args.models_command == "propose":
            from model_routing_proposals import create_proposal

            LOGGER.console(json.dumps(create_proposal(DB_PATH), ensure_ascii=False, indent=2))
        elif args.models_command == "proposal":
            from model_routing_proposals import (
                ProposalError,
                approve_proposal,
                pending_proposal,
                reject_proposal,
                table_history,
            )

            if args.proposal_command == "show":
                LOGGER.console(json.dumps({"pending": pending_proposal(DB_PATH), "history": table_history(DB_PATH)},
                                          ensure_ascii=False, indent=2))
            else:
                verb = "APPROVE" if args.proposal_command == "approve" else "REJECT"
                decided_by = _require_interactive_confirmation(verb, args.version_id)
                try:
                    if verb == "APPROVE":
                        out = approve_proposal(DB_PATH, args.version_id, decided_by=decided_by, note=args.note)
                    else:
                        out = reject_proposal(DB_PATH, args.version_id, decided_by=decided_by, note=args.note)
                except ProposalError as exc:
                    LOGGER.console(json.dumps({"error": str(exc)}, ensure_ascii=False))
                    raise SystemExit(2)
                LOGGER.console(json.dumps(out, ensure_ascii=False, indent=2))
        elif args.models_command == "revert-to-seed":
            from model_routing_proposals import revert_to_seed

            decided_by = _require_interactive_confirmation("REVERT", "SEED")
            LOGGER.console(json.dumps(revert_to_seed(DB_PATH, decided_by=decided_by), ensure_ascii=False, indent=2))
        elif args.models_command == "overview":
            LOGGER.console(json.dumps(catalog_overview(DB_PATH, include_models=not args.no_models), ensure_ascii=False, indent=2))
    elif args.command == "model-attest":
        from model_catalog import known_model_lines

        res = attest_conversation_model(
            args.conversation_id,
            args.expected_model,
            conversations_dir=args.conversations_dir,
            known_model_lines=known_model_lines(DB_PATH),
        )
        LOGGER.console(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
    elif args.command == "model-budget":
        from db import connect, get_budget_usage_for_run, list_model_dispatches_for_run

        with connect(DB_PATH) as conn:
            usage = get_budget_usage_for_run(conn, args.run_id, model_id=args.model)
            dispatches = list_model_dispatches_for_run(conn, args.run_id)
        report = {
            "audit_run_id": args.run_id,
            "model_filter": args.model,
            "total_tokens_consumed": usage["total_tokens"],
            "total_requests": usage["total_requests"],
            "dispatch_count": len(dispatches),
            "dispatches": dispatches,
        }
        LOGGER.console(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.command == "model-dispatch":
        prompt_val = args.prompt
        p_path = Path(prompt_val).expanduser()
        if p_path.is_file():
            prompt_val = p_path.read_text(encoding="utf-8")
        res = dispatch_routed_task(
            prompt=prompt_val,
            task_type=args.task,
            cwd=Path(args.cwd).resolve() if args.cwd else None,
            audit_run_id=args.run_id,
            verification_run_id=args.verification_run_id,
            finding_fingerprint=args.fingerprint,
            severity=args.severity,
            finding_category=args.category,
            evidence_gate_status=args.evidence_gate,
            execution_intent=args.intent,
            explicit_operator_escalation=args.escalate,
            operator_escalation_reason=args.escalate_reason,
            timeout_seconds=args.timeout,
        )
        LOGGER.console(json.dumps(res, ensure_ascii=False, indent=2))
        if not res["ok"]:
            raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        LOGGER.console(f"ERROR: {exc}", error=True)
        raise SystemExit(1)
