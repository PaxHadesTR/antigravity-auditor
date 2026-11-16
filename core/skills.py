from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path
from typing import Any, Iterable

SAFE_SKILL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_TRUSTED_SKILL_SIZE = 64 * 1024  # 64 KB

RELEVANT_AUDIT_PROTOCOL_SKILLS: frozenset[str] = frozenset({
    "project-auditor-orchestrator",
    "independent-audit-verifier",
    "prompt-co-architect",
    "adversarial-red-team",
    "release-and-handoff",
})


def resolve_trusted_skill_path(
    skill_name: str,
    *,
    package_root: Path | None = None,
) -> Path:
    """Resolve a skill's SKILL.md path strictly within the trusted application bundle.

    Validates that skill_name conforms to safe identifier rules and that the resolved path
    remains strictly inside the trusted application skill directories.
    Fails closed (ValueError or FileNotFoundError) if name is unsafe, path escapes root,
    or the file does not exist.
    """
    if not isinstance(skill_name, str) or not SAFE_SKILL_NAME_PATTERN.match(skill_name):
        raise ValueError(f"Invalid or unsafe skill name: {skill_name!r}")

    pkg = (package_root or Path(__file__).resolve().parents[1]).resolve()
    trusted_roots = [
        (pkg / "global-skills").resolve(),
        (pkg / "integrations" / "omniapex" / ".agents" / "skills").resolve(),
    ]

    for root in trusted_roots:
        if not root.is_dir():
            continue
        candidate = (root / skill_name / "SKILL.md").resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            # Traversal escape
            continue
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        f"Trusted skill '{skill_name}' not found within trusted application roots: {[str(r) for r in trusted_roots]}"
    )


def load_trusted_skill_content(
    skill_name: str,
    *,
    package_root: Path | None = None,
    max_size: int = MAX_TRUSTED_SKILL_SIZE,
) -> str:
    """Load trusted skill markdown content from application roots, enforcing strict limits.

    Fails closed if the skill does not exist, exceeds max_size, or is invalid/empty.
    """
    skill_path = resolve_trusted_skill_path(skill_name, package_root=package_root)
    stat = skill_path.stat()
    if stat.st_size > max_size:
        raise RuntimeError(
            f"Trusted skill '{skill_name}' file size ({stat.st_size} bytes) exceeds limit ({max_size} bytes)"
        )
    raw = skill_path.read_bytes()
    if len(raw) > max_size:
        raise RuntimeError(
            f"Trusted skill '{skill_name}' content length ({len(raw)} bytes) exceeds limit ({max_size} bytes)"
        )
    content = raw.decode("utf-8-sig", errors="replace")
    if not content.strip():
        raise RuntimeError(f"Trusted skill '{skill_name}' is empty")
    return content


def format_trusted_skill_section(
    skill_name: str,
    content: str,
) -> str:
    """Format trusted skill content as an isolated, delimited prompt section."""
    return (
        f"=== BEGIN TRUSTED AUDIT PROTOCOL INSTRUCTIONS ({skill_name}) ===\n"
        f"# The following operational instructions are pre-loaded by the trusted control plane.\n"
        f"# You DO NOT need to read external files to access this protocol.\n"
        f"# Do NOT call read_file or any tool on the Auditor installation directory or external paths.\n\n"
        f"{content.strip()}\n"
        f"=== END TRUSTED AUDIT PROTOCOL INSTRUCTIONS ({skill_name}) ==="
    )


def sanitize_skill_inventory_for_model(
    rows: Iterable[dict[str, Any]],
    *,
    allowed_protocol_skills: set[str] | frozenset[str] | None = None,
) -> list[dict[str, str]]:
    """Sanitize skill inventory for model-facing context (MCP responses and prompts).

    - Strips all absolute filesystem paths (`path`) and file hashes (`sha256`).
    - Filters bundle/global skills down to relevant audit protocol skills.
    - Preserves workspace-scoped skills if present.
    - Returns minimal safe metadata: name, scope, description.
    """
    protocol_set = allowed_protocol_skills or RELEVANT_AUDIT_PROTOCOL_SKILLS
    sanitized: list[dict[str, str]] = []
    seen: set[str] = set()

    for r in rows:
        name = str(r.get("name", "")).strip()
        if not name or name in seen:
            continue
        scope = str(r.get("scope", "")).strip()
        if name in protocol_set or scope.startswith("workspace"):
            seen.add(name)
            sanitized.append({
                "name": name,
                "scope": scope,
                "description": str(r.get("description", "")).strip(),
            })

    return sorted(sanitized, key=lambda x: (0 if x["name"] in protocol_set else 1, x["name"]))


def _frontmatter(text: str) -> tuple[str, str]:
    """Parse YAML frontmatter name and description (including multiline block scalars)."""
    name = "unknown"
    description = ""
    if not text.startswith("---"):
        return name, description
    parts = text.split("---", 2)
    if len(parts) < 3:
        return name, description

    lines = parts[1].splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if stripped.startswith("name:"):
            val = stripped.split(":", 1)[1].strip().strip("\"'")
            if val:
                name = val
            idx += 1
        elif stripped.startswith("description:"):
            val = stripped.split(":", 1)[1].strip()
            if val in (">-", ">", "|-", "|", ""):
                collected: list[str] = []
                idx += 1
                while idx < len(lines):
                    sub = lines[idx]
                    if sub.startswith((" ", "\t")) or not sub.strip():
                        if sub.strip():
                            collected.append(sub.strip())
                        idx += 1
                    else:
                        break
                description = " ".join(collected).strip()
            else:
                description = val.strip("\"'")
                idx += 1
        else:
            idx += 1
    return name, description


def discover_skill_files(
    repo_path: Path | None = None,
    *,
    project_key: str | None = None,
    home_dir: Path | None = None,
    package_root: Path | None = None,
) -> list[tuple[str, Path]]:
    home = home_dir or Path.home()
    pkg = package_root or Path(__file__).resolve().parents[1]
    locations: list[tuple[str, Path]] = [
        ("global", home / ".gemini" / "config" / "skills"),
        ("universal-kit-source", home / ".gemini" / "universal-kit" / ".agents" / "skills"),
        ("bundle-global", pkg / "global-skills"),
        ("bundle-omniapex", pkg / "integrations" / "omniapex" / ".agents" / "skills"),
    ]
    if repo_path:
        ws_scope = f"workspace:{project_key}" if project_key else "workspace"
        locations.append((ws_scope, repo_path / ".agents" / "skills"))
        locations.append((ws_scope, repo_path / ".agent" / "skills"))
    found: dict[Path, str] = {}
    for scope, directory in locations:
        if directory.is_dir():
            for skill_md in sorted(directory.glob("*/SKILL.md")):
                resolved = skill_md.resolve()
                if resolved not in found:
                    found[resolved] = scope
    return [(scope, path) for path, scope in found.items()]


def inventory(
    repo_path: Path | None = None,
    *,
    project_key: str | None = None,
    home_dir: Path | None = None,
    package_root: Path | None = None,
) -> list[dict[str, str]]:
    rows = []
    for scope, path in discover_skill_files(
        repo_path,
        project_key=project_key,
        home_dir=home_dir,
        package_root=package_root,
    ):
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig", errors="replace")
        name, description = _frontmatter(text)
        if name == "unknown":
            name = path.parent.name
        rows.append({
            "scope": scope,
            "name": name,
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "description": description,
        })
    return sorted(rows, key=lambda x: (x["scope"], x["name"], x["path"]))


def inventory_rules(repo_path: Path | None = None, *, home_dir: Path | None = None) -> list[dict[str, str]]:
    """Inventory global AGENTS.md and workspace .agents/rules/*.md files without modifying them."""
    home = home_dir or Path.home()
    items: list[dict[str, str]] = []
    global_agents = home / ".gemini" / "AGENTS.md"
    if global_agents.is_file():
        raw = global_agents.read_bytes()
        items.append({
            "scope": "global-rule",
            "name": "AGENTS.md",
            "path": str(global_agents.resolve()),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    if repo_path and (repo_path / ".agents" / "rules").is_dir():
        for rule_md in sorted((repo_path / ".agents" / "rules").glob("*.md")):
            raw = rule_md.read_bytes()
            items.append({
                "scope": "workspace-rule",
                "name": rule_md.name,
                "path": str(rule_md.resolve()),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
    return items


def relevant_skill_instruction(rows: Iterable[dict[str, str]]) -> str:
    names = sorted({r["name"] for r in rows if r.get("name")})
    priority = [
        "project-auditor-orchestrator",
        "independent-audit-verifier",
        "prompt-co-architect",
        "adversarial-red-team",
        "release-and-handoff",
    ]
    ordered = [x for x in priority if x in names] + [x for x in names if x not in priority]
    if not ordered:
        return "No discoverable custom skills were found."
    return (
        "Discovered skills: "
        + ", ".join(ordered)
        + ". Operational audit protocols are pre-loaded into your prompt by the control plane. "
        "Do NOT attempt to read external skill files or filesystem paths outside the monitored repository."
    )


def compute_skill_dir_hash(skill_dir: Path) -> str:
    """Compute a deterministic SHA-256 hash over all files in a skill directory (excluding cache files)."""
    digest = hashlib.sha256()
    resolved = skill_dir.resolve()
    if not resolved.is_dir():
        return ""
    for file_path in sorted(resolved.rglob("*")):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(resolved).as_posix()
        # Same exclusions as the copy (ignore_patterns in install_global_skills_safely).
        if (
            "__pycache__" in file_path.parts
            or ".pytest_cache" in file_path.parts
            or file_path.suffix.lower() in (".pyc", ".pyo")
        ):
            continue
        digest.update(rel.encode("utf-8"))
        # Normalize CRLF/LF on text files so line-ending differences don't cause false conflicts
        raw = file_path.read_bytes().replace(b"\r\n", b"\n")
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def install_global_skills_safely(
    source_dirs: Iterable[Path],
    target_skills_root: Path,
    *,
    backup_root: Path | None = None,
) -> dict[str, Any]:
    """Install bundle skills into target_skills_root without overwriting customized existing skills.

    - Missing skill directories are copied cleanly (excluding `__pycache__` / `*.pyc`).
    - Existing skill directories with identical content hashes are left untouched (`unchanged`).
    - Existing skill directories with modified/custom content are NEVER overwritten (`preserved_custom`);
      if `backup_root` is provided, a backup of the customized skill and the incoming bundle version are saved there.
    - Unrelated skill directories in `target_skills_root` are preserved untouched (`preserved_other`).
    """
    target_skills_root.mkdir(parents=True, exist_ok=True)
    installed: list[str] = []
    unchanged: list[str] = []
    preserved_custom: list[dict[str, Any]] = []
    seen_bundle_names: set[str] = set()
    ignore_fn = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".pytest_cache")

    for src_root in source_dirs:
        if not src_root or not src_root.is_dir():
            continue
        for src_skill in sorted(src_root.iterdir()):
            if not src_skill.is_dir() or not (src_skill / "SKILL.md").is_file():
                continue
            skill_name = src_skill.name
            if skill_name in seen_bundle_names:
                # A later bundle root with the same skill name: the first root wins; do not mistake the copy
                # installed a moment ago for a user customization.
                continue
            seen_bundle_names.add(skill_name)
            dest_skill = target_skills_root / skill_name
            src_hash = compute_skill_dir_hash(src_skill)

            if not dest_skill.exists():
                shutil.copytree(src_skill, dest_skill, ignore=ignore_fn)
                installed.append(skill_name)
                continue

            dest_hash = compute_skill_dir_hash(dest_skill)
            if src_hash == dest_hash:
                unchanged.append(skill_name)
                continue

            backup_path_str: str | None = None
            staged_bundle_str: str | None = None
            if backup_root is not None:
                backup_root.mkdir(parents=True, exist_ok=True)
                b_dest = backup_root / skill_name
                if b_dest.exists():
                    shutil.rmtree(b_dest)
                shutil.copytree(dest_skill, b_dest, ignore=ignore_fn)
                backup_path_str = str(b_dest)

                s_dest = backup_root / f"{skill_name}.bundle-new"
                if s_dest.exists():
                    shutil.rmtree(s_dest)
                shutil.copytree(src_skill, s_dest, ignore=ignore_fn)
                staged_bundle_str = str(s_dest)

            preserved_custom.append({
                "skill_name": skill_name,
                "target_path": str(dest_skill),
                "existing_sha256": dest_hash,
                "bundle_sha256": src_hash,
                "backup_path": backup_path_str,
                "staged_bundle_path": staged_bundle_str,
                "warning": (
                    f"Preserved customized global skill '{skill_name}' at '{dest_skill}' "
                    "(content differs from bundle; existing skill was NOT overwritten)."
                ),
            })

    preserved_other = sorted(
        d.name
        for d in target_skills_root.iterdir()
        if d.is_dir() and d.name not in seen_bundle_names
    )

    return {
        "target_skills_root": str(target_skills_root),
        "installed": installed,
        "unchanged": unchanged,
        "preserved_custom": preserved_custom,
        "preserved_other": preserved_other,
    }
