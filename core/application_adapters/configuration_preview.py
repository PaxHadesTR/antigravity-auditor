"""Secret-free, validated, unapplied configuration preview & offline .mcpb builder."""

from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib
from typing import Any
import zipfile

from application_adapters.contracts import AdapterConfigPreview, contains_secret_material

_SHELL_WRAPPER_TOKENS = ("powershell", "cmd /c", "cmd.exe /c", "bash -c", "sh -c", "&&", "|", ";")


def validate_launch_command(command: str, args: list[str]) -> list[str]:
    """Ensure preview launch commands are direct executable + args without shell wrappers or secrets."""
    errors: list[str] = []
    if not command or not str(command).strip():
        errors.append("MISSING_LAUNCH_COMMAND")
        return errors
    joined = " ".join([str(command)] + [str(a) for a in args])
    lowered = joined.lower()
    for tok in _SHELL_WRAPPER_TOKENS:
        if tok in lowered:
            errors.append(f"DISALLOWED_SHELL_WRAPPER:{tok}")
    if contains_secret_material(joined):
        errors.append("SECRET_IN_LAUNCH_ARGS")
    if re.search(r"(?i)(token|secret|api_key|apikey|password|hmac)=", joined):
        errors.append("CREDENTIAL_FLAG_IN_ARGS")
    return errors


def validate_preview_item(preview: AdapterConfigPreview) -> AdapterConfigPreview:
    """Validate syntax (JSON/TOML), secret freedom, and launch-safety of an unapplied preview."""
    errors = list(preview.validation_errors)
    text = preview.content_text
    secret_free = True

    if contains_secret_material(text) or contains_secret_material(json.dumps(preview.manual_install_steps)):
        secret_free = False
        errors.append("SECRET_MATERIAL_DETECTED")

    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        errors.append("EMAIL_PII_DETECTED")

    if preview.content_format in ("json", "dxt_manifest"):
        try:
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                errors.append("JSON_ROOT_MUST_BE_OBJECT")
        except json.JSONDecodeError as exc:
            errors.append(f"INVALID_JSON:{exc}")
    elif preview.content_format == "toml":
        try:
            parsed_toml = tomllib.loads(text)
            if not isinstance(parsed_toml, dict):
                errors.append("TOML_ROOT_MUST_BE_TABLE")
        except Exception as exc:
            errors.append(f"INVALID_TOML:{exc}")
    else:
        errors.append(f"UNKNOWN_CONTENT_FORMAT:{preview.content_format}")

    return AdapterConfigPreview(
        application_id=preview.application_id,
        scope_name=preview.scope_name,
        target_path=preview.target_path,
        content_format=preview.content_format,
        content_text=preview.content_text,
        validation_ok=(len(errors) == 0 and secret_free),
        validation_errors=tuple(errors),
        applied=False,
        secret_free=secret_free,
        manual_install_steps=preview.manual_install_steps,
        rollback_steps=preview.rollback_steps,
        warnings=preview.warnings,
    )


def build_offline_mcpb_archive(
    *,
    manifest_json_text: str,
    output_mcpb_path: Path,
    readme_text: str | None = None,
) -> dict[str, Any]:
    """Create and validate an offline Desktop Extension (.mcpb ZIP) without installing it."""
    if contains_secret_material(manifest_json_text):
        raise ValueError("Refusing to package .mcpb containing secret material.")
    manifest = json.loads(manifest_json_text)
    if not isinstance(manifest, dict) or not manifest.get("name") or not manifest.get("server"):
        raise ValueError("Desktop Extension manifest must define 'name' and 'server'.")

    output_mcpb_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_mcpb_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_json_text.rstrip() + "\n")
        if readme_text:
            zf.writestr("README.txt", readme_text.rstrip() + "\n")

    with zipfile.ZipFile(output_mcpb_path, "r") as zf:
        names = sorted(zf.namelist())
        parsed_manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    return {
        "package_path": str(output_mcpb_path),
        "installed": False,
        "registered": False,
        "zip_entries": names,
        "manifest_name": parsed_manifest.get("name"),
        "manifest_version": parsed_manifest.get("version"),
        "dxt_version": parsed_manifest.get("dxt_version"),
        "byte_size": output_mcpb_path.stat().st_size,
    }
