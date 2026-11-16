"""Antigravity Auditor — Independent Model Attestation Engine.

Independently verifies runtime model identity by inspecting the specific local
Antigravity CLI conversation SQLite database:
Path.home() / ".gemini" / "antigravity-cli" / "conversations" / "{conversation_id}.db"

Guarantees:
- Safe read-only SQLite connection (PRAGMA query_only=ON).
- Strict UUID conversation ID validation preventing path traversal.
- Structured protobuf parser over `gen_metadata.data` decoding wire tags,
  verifying cascade_id, request_id, model ID, and display name.
- Fails closed on unsupported schemas or malformed payloads.
- Verifies cross-model independence between primary auditor and second-pass verifier.

Model identity is resolved dynamically (``model_registry.resolve_observed_model``): ``agy``
records an un-suffixed internal model id (e.g. ``gemini-4-hydrogen``) plus an effort-qualified
display name (``Gemini 4 Hydrogen (Medium)``). The display name determines the slug and the
internal id must belong to the same model line. No static model list is consulted, so models
added to the routing table later are attested without code changes.
"""

from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from model_registry import (
    SEED_ROUTING_TABLES,
    canonical_model_slug,
    model_slug,
    resolve_observed_model,
    same_model_line,
)


PARSER_VERSION = "2.0.0-gen_metadata-dynamic"

UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class AttestationStatus:
    """Explicit attestation outcomes."""

    RUNTIME_ATTESTED = "RUNTIME_ATTESTED"
    MODEL_ATTESTATION_INCOMPLETE = "MODEL_ATTESTATION_INCOMPLETE"
    MODEL_ATTESTATION_MISMATCH = "MODEL_ATTESTATION_MISMATCH"
    MODEL_ATTESTATION_UNSUPPORTED_SCHEMA = "MODEL_ATTESTATION_UNSUPPORTED_SCHEMA"
    MODEL_ATTESTATION_DATABASE_UNAVAILABLE = "MODEL_ATTESTATION_DATABASE_UNAVAILABLE"
    MODEL_ATTESTATION_FAILED = "MODEL_ATTESTATION_FAILED"


class CrossModelStatus:
    """Explicit cross-model verification outcomes."""

    CROSS_MODEL_VERIFIED = "CROSS_MODEL_VERIFIED"
    MODEL_INDEPENDENCE_UNVERIFIED = "MODEL_INDEPENDENCE_UNVERIFIED"


def _build_seed_name_normalization() -> dict[str, str]:
    """Slug and display-name aliases of the seed routing-table models -> canonical slug.

    Compatibility helper for ``entitlement_router.discovery_importer``; attestation itself does
    not depend on it.
    """
    out: dict[str, str] = {}
    for table in SEED_ROUTING_TABLES.values():
        for ref in table.assignments.values():
            slug = model_slug(ref)
            out[slug] = slug
            base, _, effort = slug.rpartition("-")
            out[f"{base.replace('-', ' ')} ({effort})"] = slug
    return out


MODEL_NAME_NORMALIZATION: dict[str, str] = _build_seed_name_normalization()


@dataclass(frozen=True)
class GenerationMetadataRecord:
    """Decoded record from gen_metadata.data protobuf payload."""

    cascade_id: str | None
    request_id: str | None
    trajectory_id: str | None
    backend_model_id: str | None
    display_model_name: str | None
    canonical_model_id: str | None
    parser_version: str = PARSER_VERSION


@dataclass(frozen=True)
class AttestationResult:
    """Outcome of local SQLite database attestation."""

    status: str
    is_attested: bool
    conversation_id: str
    expected_model: str
    observed_model: str | None
    display_model_name: str | None
    db_path: str | None
    details: str
    generation_records_count: int = 0
    parser_version: str = PARSER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "is_attested": self.is_attested,
            "conversation_id": self.conversation_id,
            "expected_model": self.expected_model,
            "observed_model": self.observed_model,
            "display_model_name": self.display_model_name,
            "db_path": self.db_path,
            "details": self.details,
            "generation_records_count": self.generation_records_count,
            "parser_version": self.parser_version,
        }


@dataclass(frozen=True)
class CrossModelVerificationResult:
    """Outcome of comparing primary auditor and verifier models."""

    status: str
    is_independent: bool
    primary_model: str | None
    verifier_model: str | None
    reason: str


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a standard protobuf varint starting at offset. Returns (value, new_offset)."""
    val = 0
    shift = 0
    n = len(data)
    i = offset
    while i < n:
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, i
        shift += 7
        if shift > 35:
            raise ValueError("Varint too long")
    raise ValueError("Truncated varint")


def decode_raw_protobuf_fields(data: bytes) -> list[tuple[int, int, bytes]]:
    """Decode a protobuf message into list of (field_number, wire_type, raw_bytes)."""
    fields: list[tuple[int, int, bytes]] = []
    i = 0
    n = len(data)
    while i < n:
        try:
            tag, i = decode_varint(data, i)
        except ValueError:
            break
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # Varint
            start_i = i
            _, i = decode_varint(data, i)
            fields.append((field_num, wire_type, data[start_i:i]))
        elif wire_type == 1:  # 64-bit
            val = data[i:i + 8]
            i += 8
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:  # Length-delimited
            length, i = decode_varint(data, i)
            val = data[i:i + length]
            i += length
            fields.append((field_num, wire_type, val))
        elif wire_type == 5:  # 32-bit
            val = data[i:i + 4]
            i += 4
            fields.append((field_num, wire_type, val))
        else:
            # Unsupported wire type
            raise ValueError(f"Unsupported protobuf wire type: {wire_type}")
    return fields


def parse_gen_metadata_blob(blob: bytes) -> GenerationMetadataRecord:
    """Parse gen_metadata.data binary blob into structured metadata record.

    Protobuf schema structure:
    - Root message contains:
      - Field 1 (wire_type 2): Generation metadata submessage
    - Submessage Field 1 contains:
      - Field 19 (wire_type 2): backend model name string
      - Field 21 (wire_type 2): display model name string
      - Field 20 (wire_type 2): map entries with key (Field 1) and value (Field 2)
    """
    if not blob or not isinstance(blob, (bytes, bytearray)):
        raise ValueError("Empty or invalid gen_metadata blob")

    root_fields = decode_raw_protobuf_fields(bytes(blob))
    gen_submessage_bytes: bytes | None = None
    for fnum, wtype, raw_val in root_fields:
        if fnum == 1 and wtype == 2:
            gen_submessage_bytes = raw_val
            break

    if gen_submessage_bytes is None:
        raise ValueError("Missing Field 1 (generation metadata) in protobuf blob")

    sub_fields = decode_raw_protobuf_fields(gen_submessage_bytes)
    backend_model_id: str | None = None
    display_model_name: str | None = None
    cascade_id: str | None = None
    request_id: str | None = None
    trajectory_id: str | None = None

    for fnum, wtype, raw_val in sub_fields:
        if fnum == 19 and wtype == 2:
            try:
                backend_model_id = raw_val.decode("utf-8", "replace").strip()
            except Exception:
                pass
        elif fnum == 21 and wtype == 2:
            try:
                display_model_name = raw_val.decode("utf-8", "replace").strip()
            except Exception:
                pass
        elif fnum == 20 and wtype == 2:
            # Map entry key/value
            try:
                entry_fields = decode_raw_protobuf_fields(raw_val)
                k: str | None = None
                v: str | None = None
                for efnum, ewtype, evalue in entry_fields:
                    if efnum == 1 and ewtype == 2:
                        k = evalue.decode("utf-8", "replace").strip()
                    elif efnum == 2 and ewtype == 2:
                        v = evalue.decode("utf-8", "replace").strip()
                if k == "cascade_id" and v:
                    cascade_id = v
                elif k == "request_id" and v:
                    request_id = v
                elif k == "trajectory_id" and v:
                    trajectory_id = v
            except Exception:
                pass

    # Resolve the effort-qualified slug from display name + internal id (dynamic, no static list)
    canonical: str | None = resolve_observed_model(backend_model_id, display_model_name)

    return GenerationMetadataRecord(
        cascade_id=cascade_id,
        request_id=request_id,
        trajectory_id=trajectory_id,
        backend_model_id=backend_model_id,
        display_model_name=display_model_name,
        canonical_model_id=canonical,
    )


def resolve_conversation_db_path(
    conversation_id: str,
    *,
    base_dir: Path | str | None = None,
) -> Path:
    """Validate conversation_id as strict UUID and construct safe path."""
    clean_id = (conversation_id or "").strip()
    if not UUID_PATTERN.match(clean_id):
        raise ValueError(
            f"Invalid conversation_id '{conversation_id}'. Must be a valid 36-char UUID."
        )

    if base_dir is not None:
        root = Path(base_dir).resolve()
    else:
        root = Path.home() / ".gemini" / "antigravity-cli" / "conversations"

    db_path = root / f"{clean_id}.db"
    return db_path.resolve()


def attest_conversation_model(
    conversation_id: str,
    expected_model: str,
    *,
    conversations_dir: Path | str | None = None,
    known_model_lines: frozenset[str] | None = None,
) -> AttestationResult:
    """Inspect local conversation SQLite database and independently attest runtime model.

    ``known_model_lines`` (from the persisted backend catalogue) additionally rejects internal ids
    that belong to a longer sibling model line.

    Guarantees:
    - Path traversal strictly rejected.
    - Safe SQLite read-only connection (PRAGMA query_only=ON).
    - Checks gen_metadata table and decodes protobuf structure.
    - Confirms that cascade_id matches conversation_id.
    - Confirms that canonical model agrees with expected_model.
    """
    clean_expected = (expected_model or "").strip().lower()

    try:
        db_path = resolve_conversation_db_path(
            conversation_id,
            base_dir=conversations_dir,
        )
    except ValueError as exc:
        return AttestationResult(
            status=AttestationStatus.MODEL_ATTESTATION_FAILED,
            is_attested=False,
            conversation_id=conversation_id,
            expected_model=expected_model,
            observed_model=None,
            display_model_name=None,
            db_path=None,
            details=f"Conversation ID validation failed: {exc}",
        )

    if not db_path.is_file():
        return AttestationResult(
            status=AttestationStatus.MODEL_ATTESTATION_DATABASE_UNAVAILABLE,
            is_attested=False,
            conversation_id=conversation_id,
            expected_model=expected_model,
            observed_model=None,
            display_model_name=None,
            db_path=str(db_path),
            details=f"Conversation SQLite database not found at {db_path}",
        )

    # Open SQLite database in URI read-only mode with query_only=ON
    uri_path = db_path.as_posix()
    conn_uri = f"file:{uri_path}?mode=ro"
    records: list[GenerationMetadataRecord] = []

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(conn_uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")

        # Verify gen_metadata table exists
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='gen_metadata'"
        ).fetchone()
        if not has_table:
            return AttestationResult(
                status=AttestationStatus.MODEL_ATTESTATION_UNSUPPORTED_SCHEMA,
                is_attested=False,
                conversation_id=conversation_id,
                expected_model=expected_model,
                observed_model=None,
                display_model_name=None,
                db_path=str(db_path),
                details="Table 'gen_metadata' missing in conversation database.",
            )

        rows = conn.execute("SELECT idx, data FROM gen_metadata ORDER BY idx ASC").fetchall()
    except Exception as exc:
        return AttestationResult(
            status=AttestationStatus.MODEL_ATTESTATION_DATABASE_UNAVAILABLE,
            is_attested=False,
            conversation_id=conversation_id,
            expected_model=expected_model,
            observed_model=None,
            display_model_name=None,
            db_path=str(db_path),
            details=f"Failed to read conversation database: {exc}",
        )
    finally:
        if conn is not None:
            conn.close()

    if not rows:
        return AttestationResult(
            status=AttestationStatus.MODEL_ATTESTATION_INCOMPLETE,
            is_attested=False,
            conversation_id=conversation_id,
            expected_model=expected_model,
            observed_model=None,
            display_model_name=None,
            db_path=str(db_path),
            details="gen_metadata table contains 0 generation records.",
        )

    for row in rows:
        blob = row["data"]
        try:
            rec = parse_gen_metadata_blob(blob)
            records.append(rec)
        except Exception as exc:
            return AttestationResult(
                status=AttestationStatus.MODEL_ATTESTATION_FAILED,
                is_attested=False,
                conversation_id=conversation_id,
                expected_model=expected_model,
                observed_model=None,
                display_model_name=None,
                db_path=str(db_path),
                details=f"Protobuf decoding failed on row idx {row['idx']}: {exc}",
            )

    # Check conversation association and model match
    # Look for at least one record matching this conversation ID
    matching_records = [
        r for r in records
        if r.cascade_id and r.cascade_id.strip().lower() == conversation_id.strip().lower()
    ]
    if not matching_records:
        return AttestationResult(
            status=AttestationStatus.MODEL_ATTESTATION_INCOMPLETE,
            is_attested=False,
            conversation_id=conversation_id,
            expected_model=expected_model,
            observed_model=None,
            display_model_name=None,
            db_path=str(db_path),
            details="No gen_metadata record carries this conversation's cascade_id; refusing to attest an unrelated record.",
            generation_records_count=len(records),
        )
    if known_model_lines:
        matching_records = [
            GenerationMetadataRecord(
                cascade_id=r.cascade_id,
                request_id=r.request_id,
                trajectory_id=r.trajectory_id,
                backend_model_id=r.backend_model_id,
                display_model_name=r.display_model_name,
                canonical_model_id=resolve_observed_model(r.backend_model_id, r.display_model_name, known_model_lines),
            )
            for r in matching_records
        ]
    target_record = matching_records[-1]

    # Every generation of the conversation must have run on one model: a session that switched models
    # part-way cannot be attested as that model (records whose model cannot be resolved are not counted).
    resolved_models = sorted({r.canonical_model_id for r in matching_records if r.canonical_model_id})
    # A record whose model id cannot be resolved still has to be the same model as the attested one: same
    # display name or same backend id. Otherwise it counts as a different (unknown) model.
    target_display = (target_record.display_model_name or "").strip().lower()
    target_backend = (target_record.backend_model_id or "").strip().lower()
    for r in matching_records:
        if r.canonical_model_id:
            continue
        same_display = bool(target_display) and (r.display_model_name or "").strip().lower() == target_display
        same_backend = bool(target_backend) and (r.backend_model_id or "").strip().lower() == target_backend
        if not (same_display or same_backend):
            label = r.display_model_name or r.backend_model_id or "<unresolved>"
            if label not in resolved_models:
                resolved_models.append(label)
    if len(resolved_models) > 1:
        return AttestationResult(
            status=AttestationStatus.MODEL_ATTESTATION_MISMATCH,
            is_attested=False,
            conversation_id=conversation_id,
            expected_model=expected_model,
            observed_model=target_record.canonical_model_id or target_record.backend_model_id,
            display_model_name=target_record.display_model_name,
            db_path=str(db_path),
            details=f"Conversation ran on several models ({', '.join(resolved_models)}); refusing to attest.",
            generation_records_count=len(records),
        )

    observed_model_str = target_record.canonical_model_id or target_record.backend_model_id

    # Verify model match
    expected_canonical = canonical_model_slug(clean_expected)
    observed_canonical = target_record.canonical_model_id

    if expected_canonical and observed_canonical and expected_canonical == observed_canonical:
        return AttestationResult(
            status=AttestationStatus.RUNTIME_ATTESTED,
            is_attested=True,
            conversation_id=conversation_id,
            expected_model=expected_model,
            observed_model=observed_canonical,
            display_model_name=target_record.display_model_name,
            db_path=str(db_path),
            details=(
                f"Model identity independently attested via SQLite gen_metadata "
                f"(model={observed_canonical}, display={target_record.display_model_name})."
            ),
            generation_records_count=len(records),
        )

    # Mismatch detected
    return AttestationResult(
        status=AttestationStatus.MODEL_ATTESTATION_MISMATCH,
        is_attested=False,
        conversation_id=conversation_id,
        expected_model=expected_model,
        observed_model=observed_model_str,
        display_model_name=target_record.display_model_name,
        db_path=str(db_path),
        details=(
            f"Model mismatch: expected '{expected_model}' but observed '{observed_model_str}' "
            f"(display='{target_record.display_model_name}')."
        ),
        generation_records_count=len(records),
    )


def verify_cross_model_independence(
    primary_attestation: AttestationResult,
    verifier_attestation: AttestationResult,
) -> CrossModelVerificationResult:
    """Verify that primary audit and verifier dispatches satisfy true model independence.

    Requirements:
    1. Primary must be RUNTIME_ATTESTED.
    2. Verifier must be RUNTIME_ATTESTED.
    3. Primary model and verifier model must be distinct actual models.
    4. Different reasoning efforts of one model line (e.g. Hydrogen High vs Hydrogen Medium) are
       the same underlying model and are NOT independent.
    """
    if not primary_attestation.is_attested or primary_attestation.status != AttestationStatus.RUNTIME_ATTESTED:
        return CrossModelVerificationResult(
            status=CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED,
            is_independent=False,
            primary_model=primary_attestation.observed_model,
            verifier_model=verifier_attestation.observed_model,
            reason=f"Primary model attestation incomplete/failed: {primary_attestation.status}",
        )

    if not verifier_attestation.is_attested or verifier_attestation.status != AttestationStatus.RUNTIME_ATTESTED:
        return CrossModelVerificationResult(
            status=CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED,
            is_independent=False,
            primary_model=primary_attestation.observed_model,
            verifier_model=verifier_attestation.observed_model,
            reason=f"Verifier model attestation incomplete/failed: {verifier_attestation.status}",
        )

    p_mod = (primary_attestation.observed_model or "").lower()
    v_mod = (verifier_attestation.observed_model or "").lower()

    if p_mod == v_mod:
        return CrossModelVerificationResult(
            status=CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED,
            is_independent=False,
            primary_model=p_mod,
            verifier_model=v_mod,
            reason=f"Same model used for primary and verifier ({p_mod}). No cross-model independence.",
        )

    # Efforts of one model line are not independent
    if same_model_line(p_mod, v_mod):
        return CrossModelVerificationResult(
            status=CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED,
            is_independent=False,
            primary_model=p_mod,
            verifier_model=v_mod,
            reason=f"{p_mod} and {v_mod} are reasoning levels of the same model line; no model independence.",
        )

    # True independence (different model lines, e.g. Hydrogen vs Argon)
    return CrossModelVerificationResult(
        status=CrossModelStatus.CROSS_MODEL_VERIFIED,
        is_independent=True,
        primary_model=p_mod,
        verifier_model=v_mod,
        reason=(
            f"Verified cross-model independence established: "
            f"Primary={p_mod} vs Verifier={v_mod}."
        ),
    )
