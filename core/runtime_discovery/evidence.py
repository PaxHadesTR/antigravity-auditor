"""Provenance tracking and evidence manifest builder for NEXT-22A Runtime Discovery."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from runtime_discovery.contracts import EvidenceClass
from runtime_discovery.redaction import canonical_json_dumps, redact_text


def utc_now_iso() -> str:
    """Return deterministic ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class EvidenceRecord:
    """Single immutable provenance record for a command, file, or probe."""

    evidence_id: str
    application_id: str
    stage: str
    evidence_class: EvidenceClass
    source_type: str
    source_ref: str
    observed_at: str
    exit_code: int | None = None
    command_basename: str | None = None
    command_args: tuple[str, ...] = ()
    sanitized_projection_sha256: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "application_id": self.application_id,
            "stage": self.stage,
            "evidence_class": self.evidence_class.value,
            "source_type": self.source_type,
            "source_ref": redact_text(self.source_ref),
            "observed_at": self.observed_at,
            "exit_code": self.exit_code,
            "command_basename": self.command_basename,
            "command_args": list(self.command_args),
            "sanitized_projection_sha256": self.sanitized_projection_sha256,
            "notes": redact_text(self.notes) if self.notes else None,
        }


@dataclass
class EvidenceLedger:
    """Collects deterministic, secret-free provenance records for a discovery run."""

    run_id: str
    records: list[EvidenceRecord] = field(default_factory=list)
    _counter: int = 0

    def add(
        self,
        *,
        application_id: str,
        stage: str,
        evidence_class: EvidenceClass,
        source_type: str,
        source_ref: str,
        observed_at: str | None = None,
        exit_code: int | None = None,
        command_basename: str | None = None,
        command_args: tuple[str, ...] = (),
        sanitized_projection: Any = None,
        notes: str | None = None,
    ) -> str:
        self._counter += 1
        ev_id = f"ev-{self.run_id}-{self._counter:04d}"
        proj_hash: str | None = None
        if sanitized_projection is not None:
            serialized = canonical_json_dumps(sanitized_projection)
            proj_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        record = EvidenceRecord(
            evidence_id=ev_id,
            application_id=application_id,
            stage=stage,
            evidence_class=evidence_class,
            source_type=source_type,
            source_ref=source_ref,
            observed_at=observed_at or utc_now_iso(),
            exit_code=exit_code,
            command_basename=command_basename,
            command_args=tuple(command_args),
            sanitized_projection_sha256=proj_hash,
            notes=notes,
        )
        self.records.append(record)
        return ev_id

    def to_manifest(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "record_count": len(self.records),
            "records": [r.to_dict() for r in self.records],
        }
