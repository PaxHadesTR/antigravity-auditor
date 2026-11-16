"""Antigravity Auditor — deterministic model probes (Phase 2 of dynamic model routing).

A probe gives one model the complete source of a tiny fixture repository (``probe_fixtures``) with
line numbers, asks for real defects as schema-constrained JSON, and scores the answer against a
ground-truth file the model never sees:

* recall — planted defects found (file + line/symbol match),
* precision — reported findings that are real defects,
* fabrication — findings whose file, line range or quoted evidence does not exist in the source
  (the failure mode the auditor exists to stop),
* schema validity, latency, tokens and runtime model attestation.

Probes are a *qualification gate*, not a fine-grained ranking: current Gemini 4 models all solve the
suite, so routing proposals use PASSED as eligibility and rank eligible models by research evidence and
efficiency (latency, tokens). ``suite_sha256`` pins results to the exact fixture + ground truth.

Probes run through ``AntigravityCliAdapter.dispatch(probe=True)``: plan mode only, host hard policy
enforced (a model may be probed before it is in the routing table, never if policy denies it).
Scarce models (Gemini 4 Argon) are probed only with an explicit opt-in. Results are evidence for
routing proposals; probes never change the active routing table.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
from typing import Any

from db import connect
from model_attestation import AttestationStatus, attest_conversation_model
from model_catalog import _read_one, known_model_lines, latest_snapshot
from model_registry import (
    BACKEND_AGY,
    ModelRefError,
    current_host_app,
    hard_policy_violation,
    is_scarce_model,
    model_slug,
)

SUITE_VERSION = "probe_repo_v1"
FIXTURE_ROOT = Path(__file__).resolve().parent / "probe_fixtures"
DEFAULT_PROBE_TIMEOUT_SECONDS = 300
DEFAULT_MAX_PROBES = 4
LINE_TOLERANCE = 2
MAX_FINDING_SPAN = 8          # lines; wider citations are not localised evidence
MIN_EXCERPT_CHARS = 12
PASS_PRECISION = 0.75
MAX_ATTEMPTS = 2              # one retry for dispatch errors / unparsable answers only
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "line_start": {"type": "integer"},
                    "line_end": {"type": "integer"},
                    "symbol": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    "evidence_excerpt": {"type": "string"},
                },
                "required": ["file_path", "line_start", "line_end", "symbol", "title", "evidence_excerpt"],
            },
        }
    },
    "required": ["findings"],
}

_PROMPT_HEADER = """You are reviewing a small Python repository for real defects: bugs, security issues and resource leaks.
The complete repository is shown below. Each source line is prefixed with "<line number>| ".

Rules:
- Report only real defects you can point to in the code. Style, naming and missing tests are not defects.
- Do not report correct code. If you are not sure, leave it out.
- For each defect give: file_path (exactly as shown in the FILE header), line_start and line_end
  (1-based, inclusive), symbol (the enclosing function name), title, severity
  (CRITICAL, HIGH, MEDIUM or LOW) and evidence_excerpt (one line copied exactly from the code,
  without the line-number prefix).
- Answer with JSON only, in the form {"findings": [...]}.
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- fixture & prompt -------------------------------------------------------------------------------

def load_suite(suite: str = SUITE_VERSION) -> tuple[dict[str, list[str]], dict[str, Any]]:
    repo = FIXTURE_ROOT / suite
    truth = json.loads((FIXTURE_ROOT / f"{suite}.truth.json").read_text(encoding="utf-8"))
    files = {
        name: (repo / name).read_text(encoding="utf-8").splitlines()
        for name in sorted(truth["files"])
    }
    return files, truth


def suite_sha256(suite: str = SUITE_VERSION) -> str:
    h = hashlib.sha256()
    for path in sorted((FIXTURE_ROOT / suite).rglob("*.py")) + [FIXTURE_ROOT / f"{suite}.truth.json"]:
        h.update(path.relative_to(FIXTURE_ROOT).as_posix().encode())
        h.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def build_probe_prompt(files: dict[str, list[str]]) -> str:
    parts = [_PROMPT_HEADER]
    for name, lines in files.items():
        parts.append(f"\n=== FILE: {name} ===")
        parts.extend(f"{i}| {line}" for i, line in enumerate(lines, 1))
    return "\n".join(parts) + "\n"


# --- scoring ----------------------------------------------------------------------------------------

def extract_json_object(text: str) -> dict[str, Any] | None:
    """First complete JSON object in ``text``.

    Tolerates code fences, leading prose and anything after the object (agy responses sometimes repeat
    the object or append a sentence), which previously made the whole answer unparsable.
    """
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
    decoder = json.JSONDecoder()
    idx = raw.find("{")
    while idx != -1:
        try:
            value, _end = decoder.raw_decode(raw, idx)
        except (json.JSONDecodeError, ValueError):
            idx = raw.find("{", idx + 1)
            continue
        if isinstance(value, dict):
            return value
        idx = raw.find("{", idx + 1)
    return None


def _norm(text: str) -> str:
    return " ".join(str(text).split())


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _valid_finding(f: Any) -> bool:
    return (
        isinstance(f, dict)
        and isinstance(f.get("file_path"), str)
        and _is_int(f.get("line_start"))
        and _is_int(f.get("line_end"))
        and isinstance(f.get("symbol"), str)
        and isinstance(f.get("title"), str) and bool(f["title"].strip())
        and isinstance(f.get("evidence_excerpt"), str)
        and (f.get("severity") is None or f.get("severity") in _SEVERITIES)
    )


def _finding_path(finding: dict[str, Any], files: dict[str, list[str]]) -> str | None:
    """Exact fixture file name, allowing only a single leading "./"; traversal/absolute paths fail."""
    raw = finding["file_path"]
    if "\\" in raw or ".." in raw or raw.startswith("/") or ":" in raw:
        return None
    path = raw.removeprefix("./")
    return path if path in files else None


def is_fabricated(finding: dict[str, Any], files: dict[str, list[str]]) -> bool:
    """True if the cited file, line range or quoted evidence does not exist in the source.

    Evidence must be localised: a range of at most ``MAX_FINDING_SPAN`` lines and a quote that is
    one real source line (or a substantial part of one) inside the cited range. Whole-file ranges,
    tiny fragments and padded quotes all count as fabricated.
    """
    path = _finding_path(finding, files)
    if path is None:
        return True
    lines = files[path]
    start, end = finding["line_start"], finding["line_end"]
    if start < 1 or end < start or end > len(lines) or end - start + 1 > MAX_FINDING_SPAN:
        return True
    excerpt = _norm(finding["evidence_excerpt"])
    if not excerpt:
        return True
    window = lines[max(0, start - 1 - LINE_TOLERANCE): min(len(lines), end + LINE_TOLERANCE)]
    for line in window:
        source = _norm(line)
        if not source or excerpt not in source:
            continue
        # A whole line (even a short one such as "return True") or a substantial part of one.
        if excerpt == source or (len(excerpt) >= MIN_EXCERPT_CHARS and len(excerpt) * 2 >= len(source)):
            return False
    return True


def _matches(finding: dict[str, Any], defect: dict[str, Any], files: dict[str, list[str]]) -> bool:
    """Both the location (defect line inside the cited, bounded range) and the symbol must agree."""
    if _finding_path(finding, files) != defect["file_path"]:
        return False
    in_range = finding["line_start"] - LINE_TOLERANCE <= defect["line"] <= finding["line_end"] + LINE_TOLERANCE
    symbol = finding["symbol"].strip()
    return in_range and (symbol == defect["symbol"] or symbol.endswith("." + defect["symbol"]))


def score_findings(payload: dict[str, Any] | None, files: dict[str, list[str]], truth: dict[str, Any]) -> dict[str, Any]:
    defects = truth["defects"]
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        return {"schema_valid": False, "findings_count": 0, "matched_defects": [], "recall": 0.0,
                "precision": 0.0, "fabricated_count": 0, "false_positive_count": 0, "score": 0.0}
    raw = payload["findings"]
    findings = [f for f in raw if _valid_finding(f)]
    schema_valid = len(findings) == len(raw)
    matched: set[str] = set()
    fabricated = false_pos = duplicates = 0
    for f in findings:
        if is_fabricated(f, files):
            fabricated += 1
            continue
        hits = [d for d in defects if _matches(f, d, files)]
        new_hits = [d for d in hits if d["id"] not in matched]
        if new_hits:
            matched.add(new_hits[0]["id"])  # one finding credits at most one defect
        elif hits:
            duplicates += 1  # repeated report of an already credited defect
        else:
            false_pos += 1
    true_findings = len(matched)
    n = len(findings)
    recall = len(matched) / len(defects) if defects else 0.0
    precision = true_findings / n if n else 0.0
    fabrication_rate = fabricated / n if n else 0.0
    score = 0.0 if not schema_valid else round(0.5 * recall + 0.2 * precision + 0.3 * (1.0 - fabrication_rate), 4)
    return {
        "schema_valid": schema_valid,
        "findings_count": n,
        "matched_defects": sorted(matched),
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "fabricated_count": fabricated,
        "fabrication_rate": round(fabrication_rate, 4),
        "false_positive_count": false_pos,
        "duplicate_count": duplicates,
        "score": score,
    }


def classify(metrics: dict[str, Any], attestation_status: str | None) -> str:
    if attestation_status != AttestationStatus.RUNTIME_ATTESTED:
        return "ATTESTATION_FAILED"
    if not metrics["schema_valid"] or metrics["recall"] < 0.4 or metrics.get("fabrication_rate", 0) > 0.2:
        return "FAILED"
    if not metrics["schema_valid"] or metrics["precision"] < 0.5:
        return "FAILED"
    if metrics["fabricated_count"] > 0 or metrics["recall"] < 0.8 or metrics["precision"] < PASS_PRECISION:
        return "DEGRADED"
    return "PASSED"


# --- persistence & selection ------------------------------------------------------------------------

def latest_probe(db_path: Path | None, slug: str, suite: str = SUITE_VERSION) -> dict[str, Any] | None:
    return _read_one(
        db_path,
        "SELECT * FROM model_probe_runs WHERE backend=? AND model_slug=? AND suite_version=? ORDER BY rowid DESC LIMIT 1",
        (BACKEND_AGY, slug, suite),
    )


def probe_summary(db_path: Path | None, slug: str, suite: str = SUITE_VERSION) -> dict[str, Any] | None:
    row = latest_probe(db_path, slug, suite)
    if not row:
        return None
    metrics = json.loads(row["metrics_json"] or "{}")
    return {
        "status": row["status"],
        "score": row["score"],
        "recall": metrics.get("recall"),
        "precision": metrics.get("precision"),
        "fabricated_count": metrics.get("fabricated_count"),
        "latency_seconds": metrics.get("latency_seconds"),
        "total_tokens": metrics.get("total_tokens"),
        "attestation_status": row["attestation_status"],
        "suite_version": row["suite_version"],
        "suite_sha256": metrics.get("suite_sha256"),
        "probed_at": row["finished_at"],
    }


def probe_candidates(
    db_path: Path,
    *,
    host_app: str | None = None,
    models: list[str] | None = None,
    include_scarce: bool = False,
    only_unprobed: bool = True,
) -> dict[str, Any]:
    """Catalogue models eligible for probing, with a reason for every skipped model."""
    host = host_app or current_host_app()
    snap = latest_snapshot(db_path, BACKEND_AGY)
    if not snap:
        return {"candidates": [], "skipped": [], "detail": "No catalogue snapshot; run `cli.py models sync` first."}
    offered = [m["slug"] for m in json.loads(snap["models_json"])]
    wanted = None
    candidates, skipped = [], []
    if models:
        wanted = set()
        for m in models:
            # Policy is checked on the raw reference so a backend prefix (e.g. "vibe:") is never
            # silently stripped into an agy model.
            violation = hard_policy_violation(m, host)
            if violation:
                skipped.append({"model": m, "reason": "POLICY_DENIED"})
                continue
            try:
                wanted.add(model_slug(m))
            except ModelRefError:
                skipped.append({"model": m, "reason": "MALFORMED"})
    for slug in offered:
        if wanted is not None and slug not in wanted:
            continue
        violation = hard_policy_violation(slug, host)
        if violation:
            skipped.append({"model": slug, "reason": "POLICY_DENIED"})
        elif is_scarce_model(slug, host) and not include_scarce:
            skipped.append({"model": slug, "reason": "SCARCE_REQUIRES_OPT_IN"})
        elif only_unprobed and latest_probe(db_path, slug) is not None:
            skipped.append({"model": slug, "reason": "ALREADY_PROBED"})
        else:
            candidates.append(slug)
    for slug in sorted((wanted or set()) - set(offered)):
        skipped.append({"model": slug, "reason": "NOT_IN_CATALOGUE"})
    return {"candidates": candidates, "skipped": skipped, "catalog_snapshot_id": snap["snapshot_id"]}


def _store(db_path: Path, row: dict[str, Any]) -> None:
    with closing(connect(db_path)) as conn:
        conn.execute(
            """INSERT INTO model_probe_runs(probe_run_id, backend, model_slug, suite_version, catalog_snapshot_id,
                   status, score, metrics_json, conversation_id, attestation_status, error, started_at, finished_at)
               VALUES(:probe_run_id, :backend, :model_slug, :suite_version, :catalog_snapshot_id, :status, :score,
                   :metrics_json, :conversation_id, :attestation_status, :error, :started_at, :finished_at)""",
            row,
        )
        conn.commit()


# --- execution --------------------------------------------------------------------------------------

def run_probe(
    db_path: Path,
    model: str,
    *,
    adapter: Any | None = None,
    conversations_dir: Path | str | None = None,
    timeout_seconds: int = DEFAULT_PROBE_TIMEOUT_SECONDS,
    catalog_snapshot_id: str | None = None,
    suite: str = SUITE_VERSION,
) -> dict[str, Any]:
    """Probe one model, persist and return the result. Never raises for model/CLI failures."""
    from agy_adapter import AntigravityCliAdapter

    violation = hard_policy_violation(model)
    if violation:
        raise ValueError(f"Model '{model}' may not be probed: {violation}")
    slug = model_slug(model)
    adapter = adapter or AntigravityCliAdapter()
    files, truth = load_suite(suite)
    started = _utc_now()
    prompt = build_probe_prompt(files)
    attempts: list[dict[str, Any]] = []
    for attempt in range(1, MAX_ATTEMPTS + 1):
        t0 = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="auditor-probe-") as tmp:
            schema_path = Path(tmp) / "findings.schema.json"
            schema_path.write_text(json.dumps(FINDINGS_SCHEMA), encoding="utf-8")
            res = adapter.dispatch(
                prompt=prompt,
                model_id=slug,
                cwd=tmp,
                mode="plan",
                timeout_seconds=timeout_seconds,
                probe=True,
                json_schema_path=schema_path,
            )
        latency = round(time.monotonic() - t0, 3)
        conversation_id = res.conversation_id
        attestation_status = error = None
        if not res.ok:
            error = f"{res.status}: {res.error_message or ''}".strip()[:500]
            metrics: dict[str, Any] = {"schema_valid": False, "score": 0.0}
            status = "ERROR"
        else:
            from structured_delivery import structured_output_from_events

            answer = structured_output_from_events(res.events) or extract_json_object(res.response_text)
            metrics = score_findings(answer, files, truth)
            if not metrics.get("schema_valid"):
                metrics["response_excerpt"] = (res.response_text or "")[:20000]  # diagnostics only
            metrics["response_length"] = len(res.response_text or "")
            if conversation_id:
                att = attest_conversation_model(
                    conversation_id, slug, conversations_dir=conversations_dir,
                    known_model_lines=known_model_lines(db_path),
                )
                attestation_status = att.status
            else:
                attestation_status = AttestationStatus.MODEL_ATTESTATION_INCOMPLETE
            status = classify(metrics, attestation_status)
        attempts.append({"attempt": attempt, "status": status, "schema_valid": metrics.get("schema_valid"),
                         "error": error, "latency_seconds": latency, "total_tokens": res.total_tokens})
        # Retry only transport/format flakes (dispatch error or unparsable answer); quality results
        # such as fabrication or low precision are the model's real behaviour and are never retried.
        if status != "ERROR" and metrics.get("schema_valid"):
            break
    metrics["attempts"] = attempts
    metrics.update({"suite_sha256": suite_sha256(suite), "latency_seconds": latency, "total_tokens": res.total_tokens,
                    "input_tokens": res.input_tokens, "output_tokens": res.output_tokens})
    row = {
        "probe_run_id": f"PROBE-{slug}-{uuid.uuid4().hex[:12]}",
        "backend": BACKEND_AGY,
        "model_slug": slug,
        "suite_version": suite,
        "catalog_snapshot_id": catalog_snapshot_id,
        "status": status,
        "score": metrics.get("score"),
        "metrics_json": json.dumps(metrics, ensure_ascii=False),
        "conversation_id": conversation_id,
        "attestation_status": attestation_status,
        "error": error,
        "started_at": started,
        "finished_at": _utc_now(),
    }
    _store(db_path, row)
    return {**{k: row[k] for k in ("probe_run_id", "model_slug", "status", "score", "attestation_status", "error")},
            "metrics": metrics}


def probe_models(
    db_path: Path,
    *,
    models: list[str] | None = None,
    include_scarce: bool = False,
    only_unprobed: bool = True,
    max_probes: int = DEFAULT_MAX_PROBES,
    adapter: Any | None = None,
    conversations_dir: Path | str | None = None,
    timeout_seconds: int = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    sel = probe_candidates(db_path, models=models, include_scarce=include_scarce, only_unprobed=only_unprobed)
    todo = sel["candidates"][: max(0, max_probes)]
    deferred = [{"model": m, "reason": "MAX_PROBES_REACHED"} for m in sel["candidates"][len(todo):]]
    results = [
        run_probe(db_path, m, adapter=adapter, conversations_dir=conversations_dir,
                  timeout_seconds=timeout_seconds, catalog_snapshot_id=sel.get("catalog_snapshot_id"))
        for m in todo
    ]
    return {"suite_version": SUITE_VERSION, "results": results, "skipped": sel["skipped"] + deferred,
            "detail": sel.get("detail")}
