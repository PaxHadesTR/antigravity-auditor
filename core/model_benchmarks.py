"""Antigravity Auditor — tier measurements (benchmarks) of the account's models.

Probes (``model_probes``) only decide whether a model is usable at all. Measurements decide which usable model
fits each routing tier best: every model is given the auditor's real jobs on fixture repositories with a
ground truth it never sees (``probe_fixtures/bench_v1``):

* FIND (primary-audit skill, used for ENTRY and STANDARD): find the critical defects of a repository that also
  contains decoys (code that looks dangerous but is safe as deployed). Score = 0.6 recall + 0.25 decoy
  avoidance + 0.15 evidence integrity (no fabricated citations).
* VERIFY (evidence-gated verification, used for CRITICAL and CATASTROPHIC): decide CONFIRMED/REFUTED for ten
  candidate critical findings (four real) and cite the root-cause line. Score = (correct verdicts + 0.5 per
  correctly located real defect) / 12; a refuted real defect is counted separately as ``missed_real``.

Each measurement records accuracy, tokens and latency, so the routing engine can choose "the cheapest model
among the most accurate ones" per tier. Runs go through ``AntigravityCliAdapter.dispatch(probe=True)`` (plan
mode, hard policy enforced, nothing written). What to measure and when is decided by ``measurement_plan``:
new models first, models of the active table again after ``REMEASURE_DAYS``, never when the account's quota
is low (``model_quota``).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from db import connect
from model_catalog import latest_snapshot
from model_probes import (
    FINDINGS_SCHEMA,
    LINE_TOLERANCE,
    SUITE_VERSION,
    _finding_path,
    _valid_finding,
    extract_json_object,
    is_fabricated,
    latest_probe,
    suite_sha256,
)
from model_registry import (
    BACKEND_AGY,
    RoutingTableError,
    current_host_app,
    get_active_routing_table,
    hard_policy_violation,
    is_scarce_model,
    model_effort,
    model_slug,
)

BENCH_VERSION = "bench_v1"
BENCH_ROOT = Path(__file__).resolve().parent / "probe_fixtures"
KINDS = ("find", "verify")
DEFAULT_REPS = 2
DEFAULT_MAX_MODELS = 3
DEFAULT_TIMEOUT_SECONDS = 1500
REMEASURE_DAYS = 28
MIN_GEMINI_QUOTA = 35.0     # % remaining of the shared Gemini quota below which nothing is measured
MIN_SCARCE_QUOTA = 50.0     # % remaining of a scarce model's own quota (Argon) below which it waits
UNKNOWN_QUOTA_MAX_MODELS = 1
EFFORT_ORDER = ("high", "medium", "xhigh", "low")  # which unmeasured efforts are measured first
MAX_RECENT_FAILURES = 8     # failed runs within REMEASURE_DAYS after which a model waits (no endless spending)

VERIFY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["results"],
    "properties": {"results": {"type": "array", "items": {
        "type": "object",
        "required": ["id", "verdict", "file", "line", "reason"],
        "properties": {
            "id": {"type": "string"},
            "verdict": {"type": "string", "enum": ["CONFIRMED", "REFUTED"]},
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "reason": {"type": "string"},
        }}}},
}

_FIND_HEADER = """You are the primary auditor of a small Python service. Find its CRITICAL security defects: remote code
execution, authentication bypass, privilege escalation, account takeover, SSRF to credentials, arbitrary file
read/write, catastrophic data loss. Read the README first: it describes how the code is deployed, and that
decides what is exploitable. Code that only looks dangerous but is safe as deployed is NOT a defect; reporting
it is an error. Each source line is prefixed with "<line number>| ".
For each real defect give file_path (exactly as in the FILE header), line_start and line_end (the root-cause
lines, at most 8 lines), symbol (enclosing function), title, severity and evidence_excerpt (one line copied
exactly from the code, without the prefix). Answer with JSON only: {"findings": [...]}.
"""

_VERIFY_HEADER = """You are the final, evidence-gated verifier for CATASTROPHIC security findings (RCE, auth bypass,
privilege escalation, catastrophic data loss) in a code audit. Another model proposed the candidate findings
below. For EACH candidate decide CONFIRMED (the described attack really works against this code as deployed,
see README) or REFUTED (it does not). Be strict both ways: confirming a false finding and refuting a real one
are equally serious errors. For CONFIRMED give the file name (e.g. auth.py) and the single line number of the
root-cause line; for REFUTED give the line that shows why it is safe. Reason in at most two sentences. Do not
run anything; the full source is below.
"""


class BenchmarkError(RuntimeError):
    pass


def _attest(conversation_id: str | None, slug: str, db_path: Path) -> str:
    """Runtime model attestation (same rule as probes): the answer must provably come from ``slug``."""
    from model_attestation import AttestationStatus, attest_conversation_model
    from model_catalog import known_model_lines

    if not conversation_id:
        return AttestationStatus.MODEL_ATTESTATION_INCOMPLETE
    return attest_conversation_model(conversation_id, slug, known_model_lines=known_model_lines(db_path)).status


ATTEST = _attest  # test seam


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- suites ---------------------------------------------------------------------------------------------

def load_bench(version: str = BENCH_VERSION) -> dict[str, Any]:
    spec_path = BENCH_ROOT / f"{version}.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    repos: dict[str, Any] = {}
    for name, definition in spec["repos"].items():
        root = BENCH_ROOT / version / name
        files = {p.name: p.read_text(encoding="utf-8").splitlines() for p in sorted(root.glob("*.py"))}
        readme = (root / "README.md").read_text(encoding="utf-8").splitlines()
        repos[name] = {**definition, "files": files, "readme": readme}
    return {"version": version, "repos": repos}


def bench_sha256(version: str = BENCH_VERSION) -> str:
    h = hashlib.sha256()
    # Line endings of the checkout (CRLF/LF) must not change the fingerprint, or measurements would be discarded.
    h.update((BENCH_ROOT / f"{version}.json").read_bytes().replace(b"\r\n", b"\n"))
    for p in sorted((BENCH_ROOT / version).rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            h.update(p.relative_to(BENCH_ROOT).as_posix().encode())
            h.update(p.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def _source_block(repo: dict[str, Any]) -> list[str]:
    parts = ["\n=== FILE: README.md ==="] + repo["readme"]
    for name, lines in repo["files"].items():
        parts.append(f"\n=== FILE: {name} ===")
        parts.extend(f"{i}| {line}" for i, line in enumerate(lines, 1))
    return parts


def build_prompt(repo: dict[str, Any], kind: str) -> str:
    if kind == "find":
        return "\n".join([_FIND_HEADER, *_source_block(repo)]) + "\n"
    claims = [f"{cid}: {c['text']}" for cid, c in repo["claims"].items()]
    tail = ('\nAnswer with JSON only: {"results": [{"id", "verdict", "file", "line", "reason"}, ...]} '
            "with one entry per candidate.")
    return "\n".join([_VERIFY_HEADER, "CANDIDATE FINDINGS:", *claims, *_source_block(repo), tail]) + "\n"


# --- scoring --------------------------------------------------------------------------------------------

def _overlaps(finding: dict[str, Any], lo: int, hi: int) -> bool:
    return finding["line_start"] - LINE_TOLERANCE <= hi and lo <= finding["line_end"] + LINE_TOLERANCE


def _symbol_ok(finding: dict[str, Any], symbol: str) -> bool:
    got = finding["symbol"].strip()
    return got == symbol or got.endswith("." + symbol)


def score_find(payload: Any, repo: dict[str, Any]) -> dict[str, Any]:
    """Credit a defect only for a finding in its file, overlapping its lines AND naming its function; a finding
    overlapping a decoy is a decoy hit; any other non-fabricated finding lowers precision."""
    files = repo["files"]
    defects, decoys = repo["defects"], repo["decoys"]
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        return {"schema_valid": False, "score": 0.0, "recall": 0.0, "decoy_hits": [], "fabricated": 0}
    raw = payload["findings"]
    findings = [f for f in raw if _valid_finding(f)]
    matched: set[str] = set()
    decoy_hits: set[str] = set()
    fabricated = wrong = duplicates = 0
    for f in findings:
        if is_fabricated(f, files):
            fabricated += 1
            continue
        path = _finding_path(f, files)
        hits = [d["id"] for d in defects if any(
            loc["file"] == path and _overlaps(f, *loc["lines"]) and _symbol_ok(f, loc["symbol"])
            for loc in d["locations"])]
        new = [h for h in hits if h not in matched]
        if new:
            matched.add(new[0])
            continue
        if hits:
            duplicates += 1  # repeated report of a credited defect: neutral
            continue
        hit_decoys = {d["id"] for d in decoys if d["file"] == path and _overlaps(f, *d["lines"])}
        decoy_hits |= hit_decoys
        wrong += 1
    n = len(findings)
    recall = len(matched) / len(defects)
    decoy_rate = len(decoy_hits) / len(decoys) if decoys else 0.0
    fabrication_rate = fabricated / n if n else 0.0
    credited = len(matched) + wrong
    precision = len(matched) / credited if credited else 0.0
    schema_valid = len(findings) == len(raw)
    score = round(0.55 * recall + 0.2 * (1 - decoy_rate) + 0.1 * precision + 0.15 * (1 - fabrication_rate), 4) \
        if schema_valid else 0.0
    return {"schema_valid": schema_valid, "score": score, "recall": round(recall, 4), "precision": round(precision, 4),
            "matched": sorted(matched), "missed": sorted({d["id"] for d in defects} - matched),
            "decoy_hits": sorted(decoy_hits), "wrong": wrong, "duplicates": duplicates, "fabricated": fabricated,
            "findings": n}


def score_verify(payload: Any, repo: dict[str, Any]) -> dict[str, Any]:
    claims = repo["claims"]
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return {"schema_valid": False, "score": 0.0, "missed_real": len([c for c in claims.values()
                                                                          if c["verdict"] == "CONFIRMED"]),
                "false_confirm": 0}
    results = payload["results"]
    files = {**repo["files"], "README.md": repo.get("readme") or []}  # README facts may justify a REFUTED
    ids = [r.get("id") for r in results if isinstance(r, dict)]
    schema_ok = (len(ids) == len(results) == len(claims) and set(ids) == set(claims) and all(
        r.get("verdict") in ("CONFIRMED", "REFUTED") and isinstance(r.get("file"), str)
        and isinstance(r.get("line"), int) and not isinstance(r.get("line"), bool) and isinstance(r.get("reason"), str)
        for r in results))
    if not schema_ok:
        return {"schema_valid": False, "score": 0.0, "missed_real": 0, "false_confirm": 0,
                "detail": "results must hold each candidate exactly once with verdict, file, line and reason"}
    got = {r["id"]: r for r in results}
    bad_citation = [r["id"] for r in results
                    if Path(r["file"]).name not in files or not 1 <= r["line"] <= len(files[Path(r["file"]).name])]
    correct = located = 0
    missed, false_confirm, missing, bad_evidence = [], [], [], []
    for cid, claim in claims.items():
        r = got.get(cid)
        if r is None:
            missing.append(cid)
            if claim["verdict"] == "CONFIRMED":
                missed.append(cid)
            continue
        if cid in bad_citation:  # cites a file or line that does not exist: no credit for this candidate
            if claim["verdict"] == "CONFIRMED":
                missed.append(cid)
            continue
        if r.get("verdict") == claim["verdict"]:
            correct += 1
            if claim["verdict"] == "CONFIRMED":
                fname = Path(str(r.get("file") or "")).name
                line = r.get("line")
                if any(fname == f and isinstance(line, int) and not isinstance(line, bool) and lo <= line <= hi
                       for f, lo, hi in claim.get("evidence") or []):
                    located += 1
                else:
                    bad_evidence.append(cid)
        elif claim["verdict"] == "CONFIRMED":
            missed.append(cid)
        else:
            false_confirm.append(cid)
    real = sum(1 for c in claims.values() if c["verdict"] == "CONFIRMED")
    score = round((correct + 0.5 * located) / (len(claims) + 0.5 * real), 4)
    return {"schema_valid": True, "score": score, "correct": correct, "located": located,
            "missed_real": len(missed), "missed": missed, "false_confirm": len(false_confirm),
            "false_confirmed": false_confirm, "bad_evidence": bad_evidence, "bad_citation": bad_citation,
            "missing": missing}


# --- storage --------------------------------------------------------------------------------------------

def _store(db_path: Path, row: dict[str, Any]) -> None:
    cols = list(row)
    with closing(connect(db_path)) as conn:
        conn.execute(f"INSERT INTO model_benchmark_runs({', '.join(cols)}) VALUES({', '.join('?' * len(cols))})",
                     tuple(row[c] for c in cols))
        conn.commit()


def _rows(db_path: Path, sha: str) -> list[dict[str, Any]]:
    path = Path(db_path)
    if not path.is_file():
        return []
    import sqlite3

    try:
        with closing(sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=30)) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM model_benchmark_runs WHERE backend=? AND bench_sha256=? ORDER BY rowid",
                (BACKEND_AGY, sha)).fetchall()]
    except sqlite3.OperationalError:
        return []


# --- running --------------------------------------------------------------------------------------------

def run_suite(db_path: Path, slug: str, repo_name: str, kind: str, *, rep: int = 1, adapter: Any | None = None,
              bench: dict[str, Any] | None = None, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """One measurement call. Never raises for model/CLI failures (stored as ERROR)."""
    from agy_adapter import AntigravityCliAdapter
    from structured_delivery import structured_output_from_events

    violation = hard_policy_violation(slug)
    if violation:
        raise BenchmarkError(f"Model '{slug}' may not be measured: {violation}")
    bench = bench or load_bench()
    repo = bench["repos"][repo_name]
    adapter = adapter or AntigravityCliAdapter()
    started = _utc_now()
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="auditor-bench-") as tmp:
        schema_path = Path(tmp) / "schema.json"
        schema_path.write_text(json.dumps(FINDINGS_SCHEMA if kind == "find" else VERIFY_SCHEMA), encoding="utf-8")
        res = adapter.dispatch(prompt=build_prompt(repo, kind), model_id=slug, cwd=tmp, mode="plan",
                               timeout_seconds=timeout_seconds, probe=True, json_schema_path=schema_path)
    latency = round(time.monotonic() - t0, 3)
    metrics: dict[str, Any]
    if res.ok:
        from model_attestation import AttestationStatus

        answer = structured_output_from_events(res.events) or extract_json_object(res.response_text)
        metrics = score_find(answer, repo) if kind == "find" else score_verify(answer, repo)
        attestation = ATTEST(res.conversation_id, slug, db_path)
        metrics["attestation_status"] = attestation
        if attestation != AttestationStatus.RUNTIME_ATTESTED:
            status = "ATTESTATION_FAILED"
        else:
            status = "OK" if metrics.get("schema_valid") else "INVALID_OUTPUT"
        error = None
    else:
        metrics, status = {"score": 0.0}, "ERROR"
        error = f"{res.status}: {res.error_message or ''}".strip()[:500]
    row = {
        "run_id": f"BENCH-{slug}-{uuid.uuid4().hex[:12]}", "backend": BACKEND_AGY, "model_slug": slug,
        "bench_version": bench["version"], "bench_sha256": bench_sha256(bench["version"]),
        "suite": f"{kind}:{repo_name}", "rep": rep, "status": status,
        "score": metrics.get("score") if status == "OK" else None,
        "metrics_json": json.dumps(metrics, ensure_ascii=False), "total_tokens": res.total_tokens,
        "latency_seconds": latency, "conversation_id": res.conversation_id, "error": error,
        "started_at": started, "finished_at": _utc_now(),
    }
    _store(db_path, row)
    return {k: row[k] for k in ("run_id", "model_slug", "suite", "rep", "status", "score", "total_tokens",
                                "latency_seconds", "error")}


def measure_model(db_path: Path, slug: str, *, reps: int = DEFAULT_REPS, adapter: Any | None = None,
                  timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, suites: set[str] | None = None) -> list[dict[str, Any]]:
    """Run the benchmark for ``slug`` (only ``suites`` such as {"verify:ledger"} when given)."""
    bench = load_bench()
    out = []
    for rep in range(1, reps + 1):
        for repo_name in bench["repos"]:
            for kind in KINDS:
                if suites is not None and f"{kind}:{repo_name}" not in suites:
                    continue
                out.append(run_suite(db_path, slug, repo_name, kind, rep=rep, adapter=adapter, bench=bench,
                                     timeout_seconds=timeout_seconds))
    return out


def _days_ago(days: int, now: datetime | None = None) -> str:
    return ((now or datetime.now(timezone.utc)) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")


# --- aggregation ----------------------------------------------------------------------------------------

def measurements(db_path: Path | None) -> dict[str, dict[str, Any]]:
    """Per model, over the current bench: accuracy per kind, missed real defects, tokens and latency per call.
    A model is ``complete`` when every suite has at least one OK run."""
    if db_path is None:
        return {}
    bench = load_bench()
    suites = {f"{k}:{r}" for r in bench["repos"] for k in KINDS}
    by_model: dict[str, list[dict[str, Any]]] = {}
    for row in _rows(Path(db_path), bench_sha256()):
        by_model.setdefault(row["model_slug"], []).append(row)
    out: dict[str, dict[str, Any]] = {}
    for slug, rows in by_model.items():
        # Only the newest DEFAULT_REPS successful runs of each suite count, so a re-measurement replaces older
        # results instead of being averaged with them.
        ok = []
        for suite in suites:
            ok += [r for r in rows if r["status"] == "OK" and r["suite"] == suite][-DEFAULT_REPS:]
        done = {r["suite"] for r in ok}

        def mean(values: list[float]) -> float | None:
            return round(sum(values) / len(values), 4) if values else None

        verify = [r for r in ok if r["suite"].startswith("verify:")]
        missed = sum(json.loads(r["metrics_json"] or "{}").get("missed_real", 0) for r in verify)
        false_confirm = sum(json.loads(r["metrics_json"] or "{}").get("false_confirm", 0) for r in verify)
        out[slug] = {
            "complete": suites <= done,
            "find_accuracy": mean([r["score"] for r in ok if r["suite"].startswith("find:")]),
            "verify_accuracy": mean([r["score"] for r in verify]),
            "missed_real_per_run": round(missed / len(verify), 4) if verify else None,
            "false_confirm_per_run": round(false_confirm / len(verify), 4) if verify else None,
            "tokens_per_call": mean([float(r["total_tokens"] or 0) for r in ok]),
            "latency_per_call": mean([float(r["latency_seconds"] or 0) for r in ok]),
            "runs_ok": len(ok), "runs_failed": len(rows) - len(ok),
            "missing_suites": sorted(suites - done),
            "recent_failures": sum(1 for r in rows if r["status"] != "OK" and r["finished_at"] >= _days_ago(REMEASURE_DAYS)),
            "measured_at": min(max(r["finished_at"] for r in ok if r["suite"] == s) for s in done) if done else None,
            "last_attempt_at": max(r["finished_at"] for r in rows),
        }
    return out


# --- planning -------------------------------------------------------------------------------------------

def _eligible(db_path: Path, host: str) -> list[str]:
    """Offered, policy-allowed models with a PASSED probe on the current probe suite."""
    snap = latest_snapshot(db_path, BACKEND_AGY)
    if not snap:
        return []
    sha = suite_sha256()
    out = []
    for m in json.loads(snap["models_json"]):
        slug = m["slug"]
        if hard_policy_violation(slug, host):
            continue
        probe = latest_probe(db_path, slug, SUITE_VERSION)
        if probe and probe["status"] == "PASSED" and json.loads(probe["metrics_json"] or "{}").get("suite_sha256") == sha:
            out.append(slug)
    return out


def measurement_plan(db_path: Path, *, quota: dict[str, float] | None, max_models: int = DEFAULT_MAX_MODELS,
                     host_app: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    """Which models to measure now: models of the active table without a complete measurement, then other
    unmeasured models, then table models whose measurement is older than REMEASURE_DAYS. Quota-aware."""
    from model_quota import GROUP_GEMINI, remaining_for

    host = host_app or current_host_app()
    now = now or datetime.now(timezone.utc)
    try:
        table_models = {model_slug(m) for m in get_active_routing_table(host, db_path).assignments.values()}
    except RoutingTableError:
        table_models = set()
    current = measurements(db_path)
    stale_before = (now - timedelta(days=REMEASURE_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
    eligible = _eligible(db_path, host)
    order: list[tuple[int, int, str, str]] = []

    def effort_rank(slug: str) -> int:
        effort = model_effort(slug)
        return EFFORT_ORDER.index(effort) if effort in EFFORT_ORDER else len(EFFORT_ORDER)

    for slug in eligible:
        m = current.get(slug)
        if m and m["recent_failures"] >= MAX_RECENT_FAILURES:
            order.append((3, 0, slug, "REPEATED_FAILURES"))
        elif not m or not m["complete"]:
            order.append((0 if slug in table_models else 1, effort_rank(slug), slug, "NEW_OR_INCOMPLETE"))
        elif slug in table_models and (m["measured_at"] or "") < stale_before:
            order.append((2, 0, slug, "MONTHLY_REMEASURE"))
    order.sort()
    todo, deferred = [], []
    gemini_left = (quota or {}).get(GROUP_GEMINI)
    limit = max_models if quota else min(max_models, UNKNOWN_QUOTA_MAX_MODELS)
    for _, _, slug, reason in order:
        left = remaining_for(slug, quota)
        if reason == "REPEATED_FAILURES":
            deferred.append({"model": slug, "reason": reason})
        elif gemini_left is not None and gemini_left < MIN_GEMINI_QUOTA:
            deferred.append({"model": slug, "reason": "QUOTA_LOW", "remaining": gemini_left})
        elif is_scarce_model(slug, host) and left is None:
            deferred.append({"model": slug, "reason": "QUOTA_UNKNOWN"})
        elif is_scarce_model(slug, host) and left < MIN_SCARCE_QUOTA:
            deferred.append({"model": slug, "reason": "SCARCE_QUOTA_LOW", "remaining": left})
        elif len(todo) >= limit:
            deferred.append({"model": slug, "reason": "MAX_MODELS_PER_RUN"})
        else:
            m = current.get(slug)
            todo.append({"model": slug, "reason": reason,
                         "suites": m["missing_suites"] if m and not m["complete"] and m["missing_suites"] else None})
    return {"todo": todo, "deferred": deferred, "eligible": eligible, "quota": quota}


def run_measurements(db_path: Path, *, quota: dict[str, float] | None, max_models: int = DEFAULT_MAX_MODELS,
                     reps: int = DEFAULT_REPS, adapter: Any | None = None,
                     timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    plan = measurement_plan(db_path, quota=quota, max_models=max_models)
    results = {}
    for item in plan["todo"]:
        only = set(item["suites"]) if item.get("suites") else None
        runs = measure_model(db_path, item["model"], reps=reps, adapter=adapter, timeout_seconds=timeout_seconds,
                             suites=only)
        results[item["model"]] = {"reason": item["reason"], "runs": len(runs),
                                  "errors": sum(1 for r in runs if r["status"] != "OK")}
    current = measurements(db_path)
    return {"bench_version": BENCH_VERSION, "measured": results, "deferred": plan["deferred"],
            "summary": {slug: current.get(slug) for slug in results}}
