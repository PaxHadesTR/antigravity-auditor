# Antigravity Auditor — Deterministic Control Plane + Mandatory Independent Second-Pass Verification

This package turns Antigravity into a safer everyday engineering partner: it adds skills and project rules you use in ordinary conversations (planning a feature, reviewing a change, preparing a release), chat tools that audit a project on demand, and an automatic background audit. See [Everyday use](#everyday-use-in-antigravity) first; the rest of this README explains how the auditor works underneath.

Technically, it implements the autonomous project auditor architecture for Antigravity App 2.0 on Windows 11. It provides a deterministic Python + SQLite control plane, mandatory two-pass audit verification in a separate Antigravity conversation, a 10-check Deterministic Evidence Verification Gate, a weekly Windows scheduled task (multi-pass audit + model catalogue sync), an MCP server for the Antigravity agent (start audits from the chat, review findings, approve and apply fixes), isolated Git worktree execution with one commit per fix, the auditor's own test run, optional automatic PR + merge behind GitHub CI, audit quality metrics, and multi-project recovery.

## Everyday use in Antigravity

The weekly audit is only one part. After installation you can use the following in **any Antigravity conversation, on any day**, without the terminal:

**Skills** (installed globally in `~/.gemini/config/skills`, available in every project; ask in your own words, the agent picks the skill):

| Skill | Use it when | Example request |
| --- | --- | --- |
| `prompt-co-architect` | you start a feature, refactor, schema change or new project: it scans the code, asks 2–4 trade-off questions and writes a draft specification with acceptance criteria; nothing is implemented before you approve it | "I want to add CSV export; let's spec it first." |
| `adversarial-red-team` | you want a hostile, read-only review of code or of a diff before you ship it, along the seven V1–V7 vectors (concurrency, resource and memory bounds, transaction atomicity, security and secrets, failure and network resilience, adversarial test coverage, contract parity) | "Red-team the changes in this branch." |
| `release-and-handoff` | a change is done: it runs the final tests and static checks, updates the project docs, lists what it verified and prepares Conventional Commit commands | "Prepare the handoff for this feature." |
| `project-auditor-orchestrator` | you want a full audit of the current project now, its results, or an explanation of the auditor's model choices; it never changes code without your approval | "Audit this project now." / "What did the last audit find?" |
| `independent-audit-verifier` | findings need a second, independent check in a separate conversation (the audit flow uses it automatically) | "Verify the findings of the last audit." |

If you already have your own skills with these names (for example with your own shortcuts), the installer keeps them and backs up the bundled version instead.

**Project rules** (`.agents/rules/01`–`05`, copied into a repository with `register --copy-omniapex-rules`): Antigravity applies them automatically by file type whenever the agent works on that project: backend and concurrency, frontend (web and mobile), database and schema, DevOps and infrastructure, testing and verification.

**Chat tools** (the `antigravity-auditor` MCP server, verified Antigravity only): start an audit now, see the audit status and the auditor's notices, list findings with their code context, follow the independent verification, ask which model serves which role and why, decide `APPLY` / `DEFER` / `DISMISS` per finding and let the agent fix the approved ones on a separate branch (see [APPLY](#apply-fixes-without-windows-hello)).

**A typical day:**
1. New feature: "let's spec it first" (`prompt-co-architect`) → implement with the agent (the project rules apply) → "red-team the diff" (`adversarial-red-team`) → "prepare the handoff" (`release-and-handoff`).
2. Something feels wrong in a project: "audit it now" → read the verified findings → approve fixes → review the `audit-fix/...` branch.
3. Curious about the models: "which model checks critical findings, and why?"

**In the background, with no action from you:** the weekly audit of every enabled project (with `-InstallWeeklyTask`), keeping the model routing table current, and telling you in the chat when something changed.

## Quick start

1. **Install** (Windows 10/11, Python 3.11+, Git, Antigravity with the `agy` CLI; close Antigravity first):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Install-AntigravityAuditor.ps1 -InstallWeeklyTask
   ```
   It copies the package to `%LOCALAPPDATA%\AntigravityAuditor`, installs the global skills conflict-safely, creates/migrates `database\auditor.db`, registers the MCP server in `~/.gemini/config/mcp_config.json` and (with `-InstallWeeklyTask`, optionally `-WeeklyDay MON -WeeklyTime 04:00`) creates the weekly Windows task. Every step is rolled back if one fails. Finally it starts `models setup` in the background: the auditor lists the models **your** Antigravity account offers, probes them, collects their published benchmark results, gates each model with two test calls and activates a routing table built for your account (about half an hour, spends Antigravity quota; the agent tells you the result in the chat). Skip it with `-SkipModelSetup` and run `python core\cli.py models setup` later.
2. **Register a repository** (the Antigravity Project ID is detected when possible):
   ```powershell
   python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" register --path C:\path\to\repo --key myproj --project-id <id>
   ```
3. **Restart Antigravity.** In the project's chat ask, for example, "audit myproj now"; later "show the report", decide (`APPLY` / `DEFER` / `DISMISS`), and say yes when the agent asks to fix. The fixes arrive as a local branch `audit-fix/...` with one commit per finding (see [APPLY](#apply-fixes-without-windows-hello)).
4. Optional, per project (terminal only): `project-settings set --project myproj --delivery-mode pull_request` lets the auditor push the fix branch and open a described PR that you merge (`auto_merge` also merges it when GitHub CI passes); `--approval-mode strict` requires a terminal approval for every fix.

Without the weekly task nothing runs on a schedule; `cli.py audit-now --project <key>` or the chat starts an audit at any time.

## Mandatory Two-Pass Verification Architecture

Every primary audit is strictly separated from execution eligibility:
1. **Primary Candidate Submission (`auditor_publish_report`):** Stores primary findings as non-executable `CANDIDATE` records in `candidate_findings`, binds them to an immutable repository snapshot (`audit_snapshots`: `snapshot_id`, `base_commit_sha`, `working_tree_hash`, and tracked `file_hashes_json`), creates exactly one durable verification job in `verification_dispatch_queue`, and transitions the run to `VERIFICATION_PENDING`. Primary audits never mark a run `READY_FOR_REVIEW`.
2. **Independent Second-Pass Conversation (`AgentApiAdapter` & `VerificationWorker`):** A separate Antigravity conversation is launched via `agentapi new-conversation` (or generated as a manual verification prompt when `agentapi` is unavailable) without the primary auditor's chain-of-thought or authoritative severity/confidence conclusions.
3. **10-Check Deterministic Evidence Verification Gate (`core/verification.py`):** For every candidate claim, Python independently validates:
   1. Relative repository path
   2. No path traversal (`..`)
   3. Resolved path inside repository root
   4. File exists and is not an excluded secret (`.env`, private keys, credentials)
   5. File SHA-256 matches the audit snapshot (`VERIFICATION_STALE` if modified)
   6. Valid 1-based line range (`line_start <= line_end`)
   7. Line range points to actual non-empty source lines
   8. Evidence excerpt matches the source slice and `evidence_sha256`
   9. Symbol/function reference is structurally plausible and present
   10. Repository `HEAD` SHA and clean working-tree snapshot remain consistent
4. **Atomic Canonical Finalization (`auditor_finalize_verified_report`):** Only when every candidate has a final verdict (`CONFIRMED`, `PARTIALLY_CONFIRMED`, `REJECTED`, `UNVERIFIABLE`), no candidate remains `UNVERIFIABLE`, the snapshot is consistent, and verifier conversation metadata is recorded does Python atomically promote findings and transition the run to `READY_FOR_REVIEW`.
5. **Strict Decision & Execution Gates:** `auditor_save_decisions(APPLY)` and the human-only terminal authorization (`cli.py authorize-execution`) allow only `VERIFIED` (`CONFIRMED` + `PASSED` evidence gate + safe remediation review) findings from a `READY_FOR_REVIEW` run whose snapshot still matches the repository. Pre-existing findings without second-pass verification are classified as `LEGACY_UNVERIFIED` and cannot be applied without re-verification.

## What is integrated from OmniApex v7.3

- Keeps the existing global `~/.gemini/AGENTS.md` untouched.
- Imports `prompt-co-architect`, `adversarial-red-team`, `release-and-handoff` (OmniApex) and `project-auditor-orchestrator`, `independent-audit-verifier` (auditor) into Antigravity's documented global skills directory (`~/.gemini/config/skills`) via `install-global-skills --include-omniapex`, preserving any existing customized skills untouched while backing up both the customized skill and the incoming bundle version under `%LOCALAPPDATA%\AntigravityAuditor\backups\skills-<timestamp>`.
- Preserves the five V1–V7 technology rules (`01-backend-and-systems.md` through `05-testing-and-verification.md`) and, with `register --copy-omniapex-rules`, copies them into the repository's `.agents/rules/` (an existing rule with the same name is kept; the incoming one is saved next to it as `<name>.omniapex-imported.md`). Their `globs` are a quoted, comma-separated string, as Antigravity requires.
- Inventories additional skills already installed globally or in each workspace (`workspace:<project_key>`).

## Architecture & Core Modules (`core/`)

- [`core/db.py`](core/db.py): SQLite control plane (WAL mode, foreign keys, versioned schema migrations `v1 -> v10`; `005` adds governance/broker columns and `execution_leases` / `finding_checkpoints`, `006` the NEXT-22B entitlement/routing tables, `007`–`010` the model catalogue, probe runs, research reports and routing-table versions — all are applied automatically on first start, so back up `auditor.db` before upgrading), `audit_snapshots`, `candidate_findings`, `audit_verification_runs`, `finding_verification_results`, `verification_dispatch_queue`, `audit_quality_metrics`, legacy constraint upgrades, `LEGACY_UNVERIFIED` classification, online backups (`sqlite3.backup`), and restore verification.
- [`core/agentapi.py`](core/agentapi.py): Testable `AgentApiAdapter` abstraction for launching independent Antigravity conversations via `ANTIGRAVITY_AGENTAPI_EXE` or `agentapi` on `PATH` using argument arrays (never shell string concatenation), conversation ID extraction/validation, and `DISPATCH_UNCERTAIN` safeguards.
- [`core/verification.py`](core/verification.py): Two-pass state machine transitions, snapshot capture/revalidation, 10-check Deterministic Evidence Verification Gate, context-independent verification prompt generator, `auditor_get_verification_context` / `auditor_submit_verification` / `auditor_get_verification_status` / `auditor_finalize_verified_report` logic, durable queue leases, `VerificationWorker` Sidecar loop, Sidecar configuration helpers, and quality metrics calculation.
- [`core/mcp_server.py`](core/mcp_server.py): Entry point of the `antigravity-auditor` stdio MCP server. `main()` builds `AuditorMCPDispatcher` and serves it through the adaptive gateway (see [MCP Gateway & Caller Identity](#mcp-gateway--caller-identity-final-delivery)); the legacy `MCPStdioServer` class is kept for unit tests only. The dispatcher validates strict input/output schemas (`additionalProperties: False`) and implements these tools (plus the gateway's `auditor_gateway_capabilities`):
  - `auditor_audit_now` (start an audit in the background; see [Starting an audit from the agent chat](#weekly-scheduled-audit-headless-mcp-free-delivery))
  - `auditor_models_overview` (read-only routing table, catalogue and probe status)
  - `auditor_get_context`
  - `auditor_publish_report`
  - `auditor_get_verification_context` (paged by candidate: `limit` 1–50 and `offset`; returns `candidate_count` and `next_offset`)
  - `auditor_submit_verification`
  - `auditor_get_verification_status`
  - `auditor_finalize_verified_report`
  - `auditor_list_findings` (paged: `limit` 1–50, default 50, and `offset`; returns `count` for the page and `next_offset`, `null` on the last page; without `run_id` the latest report waiting for review, `all_runs: true` for every run)
  - `auditor_save_decisions` (`run_id` optional: the latest report waiting for review)
  - `auditor_authorize_execution`
  - `auditor_start_execution`
  - `auditor_update_finding_execution`
  - `auditor_finalize_execution`
  - `auditor_get_status` (recent events paged with `events_limit` 1–50, default 20, and `events_offset`; `recent_events_next_offset`; per project also `latest_audit_log` and `latest_delivery`)
- [`core/review.py`](core/review.py): Renders Markdown review reports and structured finding listings distinguishing `CANDIDATE`, `VERIFIED`, `PARTIALLY_VERIFIED`, `REJECTED`, `UNVERIFIABLE`, and `LEGACY_UNVERIFIED` findings.
- [`core/executor.py`](core/executor.py): Isolated Git worktree executor with per-finding checkpoints, dual-path happy/adversarial test gates, bounded repair attempts (max 2), and red-team diff verification.
- [`core/recovery.py`](core/recovery.py): Disk-space guards, moved-repository detection, failed worktree quarantine, and stale lock recovery. `detect_moved_repositories(..., persist=False)` computes repository health without writing; read-only callers such as `auditor_get_status` must use it (ARCH-02).
- [`core/model_registry.py`](core/model_registry.py), [`core/model_policy.py`](core/model_policy.py), [`core/agy_adapter.py`](core/agy_adapter.py), [`core/model_attestation.py`](core/model_attestation.py), [`core/model_budget.py`](core/model_budget.py): tiered model routing, `agy` dispatch, runtime model attestation and scarce-model budgets — see [Model Routing](#model-routing-dynamic-registry).
- `core/mcp_gateway/`, `core/application_adapters/`, `core/runtime_discovery/`, `core/entitlement_router/`, `core/broker/`: final-delivery gateway, client adapters, discovery/redaction, advisory model router and the (currently unwired) Windows broker — see the next section.

## MCP Gateway & Caller Identity (final delivery)

`core/mcp_server.py:main()` runs `build_local_stdio_gateway_host(..., allow_execution_tools=apply_enabled())` (APPLY is on unless `ANTIGRAVITY_AUDITOR_APPLY=0`):

- **Caller identity comes from the OS, never from the client.** `core/application_adapters/stdio_entry.py` verifies the real Windows process ancestry (`Antigravity.exe -> language_server.exe -> python.exe`, or `Antigravity.exe`/`agy.EXE` directly) using token SID, session, integrity level, kernel creation time and reparse-point-free executable paths under the token-derived `%LOCALAPPDATA%`. `clientInfo.name`, `--application-hint` and environment variables are untrusted hints.
- **Verified Antigravity** gets the audit-lifecycle scopes `core:read`, `project:read`, `evidence:read`, `audit:run`, `audit:publish`, `verification:submit`, `governance:finalize`, `models:read` (11 tools: status/capabilities, context, findings, verification context/status, start an audit, publish, submit verification, finalize report, model routing overview) plus, with APPLY on, `governance:decide` and `execution:run` (`auditor_save_decisions`, `auditor_start_execution`, `auditor_update_finding_execution`, `auditor_finalize_execution`). `governance:authorize` is never granted: authorizing an execution is human-only (see [APPLY](#apply-fixes-without-windows-hello)). Publishing, verification and finalization **write** to `auditor.db` and the target repository's `.antigravity-audit/` folder.
- **Any other caller** (PowerShell, scripts, unknown apps) is clamped to `UNKNOWN` + `core:read` → only `auditor_get_status` and `auditor_gateway_capabilities`.
- **Disabled:** `auditor_authorize_execution` over MCP (human-only) and the five `auditor_routing_*` tools (no `routing:read` scope is granted). With `ANTIGRAVITY_AUDITOR_APPLY=0` the decision and execution tools are withheld as well. `broker_client=None`: the stdio path uses direct SQLite; the `core/broker/` Session-0 service is not wired in (B4-C, see [DEFERRED_FEATURES.md](DEFERRED_FEATURES.md)).
- `tools/list` visibility and `tools/call` authorization are evaluated independently on every call; outputs are redacted (secrets/PII), schema-checked and bounded (default 50 items; per-tool text limit 4096–6000 chars).
- **Text view for content-only clients.** Antigravity reads the MCP `content` text, not `structuredContent`. When a result does not fit the tool's text limit, `core/mcp_gateway/output_adapter.py` condenses it step by step — compact JSON, drop empty values and opaque hashes, cap long strings, drop long free-text fields inside list items, then drop trailing list items — and adds a `text_view` block listing `omitted_fields` / `omitted_items`. `structuredContent` still carries the full schema-bounded result. To read complete finding details, page with a small `limit` (e.g. `auditor_list_findings` with `limit: 2` and `offset`).
- **Request budget:** `CommonStdioAdapterHost` measures a 15 s budget after the synchronous call completes. A slow request is logged to stderr as `Slow request ...`, but its real result is still returned, so a completed `auditor_publish_report` is never reported as a failure (ARCH-06).

## Model Routing (dynamic registry)

**How models stay current (fully automatic).** The auditor builds its routing table from the models *your* account offers and from **published benchmark results**; you only get told what changed. Its own tests are only a cheap gate: on 2026-11-19/20 every Gemini 4 model scored perfectly on the auditor's own verification suites, so they could not rank models, while published results (e.g. the Artificial Analysis Intelligence Index per reasoning effort, SEC-bench Pro, CWE-bench) do separate them.

0. **First install.** The installer runs `models setup` once in the background: it probes every eligible model of the account (up to 12), collects their published results and gates them, and activates the account's own table (about half an hour).
1. **Notice.** Every manual audit and the weekly task run `agy models`; models that appear (e.g. a newly enabled Gemini line) or disappear are recorded.
2. **Qualify.** New eligible models are probed on a fixture repository with planted defects (`probe_repo_v1`); only models with a `PASSED` probe can be used. Scarce models (Argon) are probed while their own quota is above 50 %.
3. **Collect published results** (`core/model_evidence.py`, weekly and for new model lines). One web-research call asks the `STANDARD` model for published numbers of every model variant: the Artificial Analysis Intelligence Index per reasoning effort and security benchmarks (SEC-bench Pro, CWE-bench v1/v2, RealVuln, CyberGym). The answer is untrusted: the auditor fetches each cited page itself (`https`, public address, same-host redirects, size and time capped) and keeps a number only if the page is the benchmark's own site or an official Google page, the value is on it, and nearest to that value stand the claimed model (no other model name closer), the claimed effort (same clause) and, on vendor pages, the claimed benchmark. Everything else is rejected with a fixed reason; numbers older than 120 days are dropped. `python core\cli.py models evidence --show` lists the numbers in use.
4. **Gate.** Each new eligible model runs two calls of the auditor's own benchmark (`core/probe_fixtures/bench_v1`): one *FIND* (planted defects among decoys) and one *VERIFY* (12 candidate critical findings where real defects hide behind subtle details and false ones look dangerous but are safe). A model may serve a tier only if it reaches the floor (`ENTRY` 0.60, `STANDARD` 0.75 on FIND; `CRITICAL` 0.85, `CATASTROPHIC` 0.90 on VERIFY). Its tokens per call are the cost the engine compares. There is no periodic re-measurement; at most 6 models per weekly run, nothing while the shared Gemini quota is below 35 % (Argon: below 50 % of its own quota).
5. **Choose.** For each tier the table takes the cheapest model among the strongest ones by published Intelligence Index (allowed gap: `ENTRY` 10 points, `STANDARD` 4, `CRITICAL` 2, `CATASTROPHIC` 0); priority `CATASTROPHIC` > `CRITICAL` > `STANDARD` > `ENTRY`; tokens are weighted by how often a tier is used and a scarce model (Argon) counts four times; `CRITICAL`/`CATASTROPHIC` must stay on a different model line than `STANDARD` (so `STANDARD` is compared with the models it may use). On the critical tiers, ties are broken by the security benchmarks (a pairwise comparison of the lines on the benchmarks both have) and, for `CATASTROPHIC`, the higher effort. The active table is kept unless the best table is stronger or saves more than 10 % weighted tokens. Until every working model of the active table has a verified published index and a gate run, the older research-based engine is used instead (it only replaces models that are no longer offered).
6. **Activate and tell.** Automatic approval is **on by default**: a proposal is activated when every changed tier has a verified published result, a `PASSED` probe, a passed gate and is not clearly weaker than the model it replaces; approval re-validates catalogue, policy and probes and is recorded as `ROUTING_TABLE_APPROVED` with `decided_by = auto:probe+research`. Each outcome (new or removed models, a table change with its undo command, a proposal that needs you) is stored as a notice; `auditor_get_status` returns it as `models.notices` (with the numbers in use as `models.published_results`) and the agent tells you once in the chat.

Opting out and undoing (your terminal, interactive with a typed confirmation): `python core\cli.py models auto-approve off|on|status` (`status` also works non-interactively; with it off, proposals wait for `models proposal approve <version_id>`); `python core\cli.py models restore <version_id>` re-activates an earlier table; `python core\cli.py models proposal create --set CATASTROPHIC=agy:<model> --note "<why>"` stores a manual proposal (never auto-approved). By hand: `python core\cli.py models evidence` (one research call) and `python core\cli.py models measure [--model <slug>]` (the two-call gate). Research-based proposals (fallback engine) are auto-approved only if every changed tier has a `PASSED` probe and the research report the proposal was built from places the line in exactly that tier with `MEDIUM`/`HIGH` confidence, an official source and no self-assessment.

Model choice is split in two layers so models can change without code changes:

1. **Routing tier** — `core/model_policy.py:route_model` deterministically maps every task to `ENTRY`, `STANDARD`, `CRITICAL` or `CATASTROPHIC` from controller metadata (task type, severity, evidence-gate status, explicit operator escalation; never the model's free-text finding category). LLMs cannot pick or escalate their own tier, and unvalidated evidence can never reach `CRITICAL`/`CATASTROPHIC` (`BLOCKED_EVIDENCE`).
2. **Routing table** — `core/model_registry.py` maps tiers to backend-qualified models. The table is **per install**: it is built from the models your account offers (see above), so it differs between accounts and changes when Google enables or retires a model. `python core\cli.py models overview` shows the table active on your install. Tiers, the built-in seed (used only before the first evidence-based or approved table) and, as an example, the table chosen on 2026-11-20 on an account that offers Gemini 4 Hydrogen, Neon and Argon:

   | Tier | Used for | Seed (`seed-2026-11-15`) | Example: chosen 2026-11-20 |
   | --- | --- | --- | --- |
   | `ENTRY` | finding classification | `agy:gemini-4-hydrogen-medium` | `agy:gemini-4-neon-medium` |
   | `STANDARD` | primary audit, exploration, routine verification (moved to `CRITICAL` when it would share the primary audit's model line) / red-team, repair planning, reports | `agy:gemini-4-hydrogen-high` | `agy:gemini-4-hydrogen-high` |
   | `CRITICAL` | verification of a run whose most severe evidence-validated candidate is `HIGH` | `agy:gemini-4-argon-medium` | `agy:gemini-4-neon-high` |
   | `CATASTROPHIC` | verification of a run with an evidence-validated `CRITICAL` candidate (the table's strongest model) | `agy:gemini-4-argon-high` | `agy:gemini-4-neon-xhigh` |

   The example column is what the evidence engine chose on that account from verified published results (Artificial Analysis Intelligence Index, low/medium/high/xhigh: Neon 44/55/60/61, Hydrogen 27/41/51/54, Argon -/48/50/-; SEC-bench Pro: Neon 90.5, Argon 83.4; CWE-bench v2: Neon 70.7, Hydrogen 68.1, Argon 65.0) and two gate calls per model (all passed): `CATASTROPHIC` takes the strongest model (Neon xhigh, 61); `CRITICAL` the cheapest within 2 points (Neon high, 60); `STANDARD` must leave the Neon line and takes the cheapest within 4 points of the best other model (Hydrogen high 51 vs. Hydrogen xhigh 54); `ENTRY` the cheapest within 10 points (Neon medium, 55). Argon is not used on that account (weaker published results, scarce quota). Your install collects the results for its own models and may end up with a different table.

**Hard policy** (`HARD_POLICIES`, keyed by host application × dispatch backend) cannot be overridden by any table: for `antigravity` × `agy` only Gemini models are allowed and the Gemini 3.8 Flash line and orchestrator models are denied. Host/backend pairs without an entry (e.g. `claude_code`, `codex`, `vibe`) are denied until a policy is added explicitly. Tables are validated on load (every tier assigned, every model allowed, `CRITICAL`/`CATASTROPHIC` on a different model line than `STANDARD`). A tier whose model is not dispatchable blocks with `BLOCKED_MODEL_UNAVAILABLE`; there is no silent fallback.

**Attestation** (`core/model_attestation.py`) reads the agy conversation's `gen_metadata` and resolves the effort-qualified model from the display name (`Gemini 4 Hydrogen (Medium)` → `gemini-4-hydrogen-medium`); the internal id (`gemini-4-hydrogen`, `gemini-4-argon-trial`) must belong to the same model line. **Independence** requires different model lines: two efforts of one line (Hydrogen High vs Hydrogen Medium) are never independent verifiers. The second-pass verifier is routed like any task; if the routed model shares the primary auditor's line (the primary audit runs on `STANDARD`), verification moves to the `CRITICAL` tier, which the table keeps on another line. A scarce `CRITICAL` model (Argon) is used this way only for critical verification (a `CRITICAL`/`HIGH` candidate); otherwise the run stays on `STANDARD` and is recorded as same-model verification. **Budgets**: models matched by the policy's scarce patterns (currently the Gemini 4 Argon line) require atomic reservations.

`python core/cli.py model-status` prints the active table, approved models and detected dispatch backends (`agy`; `vibe` is a reserved extension point).

**Model catalogue** (`core/model_catalog.py`, migration `007`): `python core/cli.py models sync` runs `agy models`, stores a snapshot in `model_catalog_snapshots` only when the list changed (`INITIAL` / `UNCHANGED` / `CHANGED`, with added/removed/renamed models) and records every check, including failures, in `model_catalog_state`. It then reports **routing-table health**: `HEALTHY`, `STALE` (a tier model is no longer offered — dispatches of that tier will fail rather than fall back), `UNKNOWN` (never synced) or `INVALID`; the command exits with code 2 on `ERROR`/`STALE`/`INVALID`. When a catalogue exists, attestation also rejects internal ids that belong to a longer sibling model line (e.g. `<line>-lite`). `python core/cli.py models overview` and the MCP tool `auditor_models_overview` (scope `models:read`, verified Antigravity only) show the table, its health and every catalogue model with its hard-policy status — read-only, they never run a backend CLI.

**Model probes** (`core/model_probes.py`, migration `008`): `python core/cli.py models probe` gives each eligible model the full source of a small fixture repository (`core/probe_fixtures/probe_repo_v1`: 9 planted defects plus correct-but-suspicious decoys) with line numbers, requires schema-constrained JSON (`agy --json-schema`), and scores recall, precision, **fabricated references** (cited file/lines/quote not in the source), schema validity, latency and tokens against a ground-truth file the model never sees; the model identity is runtime-attested. Results (`PASSED` / `DEGRADED` / `FAILED` / `ERROR` / `ATTESTATION_FAILED`) are stored in `model_probe_runs`, pinned to the suite's SHA-256, and shown in `models overview` / `auditor_models_overview`. Probes are a qualification gate: current Gemini 4 models all solve the suite, so proposals rank eligible models by research and efficiency. Scoring is strict: a finding counts only if it names an existing fixture file exactly (no `..`, absolute or backslash paths), cites at most 8 lines, quotes a whole source line (or a substantial part of one) inside that range, and agrees on both location and symbol; every defect is credited once (repeats are duplicates), and `PASSED` needs no fabrication, recall ≥ 0.8 and precision ≥ 0.75. A dispatch error or unparsable answer is retried once (both attempts are recorded); quality failures are never retried. Eligibility: hard policy checked on the raw model reference (a model can be probed before it is in the routing table), plan mode only, already-probed models are skipped unless `--reprobe`, and scarce models (Gemini 4 Argon) need `--include-scarce`. Probe sessions run in an empty temporary directory with `--settings` denying MCP tool calls and shell commands (`agy_adapter.ISOLATED_SESSION_SETTINGS`): the agy CLI has this auditor's own MCP server configured, and helper sessions must never reach it. `models sync --probe` probes every eligible non-scarce model that has no probe result yet (also when an earlier sync recorded the change), and `--research-new` runs the web research when the latest research report does not cover a catalogue model line.

**Web research** (`core/model_research.py`, migration `009`): `python core/cli.py models research` asks the routing table's `STANDARD`-tier model, in the same isolated agy session (plan mode, MCP and shell denied, empty temp dir), to research every policy-allowed catalogue model line with web search and answer schema-constrained JSON (positioning, capability rank, suggested tier, cost/latency class, confidence, sources). The report is stored as **untrusted web evidence**: unrequested lines are dropped, text is sanitised and capped, sources must be `https` and are classified `OFFICIAL` (Google-owned hosts), `THIRD_PARTY` or `SEARCH_REDIRECT` (opaque grounding links, never official); a session that never used a web tool is `NO_WEB_EVIDENCE`; a capability rank that contradicts the suggested tiers is flagged `INCONSISTENT` (ranks must then be ignored) and a researcher assessing its own model line is flagged `self_assessed`. Research never changes routing, and `auditor_models_overview` shows only its enums, numbers and fixed-text issues — never web-derived free text (indirect prompt-injection boundary).

**Routing-table proposals and approval** (`core/model_routing_proposals.py`, migration `010`): the active table is the latest user-approved `ACTIVE` row in `routing_table_versions` (at most one `ACTIVE` and one `PROPOSED` per host, enforced by unique indexes), otherwise the seed. An approved table that no longer validates fails closed — it never silently reverts to the seed. The CLI and MCP entry points pin the store to their `auditor.db` (`configure_routing_store`). `python core/cli.py models propose` (or `models sync --probe --propose`) builds a proposal from the catalogue, probes and the latest `COMPLETED` research, conservatively: a tier changes only if its model is no longer offered/allowed (replaced by a model with a `PASSED` probe, preferring the research-suggested line, then the incumbent's line), or if research places the incumbent's line in another tier and a probed model of the suggested line exists. Research capability ranks are never used; ties go to the tier's effort preference, then probe latency and tokens; every proposal must pass `validate_routing_table`. `models proposal show` lists the pending proposal with per-tier rationale and history. **Approval is human-only**: `models proposal approve|reject <version_id>` and `models revert-to-seed` require an interactive terminal and a typed confirmation (headless agents, MCP tools and scheduled tasks are refused), re-validate against the current catalogue and policy, supersede the previous table atomically and record `ROUTING_TABLE_*` audit events. There is no MCP tool that approves; `auditor_models_overview` only shows the pending proposal. The automatic approval (`models auto-approve on|off`, on by default, setting in `config/model_auto_approve.json`) is the only non-interactive path; it calls the same `approve_proposal` after the gates in `auto_approve_blockers`. `models restore <version_id>` re-activates a `SUPERSEDED` table as a new version (interactive; catalogue and policy re-checked, no new probe needed for models that were approved before). Approval re-checks, inside the approval transaction, that every model is still offered and that models new to the active table still have a `PASSED` probe on the current suite. Cross-model independence of an audit is judged against every table that was ever approved (seed, active, superseded), so approving a new table does not invalidate audits already in flight. **Limit:** the TTY + typed-confirmation gate stops headless agents, MCP tools, piped input and scheduled tasks, but it is not a privilege boundary against code running as the same Windows user (a process with shell access can allocate a pseudo-terminal, call the Python API, or edit `auditor.db`). A hardware-backed confirmation (Windows Hello / TCB, see B4-B in `DEFERRED_FEATURES.md`) is the planned hard boundary.

### Deployment

Antigravity starts the server from `~/.gemini/config/mcp_config.json` (`command: C:\Python315\python.exe`, `args: [<install root>\core\mcp_server.py]`, `env.ANTIGRAVITY_AUDITOR_HOME`). The DB path defaults to `<ANTIGRAVITY_AUDITOR_HOME>\database\auditor.db` and can be pinned with `ANTIGRAVITY_AUDITOR_DB`. Deploy from a stable install directory rather than a Git worktree, back up `auditor.db` (+ `-wal`/`-shm`) before upgrading, and fully close Antigravity so no old server process overlaps with the new one. After restart, `auditor_gateway_capabilities` must report `application_id: "antigravity"`, `verified_application_identity: true` and `execution_authorized: false`.
- [`core/telemetry.py`](core/telemetry.py): Structured console and JSONL audit event logger with secret/token redaction.
- [`core/skills.py`](core/skills.py): Discovers and hashes global, `universal-kit`, and workspace skills and rules.
- [`core/cli.py`](core/cli.py): Unified CLI entrypoint for installer, the weekly scheduled task (`schedule`, `weekly`, `scheduled-audit`), verification worker, manual verification prompt generation, agent report ingestion, review/approval, isolated execution, quality reports, and recovery.

## APPLY: fixes without Windows Hello

APPLY turns verified findings into fixes without touching the user's working tree:

1. **Decide** -- the agent records the user's choices with `auditor_save_decisions` (`APPLY`, `DISMISS`, ...). Only second-pass `VERIFIED` findings of a `READY_FOR_REVIEW` run qualify. A finding whose verification was not independent (primary audit and verifier on the same model line, or models not runtime-attested -- e.g. a Hydrogen-only week, or an interactive MCP audit) is marked `model_independent = 0`: it can still be applied through the terminal authorization (which prints a warning for it), but the auto-approval policy refuses it unless `allow_single_model_verification` is set.
2. **Approve** -- depends on the project's approval mode (`cli.py project-settings show --project <key>`); `run_id` is optional everywhere (default: the latest report waiting for review):
   - **`simple`** (default): the agent lists the `APPLY` findings in the chat and asks; after the user's explicit yes it calls `auditor_start_execution` with `chat_approved: true`. No terminal, nothing to copy. Refused for a run with an evidence anomaly (terminal approval needed).
   - **`strict`**: the user runs `python core\cli.py approve --project <key>` in an interactive terminal (lists the findings and warnings, asks `y/N`; valid 24 h). The agent then calls `auditor_start_execution` with only `project_key` and finds that approval itself. Agents have no terminal and the MCP authorize tool always refuses.
   - **auto-approval policy** (optional, below): `auto_approve: true`.
   - `approval_id` from `approve` is still accepted. `authorize-execution` is the old name of `approve`.
3. **Execute** -- the approval is consumed and an isolated Git worktree is created at the audited commit (a moved `HEAD` or changed files make the run `VERIFICATION_STALE`). The agent edits only inside that worktree and reports each finding with `auditor_update_finding_execution` (`begin` / `verify` with happy-path, adversarial and red-team results / `rollback`; at most two repairs, then the checkpoint is restored). **Each verified finding is committed on its own** in the worktree (`audit(<id>): <title>`, commit hooks skipped for these intermediate commits); a committed finding can no longer be rolled back.
4. **Deliver** -- `auditor_finalize_execution` (after integration tests; failures are quarantined with the full diff against the base commit) puts the commits on a **local review branch** `audit-fix/<run>-<id>` (changes made after the last verified finding become one more commit) and writes a patch to `reports/<run>/<exec>.patch`. Then **the auditor runs the project's tests itself** on the result (see below) and reports them in `review.tests`; a failure does not hide the branch but adds a `warning`. By default nothing is merged or pushed (see `pull_request` and `auto_merge` below for the opt-in exceptions); the result lists the commits, the changed files and review commands (`git log`, `git diff`, push + `gh pr create`, or `git merge --no-ff --no-edit`). The worktree is removed; the branch keeps the result. If the repository has no Git identity the commits use `Antigravity Auditor <auditor@localhost>`.

### Project settings (terminal only)

```powershell
python core\cli.py project-settings show --project <key>
python core\cli.py project-settings set --project <key> --approval-mode strict        # or simple (default)
python core\cli.py project-settings set --project <key> --test-command "python -m pytest -q" --test-timeout 900
python core\cli.py project-settings set --project <key> --clear-test-command          # detect again
python core\cli.py project-settings set --project <key> --delivery-mode pull_request   # or auto_merge, or local (default)
```

Changes ask `y/N` in an interactive terminal; no MCP tool can change them (the test command is executed by the auditor).

**The auditor's own test run.** After a fix, the control plane runs the configured test command in the worktree, or detects one: Python with tests -> `<project venv or current python> -m pytest -q` (`.venv`/`venv` in the repository is used when present, so the project's dependencies are found); Python without tests -> `python -m compileall -q .` (at least everything compiles); Node with a `test` script -> `npm test`. Default timeout 600 s (the whole process tree is stopped on timeout). The output tail is scrubbed of secrets. Result: `PASSED`, `FAILED`, `TIMEOUT`, `ERROR` or `NOT_CONFIGURED` (event `EXECUTION_TESTS_<status>`, `execution_runs.tests_json`). The agent's own `integration_test_passed` is still required, but no longer the only check.

**Pull request delivery (`--delivery-mode pull_request`, off by default).** After `finalize` the control plane itself (never the agent) runs `cli.py deliver` in the background: it pushes the review branch, opens a PR whose text lists the fix commits (one per finding), the auditor's test result and the run's findings that were not fixed (with the reason, e.g. the verifier rejected the proposed fix), waits for GitHub CI and records its result. It never merges: the PR stays open for you (`PR_OPEN`; `ci` is `PASSED` or the CI problem). The chat agent then no longer offers manual push/merge commands. The outcome is in `auditor_get_status` (`latest_delivery`) and the `DELIVERY_*` events. It uses your `gh` login.

**Keeping the checkout current (`pull_request` and `auto_merge`).** A fix merged on GitHub is not in your local checkout until it is pulled, and the auditor audits the local checkout. So before every audit it fetches `origin` and fast-forwards the default branch **only** when the checkout is on that branch, has no uncommitted changes to tracked files and no local commits; anything else is left alone and reported (`checkout_sync`, `CHECKOUT_SYNC` event). It also deletes `audit-fix/...` branches it created once they are fully merged, locally and on `origin`. Nothing is touched while an audit or a fix of the project runs, while an approved fix waits to start, or (scheduled runs) while a report waits for your decisions. A chat audit is not skipped as "no changes" while GitHub is ahead.

**New fix proposals for rejected fixes.** The verifier can confirm a finding but reject its proposed fix as unsafe; such a finding cannot be applied. After every finalized audit the auditor sends those findings, with the verifier's objection, to the repair planner (`STANDARD`, read-only), which proposes a new fix and test plan, and has each proposal reviewed independently (another model line). An accepted proposal becomes the finding's recommendation and the finding becomes applicable; a rejected one changes nothing (event `REMEDIATION_REPLANNED`). For an existing report: `python core\cli.py replan-remediations --project <key> [--run-id <run>]`. Partially verified findings are not re-planned.

**Automatic delivery (`--delivery-mode auto_merge`, off by default).** After `finalize` the control plane itself (never the agent) runs `cli.py deliver` in the background (log in `logs/delivery/`): it pushes the review branch, opens a PR, waits for GitHub CI and merges with a merge commit (per-finding commits stay visible; `git revert -m 1 <merge>` undoes it) **only if every gate passes**: the auditor's own test run `PASSED`, no `warning` or policy violation, nothing under `.github/` changed (a PR must not define its own check: merge those yourself), every check of the PR passed (none reported within 5 minutes, a failure, or 30 minutes without a result keeps the PR open), GitHub reports it mergeable and its head is exactly the verified commit. Then it deletes the remote branch, fast-forwards your checkout **only** when it is clean and on the default branch (otherwise it tells you to pull), and deletes the local review branch. When a gate fails the PR stays open for you (`PR_OPEN` with the reason). The outcome is in `auditor_get_status` (`latest_delivery`) and the `DELIVERY_*` events. It uses your `gh` login. Merged is not deployed: if a hosting service deploys on every push to the default branch (e.g. an "auto deploy" toggle), auto_merge means auto deploy.

The pytest run gets its own fresh `--basetemp`, so a stale entry in the shared per-user pytest temp folder cannot fail it.

**Weekly schedule (Windows Task Scheduler).** `python core\cli.py schedule install [--day MON --time 04:00]` creates one scheduled task `\AntigravityAuditor\Weekly` (runs as you, `pythonw` without a console window, starts as soon as possible after a missed time, never twice at once). It runs `models sync --probe --research-new --propose` (new models are noticed and probed, model lines no research covers yet are researched, and a proposal is created for your approval) and then `scheduled-audit` for every enabled project (log in `logs/weekly/`, event `WEEKLY_RUN_FINISHED`). It replaces the auditor's Antigravity Sidecars, which it backs up to `backups/sidecars-<time>/` and removes (`--keep-sidecars` keeps them); `register` then creates no new Sidecar. `schedule status` shows the last/next run, `schedule remove` deletes the task. A manual `audit-now` also refreshes the model list first.

**Multi-pass primary audit.** The primary audit runs three independent read-only passes in parallel (15 minutes each): security and data integrity (V3, V4), concurrency/resources/resilience (V1, V2, V5), and logic/contracts/tests (correctness, V6, V7). Their candidates are merged (same fingerprint, or same file + symbol + overlapping lines + category; the higher severity wins) before the usual second-pass verification (timeout 30 minutes). A failed pass is reported (`PRIMARY_PASS_FAILED`) without hiding the others. `ANTIGRAVITY_AUDITOR_PRIMARY_PASSES=1` restores the single 5-minute pass.

**Missing CI.** When a repository on GitHub with a recognisable project (Python or Node) has no CI configuration (`.github/workflows/*.yml|yaml`, GitLab, Azure, CircleCI, Jenkins, Bitbucket, Travis), the report contains `CI-MISSING-001` (MEDIUM, category `CI`). It is a deterministic control-plane check: no model call and no second-pass verification, so it is ready for a decision like any verified finding. `APPLY` lets the agent add a workflow under `.github/workflows/` and test files (nothing else; the recommendation contains a starting template). `DISMISS` keeps it dismissed in later audits; once CI exists an open CI finding is resolved. With CI in place, the PR of every fix branch is checked by GitHub before you merge.

The real decision is the merge, made on the actual diff. The terminal confirmation is not a privilege boundary against code running as the same Windows user with shell access; that is why the result is a branch you merge (or, only if you opted in to `auto_merge`, one merged behind GitHub CI). A hardware-backed confirmation (Windows Hello, B4-B) stays **disabled** and is not required. Set `ANTIGRAVITY_AUDITOR_APPLY=0` in the MCP server environment to withhold the APPLY tools entirely.

### Optional auto-approval policy (terminal-configured)

If you run the auditor like a server and do not want to confirm every execution, you can opt in to a policy. The agent then calls `auditor_start_execution` with `auto_approve: true` (optionally `run_id`; default: the latest report); the server authorizes the run's APPLY decisions **only if all of them** fall inside the policy, and otherwise refuses with the reasons per finding (the terminal command still works). The policy is off by default and can only be written from an interactive terminal (typed confirmation `POLICY <key>`); no MCP tool can change it.

```powershell
python core\cli.py apply-policy show [--project <key>]          # effective policy (project > '*' > default)
python core\cli.py apply-policy set --project <key|*> --enable `
    --severities LOW,MEDIUM --max-findings 3 --max-per-day 3 --max-changed-files 5 `
    --paths-allow "src/**,tests/**" --paths-deny ".github/**,**/.env*" `
    --categories-deny SECURITY --expires-in-days 30               # or --no-expiry; --disable to switch off
python core\cli.py apply-policy check --project <key> --run-id <run>   # dry run: would it auto-approve?
python core\cli.py apply-policy remove --project <key|*>
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch. |
| `severities` | `LOW, MEDIUM` | Allowed severities (`CRITICAL, HIGH, MEDIUM, LOW, INFO`). |
| `max_findings` | 3 | Max APPLY findings in one auto-approved execution. |
| `max_per_day` | 3 | Max auto-approvals per project in 24 h. |
| `categories_allow` / `categories_deny` | any / none | Finding categories (case-insensitive). |
| `paths_allow` / `paths_deny` | any / `.github/**`, `**/.env*`, `**/*.pem`, `**/*.key`, `**/secrets/**` | Gitignore-like globs on the finding's file (`**` spans folders; a pattern without `/` matches the file name anywhere). |
| `max_changed_files` | 5 | Checked **after** the fix, together with the path rules, against the files actually changed. |
| `expires_at` | none | The policy stops working after this time. |
| `allow_single_model_verification` | `false` | Also auto-approve findings verified without an independent second model (`--allow-single-model` / `--require-cross-model`). |

A project policy replaces the `*` default for that project; a corrupted stored policy counts as disabled. Auto-approvals are recorded as `authorized_by = policy:<key>#<hash>` with a snapshot of the policy and an `EXECUTION_AUTO_AUTHORIZED` event. The delivery is the same local review branch; if the finished fix went beyond the policy (too many files, a denied path) the branch is still created but the result carries `policy_violations` and a `warning`, and an `AUTO_APPLY_POLICY_EXCEEDED` event is written. Independently of the policy, the red-team scope check only lets an execution change the finding's own file and test files.

## Weekly Scheduled Audit (headless, MCP-free delivery)

`python core/cli.py register --path <repo> --key <key> --project-id <antigravity project id>` registers a repository. The weekly Windows task (`schedule install`, see above) then audits every enabled project; for each one it runs:

```powershell
python core\cli.py scheduled-audit --project <key>
```

which drives the whole pipeline without a human: primary audit → second-pass verification of every candidate → evidence gate and finalization (`READY_FOR_REVIEW`). Headless `agy -p` sessions auto-deny MCP tool calls, so these sessions do **not** publish through `auditor_publish_report`; instead the agent answers schema-constrained JSON (`agy --json-schema`, see `core/structured_delivery.py`) and the CLI submits it to the same server-side validation that the MCP tools use. The authoritative payload is agy's `structured_output` from the final `result` event (the plain response text can differ in long sessions). Helper sessions run with `--settings '{"permissions":{"deny":["mcp(*)","command(*)"]}}'`. The primary audit runs three focused passes (900 s each, see Multi-pass primary audit); verification uses a 1800 s timeout per dispatch. A pass whose conversation the backend refuses to open ("empty conversation id") is retried once.

Without the weekly task (older installs) `register` writes an Antigravity Sidecar `<key>-audit` with the builtin `schedule` trigger instead; those Sidecars did not fire reliably, which is why `schedule install` replaces them.

If a weekly run stops in verification (e.g. a retryable dispatch failure), the next `scheduled-audit` resumes that run instead of starting a new one; a job waiting for its retry back-off (up to 300 s) is awaited within the same run. Verification jobs hold a 1200 s lease (longer than one 900 s dispatch), and a worker that crashes releases its job as `RETRYABLE_FAILURE`.

**Provider quota.** When the Google side refuses a dispatch because the model's quota or rate limit ran out (`RESOURCE_EXHAUSTED`, `429`, "quota exceeded", ... in agy's stderr or structured error events), the result is `PROVIDER_QUOTA_EXHAUSTED` instead of a generic failure:
- *verification job*: parked as `RETRYABLE_FAILURE` until the provider's retry hint (or 1 h), **without spending one of its attempts**; the run stays `VERIFICATION_PENDING`, a `VERIFICATION_WAITING_PROVIDER_QUOTA` event is written and the weekly result is `VERIFICATION_WAITING_PROVIDER_QUOTA` with `retry_at`. The next `scheduled-audit` (or `verifier-worker`) continues it.
- *primary audit*: the run is closed as `FAILED` with a `PROVIDER_QUOTA_EXHAUSTED` error that does not count toward the per-commit retry limit; the weekly result is `PRIMARY_WAITING_PROVIDER_QUOTA`.
- No fallback to another model happens and no scarce (Argon) budget is used for a refused call. The auditor's own Argon budget limits are separate: when they are reached the job is `BLOCKED_CONFIGURATION` / `VERIFICATION_BLOCKED` until the budget allows it again and someone runs `recover-verification --action requeue`.

**Token saving: when the weekly audit does not run.** The scheduled run spends no model call when
- the previous report still waits for you (a `READY_FOR_REVIEW` run you have not acted on) -> `SKIPPED_AWAITING_REVIEW`;
- the code has not changed since the last finished audit (same `HEAD` and working tree) -> `SKIPPED_NO_CHANGES`.

Both are normal outcomes (exit code 0). To audit anyway, run `python core\cli.py audit-now --project <key>`: it ignores the no-change skip and replaces a report nobody acted on (that run is archived as `SUPERSEDED_BY_MANUAL_AUDIT`; its open findings are matched again by the new run, unexecuted `APPLY` decisions are dropped, `DISMISS`/`DEFER` decisions live on in the findings). The old report is replaced only once the new audit has passed its preflight, and it is given back (with its `APPLY` decisions) if the new audit fails, e.g. on the provider quota. It refuses while that run has a pending (unexpired) fix approval or a running fix. A verification left unfinished by an earlier week (retry back-off, provider quota) is always resumed first.

**Evidence anomalies.** If the verifier confirms a finding with evidence that fails the deterministic gate (for example a quote that does not exist in the code), only that finding is rejected; the rest of the report is kept. The run records the anomaly (`audit_runs.evidence_anomaly_json`, event `EVIDENCE_ANOMALY_FINDINGS_REJECTED`, an "Evidence Anomaly" section in `review-report.md`), and fixes from that run need a terminal approval (the auto-approval policy refuses it; `authorize-execution` shows a warning). An earlier canonical finding with the same fingerprint is left untouched. No extra verification call is made; use `audit-now` to re-audit. A stale snapshot (the code changed under the audit) still fails the whole run as `VERIFICATION_STALE`.

**Starting an audit from the agent chat.** `auditor_audit_now` (scope `audit:run`, granted to Antigravity) starts exactly `cli.py audit-now` as a separate background process (no console window, log in `logs/audit-now/`) and returns at once; progress is read with `auditor_get_status`. It refuses with a reason and a hint instead of starting when an audit is already running or was just launched (`ALREADY_RUNNING`), when the last report still waits for decisions (`REPORT_WAITING_FOR_REVIEW`; `replace_pending_report: true` replaces it), when the code has not changed since the last finished audit (`NO_CHANGES`; `force: true`), when a fix is running on the project (`FIX_IN_PROGRESS`), when the last audit's verification waits for a retry (`VERIFICATION_PARKED` with the next attempt time; a later call resumes it), or after 3 chat-started audits for the project in 24 h (`DAILY_LIMIT_REACHED`; the terminal command is not limited). Every audit process (chat, terminal, weekly task) holds the project's lock file, so the chat never starts a second audit next to a running one. A start that fails before a run exists is recorded as `AUDIT_START_FAILED`; `auditor_get_status` shows the latest chat-started audit's log (`latest_audit_log`). The audit itself is read-only like every audit; the guards only protect the model quota.

**Run lifecycle and the project lock.** A project has at most one active audit run; while a run is active a new audit is not started. A `READY_FOR_REVIEW` run is active until nothing is left to review:
- a run whose report has no open finding (clean week, everything rejected or suppressed) is `COMPLETED` right after finalization;
- once every finding has a non-`APPLY` decision (`DISMISS`, `DEFER`, `SKIP`) the run is `COMPLETED`; an `APPLY` decision keeps it open until the execution finishes; a fix that leaves undecided findings ends the run as `PARTIAL` (still reviewable, does not block new audits); revising decisions later reopens it as long as no newer audit run exists;
- `recover-verification --action archive-run` still closes a run manually.

Other failures never leave the weekly task with a bare traceback: a missing `agy`, a signed-out Antigravity, a moved repository, the disk guard or a locked database end with `PRIMARY_FAILED` and the reason (exit code 2). `integrity-check` reports a damaged database (`DATABASE_CORRUPT`, the latest backups and restore advice) instead of crashing.

**Executions.** Every MCP execution step records activity; an execution is recovered as `STALE` only after 6 h without a step. A stale execution cannot be resumed: its unfinished diff is saved to `quarantine/stale-executions/<exec_id>.patch` and its worktree (only an auditor-created linked worktree under `worktrees/`) is removed; authorize again to retry.

**Secrets in reports.** Evidence quotes audited code, so `findings.json`, `review-report.md` and the in-repo `manual-verification-prompt.md` are scrubbed of secret-shaped values (known key prefixes, private key blocks, credentials in URLs and `Authorization` headers, quoted or long literal values of secret-named variables); ordinary prose is left intact. `auditor.db` keeps the exact excerpts because the evidence gate compares them byte for byte. The auditor adds `/.antigravity-audit/` to the repository's local `.git/info/exclude`, so its working files never end up in `git add -A`.

The weekly task keeps the model catalogue current (`models sync --probe --research-new --propose`: new models are noticed and probed, uncovered model lines are researched, the models are measured within the quota limits, and a proposal is created and, when its gates pass, activated automatically; the agent tells you in the chat). Legacy: `models schedule --project <key>` still creates the old `auditor-models-sync` Sidecar and `models schedule --remove` deletes it; do not use it together with the weekly task. The installer creates no Sidecars.

## Requirements & Tests

- Windows 10/11, Python 3.11+ (standard library only at runtime; `tomllib`), Git, Antigravity with the `agy` CLI for dispatch.
- `pip install -r requirements-dev.txt` then `python -m pytest -q`.
- `tests/test_b4*.py` (Windows Hello / CNG / TPM key custody, ACL changes, some need elevation) are **excluded by default** (`tests/conftest.py`); run them deliberately with `AUDITOR_RUN_B4_TESTS=1` on a disposable machine only.
- `tests/test_mcp_protocol_wire_resilience.py` needs the official MCP SDK (`mcp==2.3.0`) and is skipped without it; CI runs it in an isolated venv. `tests/test_installer_preflight.ps1` covers installer preflight, file locks and rollback (18 cases).
- CI: `.github/workflows/ci.yml` (Windows, Python 3.13).
- Evidence gate bounds: a cited range may span at most 200 lines, and an excerpt must be at least 12 characters or a complete source line of the range.

## Commands

### Verification Worker, Manual Prompts & Quality Metrics

```powershell
# Inspect verification worker, queue, and Sidecar enablement status
python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" verifier-status --project myproj

# Generate a context-independent manual verification prompt for a fresh conversation
python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" generate-verification-prompt `
  --run-id <RUN_ID> `
  --output .\verification-prompt.md

# Run the read-only verifier worker (once or persistent loop)
python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" verifier-worker --project myproj --once

# Enable or disable the persistent verifier Sidecar for a registered project
python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" enable-verifier-sidecar --project myproj
python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" disable-verifier-sidecar --project myproj

# Recover a BLOCKED_CONFIGURATION, DISPATCH_UNCERTAIN, or RETRYABLE_FAILURE verification job
python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" recover-verification `
  --project myproj `
  --run-id <RUN_ID> `
  --action requeue

# Inspect historical two-pass audit quality metrics
python "$env:LOCALAPPDATA\AntigravityAuditor\core\cli.py" quality-report --project myproj
```

## Installer Preflight & Concurrency Safety Guarantees

`Install-AntigravityAuditor.ps1` executes an isolated preflight verification step (`Test-AuditorProcessPreflight`) before creating, replacing, migrating, or backing up runtime files or installing skills:

1. **Active Process Inspection:** Queries active system processes using CIM/WMI to detect running Auditor verifier-workers, MCP servers, and Sidecars referencing the target installation root or carrying Auditor identity tokens. Unrelated third-party processes (e.g. `core/mcp_server.py` or `core/cli.py` in other projects) are ignored.
2. **Database File Handle Inspection (`FileShare.None`):** Verifies that `auditor.db`, `auditor.db-wal`, and `auditor.db-shm` are not locked by incompatible open file handles at preflight time.
3. **SQLite Byte-Range Lock Limitation:** `FileShare.None` checks incompatible open file handles at preflight time; it does not directly inspect every SQLite byte-range lock (`LockFileEx`).
4. **Point-in-Time Check:** The preflight check is point-in-time and cannot prevent a new process from starting after preflight. Relevant Auditor processes must remain stopped throughout installation.
5. **No Automatic Process Termination:** The installer never terminates running processes automatically. Detected conflicts are reported with PID, process name, and command line before safely aborting with zero filesystem modifications.

## License

MIT. See [LICENSE](LICENSE).
