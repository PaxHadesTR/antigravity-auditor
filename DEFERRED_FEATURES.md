# Deferred Features — Antigravity Auditor Final Delivery Scope Freeze

Recorded per **Scope Freeze** decision: prioritize stable daily read-only Antigravity MCP usage and defer non-essential security/platform/client expansions cleanly without deleting existing `B4B-GOV` or `B4B-CNG` code.

## Deferred Items

| Item | Historical Status / Baseline | Reason Deferred |
| --- | --- | --- |
| Windows Hello / WebAuthn physical user-presence confirmation (`B4-B` interactive CBEAT / `TCB`) | `PARTIAL` (`6f260aa`), **disabled** | Not every machine has Hello set up. APPLY works without it (terminal authorization + local review branch, see README); Hello remains an optional future hard boundary. B4 tests are excluded by default. |
| Production Windows Service SCM & Session-0 Named Pipe broker cutover (`B4-C`) | Not started | Direct local stdio (`CommonStdioAdapterHost` + `InMemoryBrokerTransport` + `AdaptiveMCPGateway`) runs cleanly as an Antigravity child process without requiring a Session-0 daemon or SCM installation (`DisabledProductionNamedPipeTransport` remains fail-closed). |
| Retirement of 31 legacy direct SQLite callsites in `core/` | Inventory recorded in B4-B/B4-A1 | Non-blocking for read-only MCP stdio operation; broker DB adapter (`core/broker/db_adapter.py`) continues to enforce production DB isolation (`auditor.db`). |
| Extended TPM/CNG hardware key attestation, External Audit Anchoring, WORM storage, and TPM PCR sealing | `B4B-CNG` preserved | Hardware custody primitives remain intact in `core/broker/cng.py`, but production PCR/WORM external anchoring is out of scope for v1 read-only delivery. |
| Multi-client live activation (`Claude Desktop`, `Claude Code`, `Codex`) | Adapter profiles & offline previews in `NEXT-22D` | First live pilot target is strictly **Antigravity**; sibling client live activations remain deferred. |
| Hardware-backed approval of routing tables | TTY + typed confirmation (`cli.py models proposal approve`) | Stops headless agents, MCP tools and scheduled tasks but not same-user code with shell access; reuse the B4-B Windows Hello / TCB confirmation once it is qualified. |
| Dynamic routing for other hosts/backends (`claude_code`, `claude_desktop`, `codex`; `vibe`) | Extension points: `HARD_POLICIES` per (host, backend), backend-qualified model refs, `discover_dispatch_backends()` | Antigravity + agy only for now (user decision 2026-11-15); each new pair needs an explicit policy entry, catalogue sync and dispatch adapter. |
| Entitlement Router account/routing MCP tools live activation & SDK v2.3.0 (`mcp` package) Modern protocol runtime | Optional bridge in `NEXT-22E` (`sdk_v2_compat.py`) | System Python (`C:\Python315\python.exe`) runs `CommonStdioAdapterHost` cleanly with zero external SDK dependencies over MCP legacy/2025-11-25 stdio; `ROUTING_READ`/`PLANNING` remain unbound/denied unless account allowlists are explicitly configured. |

## Resolved After Cutover

Findings from the independent architecture & readiness review of `80ed28d` (2026-11-14) that have been fixed. Regression tests: `tests/test_arch02_arch06_fixes.py`.

| ID | Finding | Fix |
| --- | --- | --- |
| `ARCH-02` | `auditor_get_status` (`CORE_READ`, reachable by `UNKNOWN` callers) called `detect_moved_repositories`, which could update `projects`, insert `audit_events` and append to `audit-events.jsonl`. | `detect_moved_repositories(..., persist=False)`; the status tool reports live health without any write. CLI/executor recovery paths keep the persisting default. |
| `ARCH-09` (main impact) | Any result whose pretty JSON exceeded the tool's text limit collapsed to `{"tool": ..., "truncated": true}` in `content`. Antigravity reads only `content`, so on a real project `auditor_get_status`, `auditor_get_context` and `auditor_list_findings` showed no data. `auditor_list_findings` also fetched up to 500 rows that the gateway then cut to 50 silently. | Progressive text view with an explicit `text_view` omission report (`output_adapter.py`); `auditor_list_findings` gained `limit`/`offset`/`next_offset` paging. Tests: `tests/test_text_view_and_paging.py`. |
| Attestation (found 2026-11-15) | The static name map resolved agy's shared internal id `gemini-3.8-flash-n` before the display name, so every Flash record (Low/Medium/High) was attested as Flash High, and unknown internal ids (e.g. `gemini-4-argon-trial`) relied on the display-name fallback. | Model identity is resolved from the effort-qualified display name with an internal-id model-line consistency check (`model_registry.resolve_observed_model`). Tests: `tests/test_model_registry.py`. |
| `ARCH-06` | The 15 s request budget was checked after the synchronous call finished and replaced a completed (possibly committed) response with `REQUEST_TIMEOUT_EXCEEDED`, inviting duplicate publishes on retry. | The budget is diagnostic only: slow requests are logged to stderr (`Slow request ...`) and the real result is returned. |

## Resolved in the Full-Project Review (2026-11-15)

APPLY is enabled without Windows Hello (2026-11-15): decisions and execution tools for verified Antigravity, human-only terminal authorization, delivery as a local review branch + patch (nothing merged or pushed). This also resolves `ARCH-08`: `auditor_start_execution` takes the `approval_id`, so the redacted token never has to pass through MCP.

Also resolved: `ARCH-01` (the stdio scope set is now `ANTIGRAVITY_STDIO_AUDIT_LIFECYCLE_SCOPES`; the old name is a deprecated alias) and the rest of `ARCH-09` (`auditor_get_verification_context` and `auditor_get_status` events are paged).

Regression tests: `tests/test_review_fixes_2026_11.py`, installer test 18 in `tests/test_installer_preflight.ps1`.

| Area | Fix |
| --- | --- |
| Secret redaction | JSON/quoted keys (`"password": "..."`) are now redacted by `redact_text` / `contains_secret_or_pii`. |
| Model dispatch | Task types are persisted by value (not `TaskType.X`); an explicit `model_id` can no longer bypass routing gates (blocked tasks stay blocked, scarce models need a scarce tier); scarce-model reservations are released even if dispatch raises; reservations are tracked per reservation id. |
| Budgets | `daily_token_budget` is enforced on the SQLite path; scarce models are identified by the hard policy, not the substring "argon"; reservation leases (1800 s) outlive the 900 s verification timeout; byte-safe evidence truncation; malformed token counts no longer crash stream parsing. |
| Attestation | Every generation record of the conversation must resolve to one model; conversation ids are compared stripped; the conversation DB connection is always closed. |
| Routing | `CATASTROPHIC` requires a critical verification / red-team task or operator escalation, like `CRITICAL`. |
| SQLite | `with connect(...)` now closes the connection (Windows WAL/SHM handles were held until GC); legacy CHECK-constraint rebuilds carry known post-v3 columns instead of aborting. |
| State machine | `recover_stale_runs` really reconciles interrupted worktree ops (was a swallowed `TypeError`) and recovers `VERIFICATION_DISPATCHING`; follow-up verification keeps a `READY_FOR_REVIEW` run reviewable instead of an illegal transition; `unresolved_count` counts unresolved candidates. |
| Executor (APPLY/RUN, disabled) | Non-JSON approval tokens are refused (was fail-open); broker rollbacks call `restore_checkpoint(checkpoint_id, exec_id, worktree_path)`; test files are detected by convention, not by any name containing "test"; `red_team_passed` no longer depends on the adversarial test. |
| MCP / CLI | `findings_file` is limited to `.json` files inside the project repository or the reports folder; report directories must stay inside `reports/`; UNTRUSTED/UNKNOWN integrity levels are rejected in every identity layer; non-object `tools/call` arguments and bad pagination params return `-32602`; oversized stdio frames no longer desynchronise the stream; expired adapter challenges are pruned; `register` reports a partial Sidecar registration explicitly. |
| Broker (not wired in) | Reparse-point checks cover every path component (checkpoints) and paths outside `stop_at`; SIDs are validated before SDDL interpolation; `RevertToSelf` failure is fatal; protected-directory ACL guard covers `%WINDIR%` subtrees; DB paths are always resolved; `close()` closes every thread's connection; request-id replay protection is per client and bounded. |
| Installer & tests | Rollback restores `mcp_config.json`, `config.json` and the Sidecars folder; quoted/unquoted root arguments are parsed in preflight; a skills directory created by the installer is removed on rollback; tests use a throw-away `ANTIGRAVITY_AUDITOR_HOME`; the NEXT-22A evidence test is opt-in via `AUDITOR_NEXT22A_EVIDENCE`. |

A second review round (cross-review of the fixes plus previously uncovered areas) is resolved as well: weekly `scheduled-audit` resume/retry, verification worker lease length and crash release, stale-run queue cleanup, evidence-gate lexer and symbol matching for shell/TOML/YAML/JS/TS/C#/Rust/Go/Java, minimum excerpt and maximum range, broker approval verification and consumption before any worktree, repair-gate status, unknown integrity levels failing closed, scarce-budget accounting for dispatches that never ran, explicit-model tier escalation, standard JSON Schema on the wire (`nullable` → type unions; found by the MCP SDK wire tests, now in CI), bounded legacy reads and gateway session maps, skill hashing, telemetry token counts, strict policy booleans, and repository fingerprints without commits. Installs to a custom root now warn about Auditor processes whose root is not visible on their command line.

## Resolved 2026-11-18 / 2026-11-19

| Area | Change |
| --- | --- |
| Approval | Per-project approval mode: `simple` (default, the user's yes in the agent chat, `chat_approved`) or `strict` (terminal `approve`, 24 h); `run_id` defaults to the latest report everywhere. |
| Delivery | One commit per verified finding; the auditor runs the project's tests itself (`review.tests`, private pytest `--basetemp`); optional `auto_merge` (push, PR, GitHub CI, merge commit, local fast-forward) with fixed gates; `.github/` changes are never auto-merged. |
| CI | Deterministic `CI-MISSING-001` finding for GitHub repositories without CI. |
| Chat | `auditor_audit_now` starts an audit from the chat (quota guards, daily limit, process lock shared with terminal and weekly audits). |
| Depth | Multi-pass primary audit (three focused passes, merged before verification). |
| Scheduling | The Antigravity Sidecars never fired; replaced by one Windows scheduled task (`schedule install`, installer switch `-InstallWeeklyTask`) running the model catalogue sync and the audits. Installer-managed scheduling is no longer deferred (opt-in). |
| Models | Fully automatic model routing: published benchmark results (Artificial Analysis Intelligence Index per effort, security benchmarks) collected by web research and verified on their pages decide the table; a two-call gate on `bench_v1` (FIND/VERIFY) sets accuracy floors and measures tokens per call (new models only, quota-aware via `agy /usage`); the evidence engine picks the cheapest of the strongest models per tier; automatic approval is on by default (`models auto-approve off` opts out); notices reach the user through `auditor_get_status` and the agent; `models restore` undoes a change; `models proposal create` stores a manual proposal. |
| MCP flow | `PARTIAL` keeps undecided findings decidable; no audit while a fix runs; parked verification is reported and resumed; failed starts are recorded; caches never enter a fix. |

## Known Open Review Findings

| ID | Severity | Summary | Impact on daily audit-only use |
| --- | --- | --- | --- |
| `ARCH-03` | Medium (design; B4-B scope) | `stdio_entry.py` self-signs the adapter challenge with `EphemeralTestCredentialProvider`; the effective trust boundary is the OS ancestor-chain check only. | None for single-user Medium-IL stdio. |
| `ARCH-04` | Medium (multi-platform scope) | Two model-routing stacks: `model_policy.py` + `model_registry.py` (tiered, table-driven, the only path that dispatches) vs the advisory `entitlement_router/`; `auditor_routing_*` tools are unbound. Deliberately not merged in the dynamic-routing Phase 0. | None. |
| `ARCH-05` | Medium (B4-C scope) | `core/broker/*` (~4.8k lines) is merged but bypassed (`broker_client=None`); 31+ direct `sqlite3` callsites remain. | None; tracked under B4-C above. |
| `ARCH-10` | Info | The V2 Sandbox line (PR #4) is archived (branch `archive/v2-sandbox-pr4`); its migrations `005`/`006` collide with the live `005`–`010` and may only be integrated as `011+`. | None. |
