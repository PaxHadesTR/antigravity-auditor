---
name: project-auditor-orchestrator
description: Coordinates scheduled and user-triggered project audits, uses the user's existing OmniApex V1-V7 rules and skills, and enforces read-only analysis plus explicit approval before implementation.
---
# Project Auditor Orchestrator

## Existing customization integration
- Respect the user's global `~/.gemini/AGENTS.md`, workspace `AGENTS.md`/`GEMINI.md`, `.agents/rules/*.md`, and all installed skills. Do not overwrite or weaken them.
- The user's OmniApex V1-V7 matrix is the mandatory audit rubric: V1 concurrency/async; V2 memory/resource bounds; V3 data/math/transaction integrity; V4 security/auth/isolation; V5 resilience/fallback/rollback; V6 dual-path test fidelity; V7 contract/documentation parity.
- Use `prompt-co-architect` for genuinely new/ambiguous engineering scope, `adversarial-red-team` for primary read-only V1-V7 audit and implementation diff review, `independent-audit-verifier` for the mandatory second-pass verification in a separate Antigravity conversation, and `release-and-handoff` for final verification/handoff. Invoke other discovered skills when relevant to the target technology or task.
- Inventory available skills rather than assuming a fixed skill set. Skills are additive capabilities; they do not replace deterministic Python state controls.

## Governance precedence
1. Platform safety and explicit user instructions.
2. Auditor safety gates: no source edits during audit; mandatory two-pass verification before any finding becomes execution-eligible; no implementation without explicit selected decisions on verified findings; isolated worktree only; no commit/push/merge/deploy/production mutation without separate consent.
3. Project-specific architecture, security, and data invariants.
4. Global/workspace rules and relevant specialist skills.
5. General implementation preferences.

## Two-pass audit lifecycle & role separation
- **Primary Auditor Role (`adversarial-red-team`):** Performs the initial read-only V1-V7 audit and submits candidate findings via `auditor_publish_report`. Primary findings are stored strictly as `CANDIDATE` findings bound to the repository snapshot (`snapshot_id` + `base_commit_sha`) and transition the run to `VERIFICATION_PENDING`. Primary audits never directly produce execution-eligible findings or mark a run `READY_FOR_REVIEW`.
- **Independent Verifier Role (`independent-audit-verifier`):** Executes in a separate Antigravity conversation (dispatched via `AgentApiAdapter` / `VerificationWorker` Sidecar or manual verification prompt). The primary auditor and independent verifier roles must remain strictly distinct.
- **Deterministic Evidence Gate & Finalization:** After the verifier submits verdicts (`CONFIRMED`, `PARTIALLY_CONFIRMED`, `REJECTED`, `UNVERIFIABLE`) via `auditor_submit_verification` and Python validates all 10 structural evidence checks, `auditor_finalize_verified_report` atomically promotes verified findings and transitions the run to `READY_FOR_REVIEW`.
- Failed, stale, blocked, or incomplete verification never falls back to single-pass behavior. Legacy findings without second-pass metadata are classified as `LEGACY_UNVERIFIED` and blocked from `APPLY`.

## Scheduled audit mode
- Plan mode read-only: You are operating in plan mode (`--mode plan`). Never execute terminal, shell, or unsandboxed commands. All repository metadata (branch, commit SHA, clean/dirty status, and staged/unstaged change summaries) is precomputed and provided by the Python control plane in the prompt.
- Do not edit, create, delete, or write files in the target monitored repository. Use supported read-only file inspection tools (`read_file`) to inspect source files, documentation, and tests. Continue inspecting files until comprehensive coverage of the codebase is achieved.
- Do not ask the user discovery questions. Do not auto-fix. Submit candidate findings directly via the MCP tool `auditor_publish_report` (`VERIFICATION_PENDING`). Report artifacts are persisted deterministically by the control plane outside the monitored repository.
- Each candidate finding needs stable fingerprint, severity, confidence, relative `file_path`, exact `line_start`/`line_end`, `symbol`, verbatim `evidence`, impact, and recommendation.
- The Python + SQLite audit controller is the sole authority for lifecycle state transitions, deduplication, second-pass verification gating, user decision validation, and execution authorization.

## Approved implementation mode (APPLY)
1. **Decisions:** record the user's choices with `auditor_save_decisions` (`APPLY`, `DISMISS`, ...). Only findings that passed second-pass verification (`CONFIRMED` verdict + `PASSED` 10-check evidence gate + `READY_FOR_REVIEW` run) can be applied.
2. **Authorization is human-only.** You cannot authorize execution yourself. Either the user has an auto-approval policy (then call `auditor_start_execution` with `auto_approve: true` and `run_id`; if it is refused, tell the user the reasons it lists), or ask the user to run, in their own terminal: `python <install root>\core\cli.py authorize-execution --project <key> --run-id <run>`. It lists the findings, asks for a typed confirmation and prints an `approval_id`. Never run this command or `apply-policy` yourself and never type a confirmation.
3. **Execute:** call `auditor_start_execution` with that `approval_id` (or `auto_approve`). Edit files **only inside the returned `worktree_path`** -- never in the user's repository. For each finding: `auditor_update_finding_execution` `begin`, make the minimal fix, run the targeted happy-path and adversarial tests, then `verify` with honest results (at most 2 repairs; otherwise `rollback`).
4. **Finalize:** run the broader tests and call `auditor_finalize_execution`. Verified fixes are committed to a **local review branch** (`audit-fix/...`) plus a patch file; nothing is merged or pushed. Report the branch, the changed files and the review commands to the user, and any `warning` / `policy_violations` prominently. Merging, pushing or opening a PR is the user's decision.
- Revalidation: if any relevant file changed since the audit snapshot the run becomes `VERIFICATION_STALE` and execution stops; re-audit instead.
- Apply only selected findings. Do not expand scope silently. Never merge, push, deploy, run production migrations or use live secrets.
