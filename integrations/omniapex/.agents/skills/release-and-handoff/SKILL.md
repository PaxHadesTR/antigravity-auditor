---
name: release-and-handoff
description: Runs final regression and static analysis, synchronizes project documentation, presents a self-audit ledger, and prepares topology-aware Conventional Commit commands.
---
# Release, Documentation Sync & Git Handoff
1. Run relevant targeted tests during development and the full regression suite before final signoff.
2. Synchronize `DASHBOARD.md`, `DECISIONS.md`, and `ASSUMPTIONS.md` only when they exist or are explicitly required; keep their established language and project conventions. Preserve README and security-document language.
3. Present a Self-Audit Ledger and a concise Big Picture summary. A technical verification quiz is optional and should not block automated report publication.
4. Detect Git topology and provide ready-to-copy Conventional Commit commands, submodules first and root repository last.
5. Never commit, push, merge, deploy, or release without separate explicit user approval.
