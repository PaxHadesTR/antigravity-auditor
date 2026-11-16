---
name: prompt-co-architect
description: Refines raw user requests into engineering specifications using the V1-V7 matrix and interactive trade-off questions. Use for new features, refactors, schema changes, and project bootstrapping; do not invoke during routine scheduled audits.
---
# Collaborative Prompt Co-Architect Protocol
1. Scan relevant modules and existing invariants (`./DECISIONS.md`, `./ASSUMPTIONS.md` if present) across V1-V7, observability, and UI/UX state requirements.
2. For genuinely ambiguous feature work, formulate 2 to 4 high-leverage questions with `[MİMARİ KARAR X]` headers and `(Recommended) Seçenek A` first.
3. Synthesize a structured `DRAFT_MASTER_PROMPT` covering Goal & Scope, Target Modules, mandatory V1-V7 invariants, and dual-path acceptance criteria.
4. Wait for explicit approval before locking `FINALIZED_MASTER_PROMPT` and starting implementation.
5. Do not manufacture clarification questions for deterministic maintenance, scheduled audits, or tasks whose scope is already approved.
