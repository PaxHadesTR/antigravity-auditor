---
description: SQL, ORM models, database schemas, and migration rules
trigger: glob
globs: ["**/*.sql", "**/models*.py", "**/schemas*.py", "**/crud*.py", "**/prisma/**", "**/migrations/**", "**/alembic/**"]
---
- **Race-Safe Accounting & Quotas (V1/V3):** Guard balances, inventory, seat limits, and voting thresholds against concurrent double-spending or double-voting using atomic conditional updates, row-level locks, or uniqueness constraints.
- **Backward-Compatible Migrations:** Design schema changes and auto-migrations safely with sensible defaults so existing databases upgrade without data loss.
- **Query Hygiene:** Prevent N+1 query bottlenecks via appropriate eager loading and index foreign keys and high-frequency filter columns.
