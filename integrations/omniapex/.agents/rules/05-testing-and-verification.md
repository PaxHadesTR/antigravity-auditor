---
description: Unit, integration, and E2E testing rules
trigger: glob
globs: ["**/test*/**", "**/*test*.*", "**/*spec*.*"]
---
- **Dual-Path Adversarial Coverage (V6):** Verify both the primary execution path and adversarial/failure paths, including boundaries, unauthorized access, concurrent requests, and clean rollback.
- **Zero-Pollution Test Isolation:** Tests must never permanently alter live databases, configuration files, or user state. Use isolated test databases, transactions, or reliable snapshot restoration.
