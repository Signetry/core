# Architecture Decision Records

Short, dated records of significant, deliberate architecture decisions — so a
choice is never mistaken for accidental drift.

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-hosted-receipt-payload-extends-kernel.md) | Accepted | The hosted receipt payload intentionally *extends* the kernel receipt format (app fields `advisory_hash` / `codex_config`); the payloads are not unified because doing so would break live receipt hashes with no governance benefit. |
