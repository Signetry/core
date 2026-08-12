# ADR-0001 — The hosted receipt payload extends the kernel receipt format

- **Status:** Accepted
- **Date:** 2026-07-29
- **Deciders:** platform maintainers
- **Applies to:** `umbra-core` (kernel receipt format) and the hosted `umbra`
  backend (`backend/receipt.py`)

## Context

`umbra-core` defines the canonical **Remediation Receipt**: a signed
(`Ed25519`), canonicalized record of one governed change — kind
`umbra.remediation-receipt`. The hosted platform (`umbra` / umbra.engineer)
produces receipts for the same purpose but through an app-specific pipeline that
knows about things the kernel deliberately does not: OSV advisories and the Codex
CLI configuration that ran.

As of 2026-07 the hosted backend **single-sources its signing crypto from the
kernel** (canonical hashing, Ed25519 sign/verify, key derivation from
`UMBRA_SIGNING_KEY`) — see `backend/receipt.py`. What is *not* shared is the
**receipt payload assembly** (`build_receipt`). The two payloads differ:

| Field | Kernel | Hosted | Meaning |
|---|:---:|:---:|---|
| `kind`, `version`, `repo`, `base_commit`, `executor`, `policy_hash`, `contract`, `contract_result`, `trust_boundary`, `verifier`, `checks`, `baseline_checks`, `check_diagnosis`, `model_identity`, `context_manifest`, `proposed_change`, `provider_ledger`, `diff_hash`, `authority_level`, `authority`, `outcome`, `auto_merge`, `human_review_required` | ✅ | ✅ | shared core |
| `advisory_hash` | — | ✅ | hash of the OSV advisory the hosted remediation cleared |
| `codex_config` | — | ✅ | the Codex CLI config hash when a live Codex run produced the change |
| `plan_capability_set`, `plan_adherence` | ✅ | — | the v0.3.0 CaMeL/DRIFT plan binding (kernel pipeline only) |

Both are signed identically and both verify against the same pinned public key.

## Decision

**The hosted receipt payload is an intentional, sanctioned *extension* of the
kernel format, not a fork to be reconciled.** We do **not** unify the two payload
assemblers.

- The hosted backend keeps `build_receipt` local so it can bind app-specific
  evidence (`advisory_hash`, `codex_config`).
- The kernel keeps its `build_receipt` free of app concerns (an editor/CI
  integration has no OSV advisory or Codex config to bind).
- Both remain `kind: "umbra.remediation-receipt"` and are verified by the same
  `verify_receipt` / pinned-key check.

## Why not unify

Unifying the payload was evaluated and **rejected** because it is a breaking
change with no governance benefit:

1. **It changes signed receipt hashes on the live site.** The canonical hash is
   computed over the exact payload; adding/removing fields changes every new
   receipt's `canonical_hash` and signature. Previously-issued receipts still
   verify (same key), but the format would shift under consumers with no upside.
2. **The kernel must stay app-agnostic.** Pushing `advisory_hash` / `codex_config`
   into the kernel would leak hosted-specific concepts into the component every
   integration depends on — the opposite of a clean kernel.
3. **Dropping the app fields loses real evidence.** `advisory_hash` binds the CVE
   the change cleared; `codex_config` attests which Codex ran. Removing them to
   match the kernel would weaken the hosted receipt's accountability.

## Consequences

- **No code or behavior change** results from this ADR; it records an existing,
  deliberate arrangement so it is not mistaken for architectural drift.
- **Consumers** can rely on the shared core fields across both producers. Fields
  outside the shared set are producer-specific and namespaced by presence
  (`advisory_hash`/`codex_config` ⇒ hosted; `plan_capability_set` ⇒ kernel).
- **Invariant preserved everywhere:** `auto_merge` is always false; the signature
  covers the whole payload; the key is single-sourced.
- **Future option (non-breaking):** if a shared richer format is ever wanted, the
  kernel `build_receipt` could gain *optional* `advisory_hash` / `codex_config`
  params (defaulting to absent), letting the hosted backend delegate the whole
  payload while keeping byte-identical output. That is a kernel feature + release,
  not a hosted-only change, and is out of scope here.

## References

- `umbra_core/pipeline/receipt.py` — kernel `build_receipt` / `verify_receipt`.
- Hosted `backend/receipt.py` — app payload assembly + the delegation note.
- [`umbra-umbrella` ARCHITECTURE](https://github.com/Signetry/signetry/blob/main/ARCHITECTURE.md) — platform overview.
