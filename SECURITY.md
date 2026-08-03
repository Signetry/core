# Security Policy

umbra-core is a security tool, so we hold its own security to a high bar.

## Supported versions

Fixes land on the latest tagged release of the
[source repo](https://github.com/bkd-dotcom/umbra-core/releases) (umbra-core is
source-available and installed from source — not published to PyPI). Always run the
latest.

| Version | Supported |
|---|---|
| `>= 0.5.0` | ✅ (current — detection engine, `--fix` fusion, BYOK secret redaction) |
| `0.1.3`–`0.4.x` | ✅ governance core; upgrade for the detection engine + BYOK hardening |
| `0.1.0`–`0.1.2` | ⚠️ superseded — upgrade to the latest |

`0.1.0`–`0.1.2` contain issues fixed in later releases (path-matching bypasses,
dev-key verification trust, and — in the companion GitHub Action `< v0.1.3` — a
workflow script-injection sink). `0.5.1+` adds bring-your-own-key credential
redaction for `--fix`. Pin the Action to `@v1` (which moves forward) or
`@v0.1.3+`, and install `umbra-core` from source at `@v0.5.3` or later
(`pip install "umbra-core @ git+https://github.com/bkd-dotcom/umbra-core@v0.5.4"`).

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use GitHub's private vulnerability reporting:
**https://github.com/bkd-dotcom/umbra-core/security/advisories/new**

Include, where possible: affected version, a minimal reproduction (a crafted
`.umbra/admission.yaml`, repo layout, or receipt), the impact (e.g. scope bypass,
authority escalation, receipt forgery, secret exposure), and any suggested fix.
We aim to acknowledge within a few days and to fix confirmed issues promptly, then
credit reporters who wish to be named.

## Threat model & honest scope

Read this before relying on umbra-core for a security guarantee.

- **What it enforces.** An executable contract (allowed/forbidden paths, diff
  budget, required checks) evaluated *outside the model* and fail-closed; an
  independent verifier the patch-writer can't self-approve; earned authority
  (0/1/2) that is a result of evidence; and an Ed25519-signed receipt.
- **Prompt injection is *mitigated*, not solved.** Detection is layered
  (imperative patterns over normalized text + structural carriers + optional
  semantic classifier) with full-file quarantine when a hidden/encoded carrier is
  found. No detector defeats all injection — the durable protection is the
  architecture (on-disk quarantine + contract + verifier + authority cap), which
  bounds a change even if every detection layer misses.
- **Check isolation is best-effort by platform.** Checks run under the strongest
  tier that *preflights* — `sandboxed` (Linux bubblewrap), `network-isolated`
  (`unshare -rn`), or `host-restricted` (allowlist + secret-stripped env only).
  The achieved tier is recorded truthfully in every receipt. A code-executing
  check that runs un-sandboxed caps authority at L1; set
  `UMBRA_REQUIRE_SANDBOX=true` to fail closed instead.
- **Receipt trust requires a real key.** With no `UMBRA_SIGNING_KEY`, signing uses
  a deterministic **dev-fallback key whose seed is public in the source tree** —
  such a receipt proves nothing to a third party and is flagged `key_ephemeral`.
  `verify_receipt` refuses the dev key unless an explicit `expected_public_key` is
  pinned. **Set a production `UMBRA_SIGNING_KEY` and publish/pin its public key.**
- **Not a replacement for code review.** umbra-core is the governance layer
  between the agent and the human; a human still merges. `auto_merge` is always
  false.

### Detection scan + governed auto-fix (`umbra scan` / `umbra scan --fix`)

`umbra scan` is a read-only static analysis over the source (deterministic AST +
regex; optional Semgrep/tree-sitter/LLM-triage layers). It performs **no code
execution** on the scanned repo, needs no credentials by default, and runs offline.
The optional LLM-triage layer is *advisory only*: it can drop or annotate findings,
never add or strengthen one.

`umbra scan --fix` is the only path that runs a **live agent** (Codex / Claude
Code / …) with a **real API key** against repository code, so it has the largest
attack surface. Its safety rests on three properties, all enforced by the mechanism:

- **Bring-your-own-key, isolated.** The executor credential is read from the
  caller's own environment (a repo secret in CI). It is scoped to the drafting step,
  never written to git, never passed to `git push`/merge, and never shared with any
  other run or repo. Umbra redacts credential shapes from the diff, the receipt, and
  every artifact before serialising, and the CI workflow additionally masks the
  value and **fails closed** if any credential shape appears in the output.
- **Disposable, credential-free drafting checkout.** The agent edits a throwaway
  checkout that has no push/merge credentials and no access to your other secrets
  (required-check subprocesses get an *allowlist* env — API keys can't reach them by
  construction). Because the checkout is disposable and cannot push, the agent's
  filesystem sandbox is defense-in-depth, not the boundary; on a CI runner where the
  OS sandbox can't initialise you may set `UMBRA_CODEX_SANDBOX=danger-full-access`
  for drafting *only* — the real containment is the disposable checkout plus the
  admission pipeline that governs the result.
- **The draft earns authority from evidence, not from the agent.** Whatever the
  agent produces is run through the same contract → trust-boundary → required-checks
  → independent-verifier pipeline. A fix that touches a forbidden path, introduces a
  secret, fails a required check, or correlates with a quarantined injection is
  capped at ≤ L1 and never becomes a PR. Only L2 opens a **branch-only** PR; a human
  merges. `auto_merge` is always false.

**Trusting the scanned repo.** Treat `--fix` like running a coding agent on that
code: only point it at repositories you're willing to have an agent read. The
untrusted-instruction quarantine reduces prompt-injection-via-repo-text, but a
sufficiently adversarial repo is out of scope — scan such repos read-only
(`umbra scan`, no `--fix`).

## Hardening recommendations for operators

- Set a managed `UMBRA_SIGNING_KEY` (base64 of ≥32 random bytes) and pin its
  public key in whatever verifies receipts.
- Run checks on Linux with bubblewrap available (the Action installs it) so the
  tier is `sandboxed`; use `UMBRA_REQUIRE_SANDBOX=true` for fail-closed CI.
- Own and version your `.umbra/admission.yaml` (`policy_owner` / `policy_version`).
- Make the admission status check **required** in branch protection, and enable
  it for administrators too, so nothing merges without a receipt.

### Running `--fix` safely (live agent + real key)

- **Scope the credential to its own repo.** Put the executor key in the target
  repo's Actions secrets (or org secret you control), never a shared/global one; a
  scan of repo A must never use repo B's key. See `docs/AUTOFIX_SETUP.md`.
- **Least-privilege token.** The workflow needs only `contents: write` +
  `pull-requests: write` to open branch-only PRs — no admin, no merge. Keep
  branch protection on `main`; the fix PR still requires a human.
- **Bound the blast radius in the contract.** Set tight `allowed_paths` /
  `forbidden_paths` and a small `diff_budget` so an over-eager draft is capped at
  L1 rather than opening a PR. Keep `.github/**` and `.umbra/**` forbidden.
- **Cap cost and volume.** Use `--max-fixes` (start at 3–5). Detection (`umbra
  scan`) is free/offline; only `--fix` spends model calls.
- **Prefer report-only for untrusted code.** Run `umbra scan` (no `--fix`) on
  repositories you don't fully trust; only enable `--fix` where you'd let an agent
  edit the code anyway.
- **Rotate on exposure.** If a key was ever pasted outside a secret store, rotate
  it. Umbra redacts credential shapes from its own outputs, but treat any key that
  left a secret manager as compromised.
