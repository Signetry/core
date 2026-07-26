# Changelog

All notable changes to **umbra-core** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Until `1.0.0` the public API may
change between minor versions.

## [0.4.0] — 2026-07-26

### Added — CLI developer experience

- **`umbra init`** scaffolds a conservative starter `.umbra/admission.yaml` (loads
  cleanly through the real contract loader; refuses to overwrite without `--force`),
  so a new user is one command from a governed change.
- **`umbra completion <bash|zsh|fish>`** prints a shell completion script for the
  subcommands (dependency-free; `eval "$(umbra completion zsh)"`).
- **`install.sh`** — a `curl … | sh` one-line installer (uv → pipx → pip, isolated
  and fail-closed) and a **Homebrew tap** (`brew install bkd-dotcom/umbra/umbra`).
- Docs site: a **Capabilities & Proof** page (capability graph, plan binding,
  dual/masked verifier, G1/G2/G3 gates, extension admission) and a refreshed
  quickstart.

## [0.3.0] — 2026-07-26

### Added — Admitted Extension (skill / MCP supply chain) + ASBOM

- **`admit_extension`** governs an agent extension (a *skill* directory or an *MCP*
  server manifest) as a first-class object — the 2026 supply-chain surface the
  per-change pipeline never sees:
  - **Fingerprint** — every file (manifest + docs + scripts) is content-hashed into
    a stable `extension_hash`, so "the skill I admitted" is bound by bytes; a later
    silent edit changes the hash.
  - **Quarantine before read** — documentation surfaces (`SKILL.md`, README) and
    every MCP tool `description` are scanned with the trust-boundary detector; an
    agent-directed manipulation is a **deny**, not an instruction (fail-closed;
    `--allow-quarantined` is an explicit human override).
  - **Allowlist** — when the contract's capability graph declares `allowed_skills`
    / `allowed_mcp`, an extension outside it is denied.
  - **Never grants authority** — admitting an extension only records that these
    exact bytes were reviewed; it does not widen anything.
- **`asbom`** emits a **CycloneDX 1.5-aligned** Agent Software Bill of Materials of
  admitted extensions (SHA-256 hashes + `umbra:verdict` / quarantine properties)
  for org inventory.
- New CLI: **`umbra admit-extension <dir>`** (`--kind`, `--repo` for the allowlist,
  `--allow-quarantined`, `--asbom`, `--org`; exits non-zero on deny). New API:
  `admit_extension`, `inspect_extension`, `asbom`, `AdmittedExtension`,
  `ExtensionFile`.

### Added — G1/G2/G3 proof gates (Proof Plane)

- **`evaluate_gates`** distills a signed receipt into the three governance gates
  the architecture names, so a consumer reads the accountability verdict directly:
  - **G1 Capability integrity** — *what was this agent allowed to do?* Passes when
    a plan capability set was bound before the run and the change stayed within it.
  - **G2 Behavioral authenticity** — *did the checks / sandbox actually run?*
    Passes only when required checks ran under **real isolation** (`sandboxed` /
    `network-isolated`) and passed; a `host-restricted` run is honestly `unproven`.
  - **G3 Interaction auditability** — *is the history tamper-evident?* Passes only
    when signed with a **non-ephemeral** key; strengthened when the receipt is in
    the Merkle transparency log.
- Each gate reports `pass` / `fail` / `unproven` with a reason — never a green on
  missing evidence. `build_receipt` now attaches a `gates` summary to the envelope.
- New CLI: **`umbra gates <receipt.json>`** (exits non-zero unless all gates pass,
  so it can gate CI; `--json` for machine output). New API: `evaluate_gates`,
  `Gate`, `GateSummary`.

### Added — canonical PR-comment renderer (one template, every surface)

- **`render_pr_comment`** renders the frozen GitHub PR-comment template directly
  from the Admission Decision Pack (`{report, receipt}`), so the GitHub Action, a
  git hook, and the hosted console all emit the identical pack — no surface can
  invent a stronger claim than the receipt. Table (Executor · Contract · Trust
  boundary · Checks · Verifier · Proof gates · Receipt · Auto-merge), machine-
  readable reason codes, and the L2/L1/L0 conditional line.
- New CLI: **`umbra comment <report.json>`** (reads the `admit --json` payload from
  a file or stdin). New API: `render_pr_comment`.

### Added — capability graph (contract v2)

- **Capability-graph contract fields** (`.umbra/admission.yaml`, all optional and
  additive; a contract that declares none behaves exactly as before):
  - `allowed_tools` — allowlist of agent tool/command names; a tool off the list
    is denied.
  - `denied_bash` — extra shell deny patterns layered on top of the built-in
    dangerous-command baseline (a malformed regex fails closed on literal match).
  - `allowed_mcp` — allowlist of `server` or `server:tool` MCP identifiers.
  - `allowed_skills` — allowlist of skill/plugin identifiers permitted to load.
- Guard API extended: `guard(repo_path, tool=..., mcp=..., skill=...)` plus
  `guard_tool` / `guard_mcp` / `guard_skill`. Capabilities can only *restrict*.
- `Contract.has_capability_graph` and `capability_graph` in `to_public()` so
  surfaces can label a v1 vs v2 policy. The derived flag is excluded from the
  rules hash, so an empty capability graph does not change a v1 contract's hash.

### Added — independent (masked) second opinion in the verifier

- **`masked_recheck`** (MELON / ShieldAgent line): correlates the actual changeset
  against the manipulation categories the trust boundary detected in untrusted
  repository text. When a change does what an injection surface pushed for (e.g.
  the README tried to induce secret access and the change now reads env secrets),
  it raises a **hijack signal**.
- A hijack signal never *blocks* (the deterministic path owns blocking) but the
  pipeline caps earned authority at ≤ L1 for human review. New verifier fields:
  `independent_status`, `hijack_signal`, `independent_detail` (bound into the
  signed receipt).

### Added — plan capability binding (CaMeL / DRIFT out-of-band control)

- **`PlanCapabilitySet`** is derived from mission + contract *before* the executor
  runs — a frozen, hashable envelope of what the run may do. It is recorded in the
  admission report and signed receipt (answers G1: "what was this agent allowed to
  do?"). Only a digest of the mission is bound, never the prose verbatim.
- After the run, `evaluate_plan_adherence` checks the actual changeset against the
  plan; a deviation caps authority (never widens it).
- New API: `derive_plan`, `evaluate_plan_adherence`, `PlanCapabilitySet`,
  `PlanAdherence`. `build_receipt` accepts `plan_capability_set` / `plan_adherence`.

## [0.2.1] — 2026-07-23

### Fixed

- `umbra_core.__version__` was hardcoded to `"0.1.0"` and had drifted from the
  real package version. It now reads from installed package metadata
  (`importlib.metadata`), so it always matches the released version. Functional
  behavior was unaffected in prior releases (only the reported version string was
  stale); this makes `import umbra_core; umbra_core.__version__` correct.

## [0.2.0] — 2026-07-22

### Added — real-time guard (for editor/agent plugins)

- **`umbra guard`** — a fast, deterministic pre-action check for editor/agent
  hooks. Given one proposed file path and/or shell command, it allows or denies
  against the repo's `.umbra/admission.yaml` — instantly, no model, no network.
- Python API: `guard(repo_path, path=..., command=...) -> GuardDecision`.
- `umbra guard --stdin-json --hook-output` emits Claude Code `PreToolUse`
  decision JSON, so a Claude Code plugin hook can **block** an out-of-scope or
  forbidden edit/command *before it happens* — governance from inside the editor,
  run by deterministic code (not the model).
- Blocks dangerous shell patterns (`curl|bash`, `rm -rf /`, reading `.env`/keys,
  `git push`, `gh secret`, …) and checks any file a command writes against scope.

This is the primitive behind the Umbra editor plugins (Claude Code, Cursor,
Codex). It is a pre-flight guard, not a replacement for full admission.

## [0.1.4] — 2026-07-22

### Repository / tooling

- Added `CODEOWNERS`, Dependabot (pip + github-actions), and a CodeQL workflow.
- Automated the GitHub Release: on a version tag, notes are extracted from this
  changelog and the built sdist + wheel are attached (after the PyPI publish).
- Documentation site (MkDocs Material) publishes to GitHub Pages on release.

No functional or security changes to the library since 0.1.3.

## [0.1.3] — 2026-07-22

### Security — defense in depth

- **Layered prompt-injection detection.** Added structural-carrier detection
  (wording-independent): hidden zero-width/bidi unicode, imperatives inside HTML
  comments, role-prompt fences (`<|system|>`), and long base64 blobs that decode
  to imperatives.
- **Full-file quarantine.** When a hidden/obfuscated/encoded carrier is found (or
  `UMBRA_QUARANTINE_MODE=full`), the entire untrusted instruction file is withheld
  from the agent — detection completeness stops mattering.
- **Optional semantic classifier** via `register_semantic_classifier(fn)` — an
  LLM-backed second opinion, off by default, with failures isolated so they never
  break admission.
- **`UMBRA_REQUIRE_SANDBOX`** strict mode: code-executing checks (`npm/pip
  install`, `go/cargo build`) are *blocked* (fail closed) unless a real sandbox is
  available, instead of degrading to host-restricted.

### Added

- `scan_structural`, `register_semantic_classifier` public exports.
- `checks.unsandboxed_code_execution` recorded in every report/receipt.

## [0.1.2] — 2026-07-22

### Security

- **Un-sandboxed code execution caps authority at L1.** A code-executing check
  that ran without a filesystem/network sandbox can no longer earn branch-PR
  authority; a loud warning is logged.
- **MCP path scoping** via `UMBRA_MCP_ROOTS` — `umbra_admit` refuses paths outside
  the allowlisted workspaces.
- **Baseline isolation via `git archive`** (respects `.gitignore`, no symlink
  follow, filters traversal members) instead of `copytree`.
- Dropped `PYTHONPATH`/`NODE_PATH` from the scrubbed check environment.
- SLSA statements stamp `key_ephemeral` / `provenance_trustworthy` so a dev-key
  receipt is never mistaken for attested provenance.
- Expanded Claude Code disallowed tools (`gh api/release/workflow/secret/auth`,
  `curl`/`wget`/`nc`/`ssh`/`scp`/`rsync`).

### Changed

- PyYAML is now a hard dependency for consistent `admission.yaml` parsing.

## [0.1.1] — 2026-07-22

### Security — pre-Marketplace audit fixes

- **Path-matching bypass (P0).** Git paths are read with
  `core.quotePath=false` so non-ASCII names can't evade forbidden globs; malformed,
  quoted, absolute, and traversal paths fail closed (`is_malformed_path`).
- **Case-insensitive forbidden paths (P0).** `Deploy.yml` / `.ENV` /
  `MY_SECRET.txt` can no longer bypass a lowercase forbidden glob on any filesystem.
- **Receipt trust (P0).** `verify_receipt` refuses the public dev-fallback key
  unless an explicit `expected_public_key` is pinned; requires `canonical_hash`;
  rejects an all-zero signing seed.
- **Symlink guard (P1).** `sanitize_checkout`/`restore_checkout` never follow a
  symlinked instruction file out of the checkout.
- **Broader untrusted sources (P1)** — Copilot/Gemini/Cline/Windsurf/Aider configs
  and PR templates are scanned.
- **Authority guard (P1).** A change can no longer earn L2 by weakening a check
  that wasn't clean at baseline.

### Added

- `NullExecutor` (`--agent none`): govern an existing working-tree diff without
  invoking an agent — the CI primitive used by the GitHub Action.

## [0.1.0] — 2026-07-22

### Added — initial public release

- **Agent-agnostic `Executor` protocol** with `CodexExecutor` and
  `ClaudeCodeExecutor`.
- **Admission pipeline** (`run_admission`): executable contract → trust-boundary
  quarantine → required checks → independent verifier → earned authority (0/1/2)
  → Ed25519-signed receipt. `auto_merge` always false.
- **Earned-authority passport** + Emergency Brake (`gate_pr`, `revoke`).
- **SLSA / in-toto provenance** (`to_slsa_provenance`).
- **Append-only Merkle transparency log**.
- **CLI** (`umbra admit/verify/brake/provenance`), **MCP server**, git pre-push
  hook, and a GitHub Action.

> Note: `0.1.0`–`0.1.2` are superseded by `0.1.3`. See [SECURITY.md](SECURITY.md).

[0.2.1]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.2.1
[0.2.0]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.2.0
[0.1.4]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.4
[0.1.3]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.3
[0.1.2]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.2
[0.1.1]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.1
[0.1.0]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.0
