# Changelog

All notable changes to **signetry-core** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Until `1.0.0` the public API may
change between minor versions.

## [0.8.0] — 2026-09-01

### Added — the receipt format is now a published, independently testable spec

- **[`docs/RECEIPT_SPEC.md`](docs/RECEIPT_SPEC.md)** documents the
  `signetry.remediation-receipt` v1 format in full: envelope, payload,
  canonicalization, signing, the verification algorithm, the §4.3 invariants, and a
  change contract. RFC 2119 language throughout. A receipt is meant to be verifiable
  by someone who does not have this tool and is reading it years later, so the format
  is an interface and is now written down as one.
- **[`tests/conformance/`](tests/conformance/)** — 17 assertions over 7 committed JSON
  vectors, with published test-key seed strings so an implementation in any language
  can be checked against exactly the same files. Regenerate with
  `python tests/conformance/generate_vectors.py`; the vectors are committed rather
  than computed at test time so a change to canonicalization or signing shows up as a
  diff.
- **The spec and the suite are [Apache-2.0](LICENSE-Apache-2.0.txt), named as explicit
  exclusions from the BUSL `Licensed Work`** in [`LICENSE`](LICENSE). They carry no
  restriction and no Change Date. Writing a competing issuer or an independent
  verifier against the spec is a supported use.
- **`check_invariants(receipt)`** (exported from `signetry_core.pipeline`) enforces
  RECEIPT_SPEC §4.3: `auto_merge` must be `false`, `human_review_required` must be
  `true`, plus `kind`/`version`/`authority_level` well-formedness. `verify_receipt`
  now returns `conforming` and `invariant_violations` alongside its cryptographic
  result, because those are different questions — a receipt can be correctly signed
  and still claim something the format forbids.
- **`signetry verify` now fails on a non-conforming receipt**, not just an unverifiable
  one, and says which of the two failed. A validly signed receipt with
  `auto_merge: true` prints `NON-CONFORMING` and `REJECTED` and exits `1`; it never
  prints a bare `VERIFIED`. This is what makes "Signetry never merges on its own
  judgement" a checkable property of every receipt instead of a promise in a README.

### Added — policy registry

- **`signetry policies`** and **`signetry init --policy <id>`**. Six starter admission
  contracts for common repository shapes: `docs-only`, `dependency-bump`,
  `python-library`, `node-service`, `monorepo-service`, `ci-workflow-fix`. Writing the
  first contract is where adoption stalls, and "which globs should an agent be allowed to
  touch in this stack" is a real security decision most teams defer.
- The published file **is** the installed file. `init --policy` copies the registry bytes
  verbatim — no templating, no merge — so an adopter can diff their
  `.signetry/admission.yaml` against the registry and get nothing back. Verified in CI.
- Every entry carries its own evidence. A policy declares example paths it must block and
  must allow in `# @policy` header comments, and `tests/test_policy_registry.py` runs each
  claim through the real `evaluate_contract`. A policy whose documentation does not match
  its behaviour fails CI. The `allows` direction is the one that catches an over-broad
  forbidden glob quietly making a policy useless.
- `ci-workflow-fix` carries a `caution` that `init` prints at adoption time, because write
  access to `.github/workflows` is a privilege-escalation path and a registry that shipped
  it silently would be worse than one that omitted it.
- New public helper `is_policy_placeholder`, and `signetry_core/policies/` ships in the
  wheel (confirmed against a built artifact, not assumed).

### Changed — licence: open core (BUSL-1.1, converting to Apache-2.0)

- `signetry-core` is now licensed **[BUSL-1.1](LICENSE)** and converts to
  **Apache-2.0 on 2030-08-31**, replacing the previous "All Rights Reserved"
  proprietary terms. You may read, run in your own CI, use in production to govern
  repositories you or your organization control, fork, modify, and redistribute it;
  the one carve-out is offering it to third parties as a paid, competing hosted
  service. `pyproject.toml`'s `license` field is now `BUSL-1.1`.
- The **integration surface is Apache-2.0**: the
  [Action](https://github.com/Signetry/action),
  [plugins](https://github.com/Signetry/plugins),
  [pre-commit guard](https://github.com/Signetry/precommit), and
  [eval suite](https://github.com/Signetry/eval).
- The **CLA still applies** — open core means code moves across the BUSL/Apache line,
  and the assignment is what allows that relicensing without re-asking every past
  contributor. `CLA.md`, `CONTRIBUTING.md`, and `CONTRIBUTORS.md` were rewritten for
  the open-source posture; README/docs/workflow comments no longer claim the project
  is "not open source" or "All Rights Reserved".
- No functional or API change. Distribution is unchanged: still installed from source
  by tag, not published to PyPI.
- **The CLA's fallback licence grant is now non-exclusive.** It previously granted the
  Owner an *exclusive* licence where copyright assignment is not permitted by law, which
  would have stripped contributors of the right to use their own contribution — directly
  contradicting the rights the LICENSE grants everyone. The CLA text is now identical
  across all Signetry repositories (bar the engine/integration licence wording) so the
  legal terms cannot drift per-repo again. See [CLA.md](CLA.md) §2–3.

### Fixed

- **A scaffold placeholder was reported as declared provenance.** `signetry init` writes `policy_owner: your-team`, and `policy_status()` reported
  `declared` — *"Policy declares a human owner and version (change-controlled
  metadata)"* — for a file no human had read. Every receipt from a freshly initialised
  repo asserted change-control that did not exist.
- Placeholder provenance is now treated as **absent**, with its own status value:
  `declared` / `placeholder` / `incomplete`, each carrying a `note` explaining which.
  Consumers must treat anything other than `declared` as not change-controlled; the extra
  values exist to say *why*, which is actionable, and never mean "good enough".
- Note for consumers matching on this field: a repo that ran `signetry init` and never
  edited the provenance keys now reports `placeholder` where it previously reported
  `declared`. That is the bug being fixed, not a regression.
- Two repo-root-relative links in `docs/RELEASING.md` resolved from `docs/` and were
  therefore broken.

### Added — Python insecure-deserialisation coverage

- `marshal.load(s)` and `shelve.open` now flagged (CWE-502) — both execute arbitrary
  code during decoding, and neither was detected.
- `yaml.unsafe_load` flagged, and the Loader is now **resolved** rather than merely
  counted: the previous check treated *any* `Loader=` kwarg as safe, so an explicitly
  unsafe `yaml.load(x, Loader=yaml.Loader)` passed silently.
- Gaps identified by @AdvaitVarhade in #87/#91.

### Fixed — a positional safe Loader was a false positive

- `yaml.load(x, yaml.SafeLoader)` was flagged, because the old check only inspected
  keyword arguments. The Loader is now read from the keyword *or* the second
  positional argument, and matched on its last path segment so both `yaml.SafeLoader`
  and a bare imported `SafeLoader` are recognised.

## [0.7.0] — 2026-08-18

### Added — detection breadth

- **Kotlin** (`.kt`/`.kts`) is now scanned at all. It was absent from the extension
  map, so a Kotlin service or Android app scanned clean regardless of contents.
  `kotlin.sql_injection` (CWE-89) and `kotlin.command_injection` (CWE-78) match
  both the `$var`/`${var}` interpolation idiom — which the Java concat-only
  patterns miss entirely — and `+` concatenation. (#52, #93)
- **Go SSRF** — `go.taint.ssrf` (CWE-918): `http.Get/Head/Post/PostForm`,
  `*Client.Do`, `http.NewRequest`. (#95)
- **Go and Java path traversal** — `go.taint.path_traversal` /
  `java.taint.path_traversal` (CWE-22). The Java pattern accepts a qualified
  prefix, so `new java.io.FileInputStream(...)` matches, not only the imported
  short form. (#95)
- **PHP XXE** — `php.xxe` (CWE-611), keyed on `LIBXML_NOENT`/`LIBXML_DTDLOAD` or
  `libxml_disable_entity_loader(false)`. Since PHP 8 / libxml 2.9 external
  entities are off by default, parsing untrusted XML is not itself the bug —
  explicitly re-enabling entities is. (#95)
- `SinkSpec.skip_if` — an optional negative guard for taint sinks where a tainted
  identifier *on the line* does not imply taint *in the dangerous position*. (#97)

### Added — executors

- **`AiderExecutor`**, registered as `aider`. Fail-closed on both
  `SIGNETRY_ENABLE_AIDER=true` and the CLI responding. Commit authority stays with
  the pipeline (`--no-auto-commits`, `--no-dirty-commits`), shell suggestion is
  disabled, read-only runs use `--dry-run`, the `--model` value is rejected unless it
  cannot alter the built command, and the prompt is redacted from the replay
  command. (#53, #96)

### Fixed — SSRF precision

- The Python SSRF rule now resolves the URL argument independently for keyword and
  positional forms. `requests.request` was previously checked at `args[0]` — the
  HTTP *method* — making that target effectively dead for positional calls. Adds
  `httpx` put/patch/delete/head/options/request and `urllib.request` coverage.
  Thanks @AdvaitVarhade. (#86, #89)
- `urllib.request.Request` removed from the SSRF sink list: taint already
  propagates to the `urlopen` sink, so listing the constructor reported one
  vulnerability twice on adjacent lines, where the `(file, line, category)` dedup
  cannot collapse it. (#94)
- A constant host with a tainted query string is no longer reported as Go SSRF.
  `http.Get("https://api.example.com/search?q=" + q)` pins the destination, so it
  is not SSRF — while `http.Get("https://" + userHost)` still is, because the
  attacker controls the host. (#97)

### Fixed — CI

- The advisory reviewer **could never comment on a fork PR**. Fork PRs get a
  read-only `GITHUB_TOKEN` regardless of the `permissions:` block, so
  `pull-requests: write` was silently dropped and the comment call returned 403 —
  every outside contribution showed a red `review` check. Split into an untrusted
  job (no write permission, uploads an artifact) and a trusted `workflow_run` job
  that posts it and never executes PR code. Deliberately not `pull_request_target`.
  (#92)
- The advisory review step's `exit 0   # never fail the PR` had never run: GitHub
  invokes `run:` steps as `bash -e`, so a non-zero exit from the reviewer aborted
  the step first and any Block verdict turned the check red. (#92)

## [0.6.0] — 2026-08-12

### Naming

- The kernel is distributed as **signetry-core** (import package `signetry_core`,
  CLI `signetry`). Environment variables use the `SIGNETRY_*` prefix, the config
  directory is `.signetry/` (e.g. `.signetry/admission.yaml`), and receipt/provenance
  identifiers live in the `signetry` namespace (`signetry.remediation-receipt`,
  provenance `predicate.signetry`, `signetry:*` extension properties,
  `signetry_admit` / `signetry_verify` / `signetry_provenance`).
- Install: `pip install "signetry-core @ git+https://github.com/Signetry/core@v0.6.0"`.

## [0.5.4] — 2026-08-03

### Changed — source-available distribution (no PyPI)

- signetry-core is **source-available** (All Rights Reserved) and is **no longer
  published to PyPI** — all prior PyPI releases were yanked. Install from source:
  `pip install "signetry-core @ git+https://github.com/Signetry/core@v0.5.4"`.
- `install.sh` installs from the git tag (`SIGNETRY_VERSION` overrides), not PyPI.
- `release.yml` no longer publishes to PyPI; it builds/tests and cuts a GitHub
  Release with the git-source install command.
- Docs (SECURITY, INTEGRATIONS, RELEASING, ORG_MIGRATION, docs/site, LAUNCH),
  the bundled git hook, the MCP server hints, and the integrations action install
  signetry-core from source. No functional/library API change from `0.5.3`.

## [0.5.3] — 2026-07-30

### Fixed — Codex sandbox on CI runners

- `CodexExecutor` honors `SIGNETRY_CODEX_SANDBOX` (`read-only` | `workspace-write` |
  `danger-full-access`) so a run can select a sandbox mode that initializes on the
  host. On CI runners the OS sandbox (bubblewrap/Landlock) often cannot start, which
  made `codex exec` fail; the operator can now choose full-access drafting there.
  Safe because the executor only DRAFTS in a disposable checkout with no push/merge
  credentials, and Signetry's admission pipeline governs the result regardless.
- The auto-fix workflow sets `SIGNETRY_CODEX_SANDBOX=danger-full-access` for CI.

## [0.5.2] — 2026-07-30

### Added — OpenAI/Anthropic-compatible gateway support (e.g. IBM ICA)

- `CodexExecutor` accepts a custom, syntactically-safe model name when
  `OPENAI_BASE_URL` points at a gateway (e.g. `gpt-5.5-gus` on IBM ICA), in addition
  to the native allowlist. The strict allowlist still applies to `api.openai.com`.
- The auto-fix workflow gained `openai_base_url` / `codex_model` /
  `anthropic_base_url` / `claude_model` inputs so a run can use a gateway with the
  caller's own key (bring-your-own-key), configuring Codex via an isolated
  `CODEX_HOME` provider and Claude via `ANTHROPIC_BASE_URL` + `SIGNETRY_CLAUDE_MODEL`.

Verified live on IBM ICA: Codex (`gpt-5.5-gus`) and Claude (`claude-opus-4-8`) each
draft a fix that earns L2 through the admission pipeline.

## [0.5.1] — 2026-07-30

### Security — bring-your-own-key safety for `--fix`

- Redact credential shapes (OpenAI/Anthropic/GitHub/AWS/Google/Slack keys, PEM
  private keys, generic `secret=`/`token=` assignments) from any fix diff, receipt,
  or artifact before it is serialised — so a governed fix or auto-fix PR can never
  carry an executor credential.
- Extend the required-check env defense-in-depth denylist (ANTHROPIC/CLAUDE/CODEX/
  GEMINI/AZURE/…); the check environment remains an allowlist, so keys cannot reach
  a check subprocess by construction.
- Every user brings their own key: the executor credential lives only in the
  caller's own environment/repo secret, is never shared, never written to git, and
  never used to push or merge. See `docs/AUTOFIX_SETUP.md`.

## [0.5.0] — 2026-07-30

### Added — detection engine + governed fix fusion

- **Layered SAST detection engine** (`signetry_core.pipeline.findings`): a
  deterministic, offline floor (Python AST taint + regex) across the OWASP set —
  SQLi, command/code injection, unsafe deserialization, path traversal, XSS, weak
  crypto, insecure randomness, SSRF, SSTI, JWT-none, Django raw SQL, NoSQL, XXE,
  hardcoded secrets, TLS-off, debug mode.
- **Cross-file / interprocedural taint** for Python and for Go/Java/PHP/Ruby/C#
  (source in one file → call → sink in another).
- **Multi-language rules + line-based taint** for Go/Java/PHP/Ruby/C#, sanitizer-
  and parameterised-query-aware (zero-FP oriented).
- **Optional layers, non-fatal when absent**: Semgrep, tree-sitter AST, and LLM
  triage (advisory only — never strengthens or self-approves).
- **SARIF 2.1.0 export** and disposable **remote-repo clone** (`signetry scan <url>`).
- **Fusion**: `signetry scan --fix --fix-agent <codex-cli|claude-code>` turns each
  finding into a bounded remediation mission, runs it through the admission
  pipeline, and seals an Ed25519 receipt; `signetry-autofix.yml` opens branch-only fix
  PRs (never merges). Setup: `docs/AUTOFIX_SETUP.md`.
- **CLI**: `signetry scan` with `--json`/`--sarif`/`--output`, `--fail-on`, and the
  opt-in `--semgrep`/`--treesitter` layers.

Benchmark (see Signetry/eval): 52-case public corpus across 7 languages —
signetry-core **100% recall / 0 false positives** vs claude-code-security-review
(Opus 4.8) 90%.

## [0.4.0] — 2026-07-26

### Added — CLI developer experience

- **`signetry init`** scaffolds a conservative starter `.signetry/admission.yaml` (loads
  cleanly through the real contract loader; refuses to overwrite without `--force`),
  so a new user is one command from a governed change.
- **`signetry completion <bash|zsh|fish>`** prints a shell completion script for the
  subcommands (dependency-free; `eval "$(signetry completion zsh)"`).
- **`install.sh`** — a `curl … | sh` one-line installer (uv → pipx → pip, isolated
  and fail-closed) and a **Homebrew tap** (`brew install signetry/signetry/signetry`).
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
  admitted extensions (SHA-256 hashes + `signetry:verdict` / quarantine properties)
  for org inventory.
- New CLI: **`signetry admit-extension <dir>`** (`--kind`, `--repo` for the allowlist,
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
- New CLI: **`signetry gates <receipt.json>`** (exits non-zero unless all gates pass,
  so it can gate CI; `--json` for machine output). New API: `evaluate_gates`,
  `Gate`, `GateSummary`.

### Added — canonical PR-comment renderer (one template, every surface)

- **`render_pr_comment`** renders the frozen GitHub PR-comment template directly
  from the Admission Decision Pack (`{report, receipt}`), so the GitHub Action, a
  git hook, and the hosted console all emit the identical pack — no surface can
  invent a stronger claim than the receipt. Table (Executor · Contract · Trust
  boundary · Checks · Verifier · Proof gates · Receipt · Auto-merge), machine-
  readable reason codes, and the L2/L1/L0 conditional line.
- New CLI: **`signetry comment <report.json>`** (reads the `admit --json` payload from
  a file or stdin). New API: `render_pr_comment`.

### Added — capability graph (contract v2)

- **Capability-graph contract fields** (`.signetry/admission.yaml`, all optional and
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

- `signetry_core.__version__` was hardcoded to `"0.1.0"` and had drifted from the
  real package version. It now reads from installed package metadata
  (`importlib.metadata`), so it always matches the released version. Functional
  behavior was unaffected in prior releases (only the reported version string was
  stale); this makes `import signetry_core; signetry_core.__version__` correct.

## [0.2.0] — 2026-07-22

### Added — real-time guard (for editor/agent plugins)

- **`signetry guard`** — a fast, deterministic pre-action check for editor/agent
  hooks. Given one proposed file path and/or shell command, it allows or denies
  against the repo's `.signetry/admission.yaml` — instantly, no model, no network.
- Python API: `guard(repo_path, path=..., command=...) -> GuardDecision`.
- `signetry guard --stdin-json --hook-output` emits Claude Code `PreToolUse`
  decision JSON, so a Claude Code plugin hook can **block** an out-of-scope or
  forbidden edit/command *before it happens* — governance from inside the editor,
  run by deterministic code (not the model).
- Blocks dangerous shell patterns (`curl|bash`, `rm -rf /`, reading `.env`/keys,
  `git push`, `gh secret`, …) and checks any file a command writes against scope.

This is the primitive behind the Signetry editor plugins (Claude Code, Cursor,
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
  `SIGNETRY_QUARANTINE_MODE=full`), the entire untrusted instruction file is withheld
  from the agent — detection completeness stops mattering.
- **Optional semantic classifier** via `register_semantic_classifier(fn)` — an
  LLM-backed second opinion, off by default, with failures isolated so they never
  break admission.
- **`SIGNETRY_REQUIRE_SANDBOX`** strict mode: code-executing checks (`npm/pip
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
- **MCP path scoping** via `SIGNETRY_MCP_ROOTS` — `signetry_admit` refuses paths outside
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
- **CLI** (`signetry admit/verify/brake/provenance`), **MCP server**, git pre-push
  hook, and a GitHub Action.

> Note: `0.1.0`–`0.1.2` are superseded by `0.1.3`. See [SECURITY.md](SECURITY.md).

[0.2.1]: https://github.com/Signetry/core/releases/tag/v0.2.1
[0.2.0]: https://github.com/Signetry/core/releases/tag/v0.2.0
[0.1.4]: https://github.com/Signetry/core/releases/tag/v0.1.4
[0.1.3]: https://github.com/Signetry/core/releases/tag/v0.1.3
[0.1.2]: https://github.com/Signetry/core/releases/tag/v0.1.2
[0.1.1]: https://github.com/Signetry/core/releases/tag/v0.1.1
[0.1.0]: https://github.com/Signetry/core/releases/tag/v0.1.0

<!-- cla skip verify 1785776744 -->
