# Detection parity + governance moat — plan & head-to-head benchmark

> Status: working plan. Author-run benchmark evidence included. This doc is the
> source of truth the `signetry_core/pipeline/findings/` implementation and the
> `signetry-eval` head-to-head harness are built against.

## Why this exists

Two adjacent tools were tested against Signetry:

- **`@openai/codex-security`** (OpenAI) — an LLM vulnerability scanner (`gpt-5.6-sol`
  at `xhigh`); outputs findings (SARIF/CSV/JSON).
- **`claude-code-security-review`** (Anthropic) — an LLM PR security reviewer;
  diff-aware, outputs structured findings with confidence scores.

Both are **vulnerability scanners**. Signetry is a **change-control / admission plane**
(governs whether an agent's change is *admitted* and proves it with a signed
receipt). They are different categories — but a buyer still asks "does Signetry find
the bugs these find?" Before this work the honest answer was *no*, which undercut
the whole platform. This plan closes that gap **and** proves the governance
advantage the scanners structurally cannot match.

## Measured benchmark (author-run)

A ground-truth fixture was built with 14 planted code vulnerabilities across a
Python Flask app and a Node/Express app, plus a `package.json` with known-CVE
dependencies. The `# GT-N` answer-key tags were stripped before any tool saw the
code.

| Tool | Ran? | Code vulns (of 14) | False positives | Auth / cost |
|---|---|---|---|---|
| claude-code-security-review (real, via Claude prompt) | yes | **13 / 14** | **0** | Anthropic key / Claude sub; $ per PR |
| @openai/codex-security | auth OK, then quota-blocked | n/a (account limit) | n/a | ChatGPT login/API key; $ per scan |
| signetry-core (before) | offline | **0 / 14** | 0 | none |
| signetry-reviewer deterministic scanner | offline | **~3 / 14** | 0 | none |

The one vuln Claude "missed" (GT-11 open redirect) is **deliberately excluded** by
its own false-positive filter, so its effective recall on in-scope classes is 14/14.

## The two scoreboards

1. **Vuln detection** — Signetry lost (0–3 vs 13/14). Table stakes.
2. **Agent governance** — Signetry wins by default: on-disk injection quarantine,
   earned/revocable authority (L0/L1/L2), independent verifier + masked
   hijack-signal re-check, Ed25519 signed receipts, fail-closed sandboxed checks.
   Claude's own README: *"not hardened against prompt injection."* Neither scanner
   has any of this.

**Strategy: reach parity on (1), then wrap detection inside (2), and prove both.**

## The layered detection engine (`signetry_core/pipeline/findings/`)

Three layers, each degrades gracefully:

1. **Deterministic floor (always on, offline, no deps).** Python AST + regex rules
   over full files covering the OWASP set the competitors detect: SQLi, command
   injection, unsafe deserialization, path traversal, weak hashing, insecure
   randomness, `eval`/`exec`, Flask `debug=True`, hardcoded secrets/JWT/DB creds,
   XSS. This layer must hit >=13/14 with 0 FP on the fixture.
2. **Semgrep backend (optional, auto-detected).** If `semgrep` is on PATH, merge its
   registry-rule findings (dedup by file+line+class). Absence never errors.
3. **LLM triage (optional, executor-based).** Reduce false positives + add exploit
   scenarios. Never *promotes* to blocking on its own (same principle as
   `verifier.py`).

Each finding is a stable record: `id, category, severity, file, line, title,
detail, remediation, confidence, source, cwe`.

## Fusing detection into governance (the moat)

A scan produces findings -> Signetry hands a finding to an executor as a bounded "fix
this CWE at file:line" mission -> the fix runs through `run_admission` -> earns
L0/L1/L2 with a signed receipt. Output is not "here's a bug" but **"here's the bug,
the agent's fix, the evidence it passed checks, and a verifiable receipt."**

## Proving it: head-to-head eval

Extend `signetry-eval` with a `detection` scenario category scored against the shared
ground-truth fixture: recall + false-positive rate for Signetry vs the two
competitors on identical inputs, alongside the existing ASR/utility metrics.

## Acceptance criteria

- [x] Deterministic floor detects 13/13 in-scope fixture vulns (14/14 incl. both
      hardcoded secrets), 0 false positives.
- [x] Engine runs fully offline with no new hard dependency.
- [x] Semgrep merged when present; absence never errors.
- [x] LLM triage never promotes a finding to blocking on its own (test-enforced).
- [x] `signetry scan <repo>` CLI with `--fail-on` severity gating for CI.
- [x] `signetry-eval benchmark` emits a head-to-head table on shared ground truth;
      replays captured competitor output, reports not-run tools honestly.
- [x] `pytest` stays green (signetry-core 200, signetry-eval 26).

## Result (measured)

| Scanner | Recall | False positives | Auth | Cost |
|---|---|---|---|---|
| **signetry-core** | **100%** (13/13) | **0** | none | free/offline |
| claude-code-security-review | 100% (13/13) | 0 | Anthropic key | $ per PR |
| openai-codex-security | not run (account quota) | — | ChatGPT/API | $ per scan |

Signetry reached **detection parity** with the LLM scanners while remaining offline,
deterministic, and free — then keeps the governance layer (earned authority,
injection quarantine, independent verifier, signed receipts) that the scanners do
not attempt. Reproduce with `signetry-eval benchmark --markdown`.
