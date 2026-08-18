# Scan a repo in 60 seconds

The detection engine is the zero-setup entry point: no contract, no agent, no API
key, no network. Point it at code and it reports findings.

If you want the governance side instead — bounding what an agent may change and
proving it — start at [Quickstart](quickstart.md).

## Install

```bash
# source-available (All Rights Reserved); not on PyPI — install from source
pip install "signetry-core @ git+https://github.com/Signetry/core@v0.7.0"
```

## Scan

```bash
signetry scan .                                    # a local checkout
signetry scan https://github.com/owner/repo.git    # or a git URL (disposable clone)
```

That is the whole setup. The deterministic layer is offline and dependency-free:
Python AST taint plus cross-file/interprocedural taint, rules and line-based taint
for Go, Java, PHP, Ruby and C#, and rules for Kotlin — covering SQL/command/code
injection, unsafe deserialization, path traversal, XSS, weak crypto, insecure
randomness, SSRF, SSTI, JWT-none, NoSQL, XXE, hardcoded secrets, disabled TLS and
debug mode.

Scanning a git URL shallow-clones to a temp directory and cleans up after itself;
use `--depth` if a rule needs more history.

## Upload to GitHub code scanning

```bash
signetry scan . --sarif -o results.sarif
```

`--sarif` emits SARIF 2.1.0, which `github/codeql-action/upload-sarif` accepts
directly:

```yaml
- run: signetry scan . --sarif -o results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Gate CI

```bash
signetry scan . --fail-on high
```

Exits non-zero when any finding meets or exceeds that severity, so it fails the
job. Accepts `critical`, `high`, `medium`, `low`, `info`.

Starting at `--fail-on critical` on an existing codebase and tightening from there
avoids a wall of pre-existing findings blocking the first build.

## Optional extra layers

```bash
signetry scan . --semgrep       # merge Semgrep results if it is installed
signetry scan . --treesitter    # tree-sitter AST layer, if the extras are installed
```

Both are additive and **non-fatal**: if the tool is absent the scan still runs and
records the layer as unavailable rather than silently claiming it ran.

## Then govern the fix

```bash
signetry scan . --fix --fix-agent codex-cli
```

`--fix` turns each finding into a *bounded* remediation mission, runs it through the
admission pipeline, and seals a signed receipt — so the output is not just "here's a
bug" but the bug, the fix, the evidence it passed checks, and the authority that fix
earned. It **never merges**; only branch-PR-ready changes become branch-only PRs.

`--max-fixes` caps how many findings get a fix attempt (highest severity first,
default 10).

Wiring this as a scheduled action that opens receipt-attached fix PRs is covered in
[AUTOFIX_SETUP.md](https://github.com/Signetry/core/blob/main/docs/AUTOFIX_SETUP.md).

## How it is measured

Detection is scored on a public, 60-case, 7-language corpus with provenance for
every case and SAFE decoys that measure false positives, not just recall —
[Signetry/eval](https://github.com/Signetry/eval).
