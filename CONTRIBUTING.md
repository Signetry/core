# Contributing to signetry-core

`signetry-core` is the **engine** of Signetry's [open-core model](https://github.com/Signetry/signetry/blob/main/LICENSING.md).
It is licensed [BUSL-1.1](LICENSE) and converts to Apache-2.0 on **2030-08-31**;
the integration surface around it (the [Action](https://github.com/Signetry/action),
the [plugins](https://github.com/Signetry/plugins), the
[pre-commit guard](https://github.com/Signetry/precommit), the
[eval suite](https://github.com/Signetry/eval)) is Apache-2.0 today.

## What the licence lets you do

Without asking anyone, at no cost: read the source, run it in your own CI, use it in
production to govern changes to repositories you or your organization control, fork
it, patch it, and publish those patches. The single carve-out is offering
`signetry-core` to third parties as a paid, competing hosted service — change
admission, agent governance, or receipt issuance and verification as a service. See
[LICENSE](LICENSE) for the exact grant.

## Getting started

```bash
uv venv
uv pip install -e ".[dev]"      # or: make install
uv run pytest                   # hermetic — no real agent invoked, no network
uv run ruff check .
```

`make test`, `make lint`, and `make build` wrap the same commands. To exercise the
prompt-injection defense end to end:

```bash
uv run python demos/injection/demo.py    # or: make verify-injection
```

Every PR runs the test suite on Python 3.11–3.13 (`uv sync --extra dev`,
`uv run ruff check .`, `uv run pytest -q`), a `signetry scan` SARIF check, the
injection demo, and signetry-core's own admission self-check. Match that locally and
CI should be green.

🌱 **Where to start:** the
[good-first-issues board](https://github.com/Signetry/signetry/issues/10)
and [Discussions](https://github.com/Signetry/signetry/discussions).
Well-scoped areas in this repo:

- **A new detection rule** — add a vuln class or language to
  `signetry_core/pipeline/findings/` with a test in `tests/test_findings_engine.py`.
- **An executor adapter** — wire a new coding agent behind the `Executor` protocol
  (`signetry_core/executors/`).
- **Docs / examples** — clarify the admission pipeline, hardening, or a recipe.

Keep the core deterministic and honest: no model or network calls in the
deterministic pipeline (agent/LLM work stays behind the `Executor` protocol or the
optional classifier hook), `auto_merge` always false, authority earned from evidence,
and no overstating enforcement tiers or detection scope. The
[pull request template](.github/PULL_REQUEST_TEMPLATE.md) is the checklist.

## Signing the CLA (still required before merge)

Open source does **not** mean no CLA. Signetry is open **core**, so code legitimately
moves across the line between the BUSL-1.1 engine and the Apache-2.0 integration
surface — a well-built adapter may be promoted into the engine, and engine code may be
released under Apache-2.0 early or at the Change Date. The CLA is what lets us do that
relicensing without tracking down every past contributor for permission again.

This is enforced by a bot. When you open a pull request, the **CLA Assistant** check
will ask you to sign the [Contributor License Agreement](CLA.md). Reply on the PR
with exactly:

```
I have read the CLA Document and I hereby sign the CLA
```

Your acceptance is recorded in `signatures/cla.json`. A PR **cannot be merged** until
the CLA is signed.

## Credit

Contributors are **acknowledged** in [CONTRIBUTORS.md](CONTRIBUTORS.md), the Git
history, and release notes. See the "Recognition of Contributors" clause in
[CLA.md](CLA.md).

## Conduct and security

Be decent — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security issues go through
[private reporting](https://github.com/Signetry/core/security/advisories/new), not a
public issue; see [SECURITY.md](SECURITY.md).
