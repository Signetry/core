<p align="center">
  <img src="assets/brand/mark-transparent.svg" alt="signetry" width="88" height="88"/>
</p>

# signetry

**A change-control plane for coding agents.**

Coding agents (Claude Code, Codex, Cursor, Copilot, Devin) can change your
repository. signetry-core is the layer that decides **how much authority a given
change has earned — and proves it** — for any agent. It sits *above* the agent, at
the repository, where governance is enforceable.

For every change it runs one deterministic pipeline:

```
executable contract  →  untrusted-text quarantine  →  required checks  →
independent verifier  →  earned authority (0/1/2)  →  Ed25519-signed receipt
```

The governing insight: **a coding agent cannot approve its own authority to make a
change.** The patch-writer is never the patch-approver. `auto_merge` is always
false — a human merges.

## Where to start

- **[Quickstart](quickstart.md)** — install and govern a change in minutes.
- **[Scan a repo in 60 seconds](scan-quickstart.md)** — the zero-setup entry point:
  find vulnerabilities with no contract, agent, or API key.
- **[Concepts](concepts.md)** — the pipeline, earned authority, receipts.
- **[GitHub Action](github-action.md)** — govern every PR (on the Marketplace).
- **[Security](security.md)** — threat model and honest scope.

## Install

```bash
# BUSL-1.1 (Apache-2.0 on 2030-08-31); not on PyPI — install from source
pip install "signetry-core @ git+https://github.com/Signetry/core@v0.7.0"
```

- Source (install from here): <https://github.com/Signetry/core>
- Action (Marketplace): <https://github.com/marketplace/actions/signetry-admission>

## License & contributing

[BUSL-1.1](https://github.com/Signetry/core/blob/main/LICENSE) — source-available, and
it becomes [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) on
**2030-08-31**.

**You may**, at no cost and without asking: read the source, run it in your own CI,
use it in production to govern changes to repositories you or your organization
control, fork it, patch it, and publish those patches.

**You may not** offer `signetry-core` to third parties as a paid, competing hosted
service — change admission, agent governance, or receipt issuance and verification
as a service. That one carve-out is what funds the work.

Everything you actually plug into — the [GitHub Action](https://github.com/Signetry/action),
the [editor and agent plugins](https://github.com/Signetry/plugins), the
[pre-commit guard](https://github.com/Signetry/precommit), and the
[adversarial eval suite](https://github.com/Signetry/eval) — is **Apache-2.0**, so an
integration you build is yours with no strings. See
[LICENSING.md](https://github.com/Signetry/signetry/blob/main/LICENSING.md).

Contributions are accepted under the
[CLA](https://github.com/Signetry/core/blob/main/CLA.md), which is still required: it
lets a contribution move across the open-core line later without re-asking every
contributor for permission. Contributors are **credited** in `CONTRIBUTORS.md`, the Git
history, and release notes. See
[CONTRIBUTING.md](https://github.com/Signetry/core/blob/main/CONTRIBUTING.md) and the
[good-first-issues board](https://github.com/Signetry/signetry/issues/10).
