# umbra-core

**An agent-agnostic change-control plane for coding agents.**

Coding agents (Claude Code, Codex, Cursor, Copilot, Devin) can change your
repository. umbra-core is the layer that decides **how much authority a given
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
- **[Concepts](concepts.md)** — the pipeline, earned authority, receipts.
- **[GitHub Action](github-action.md)** — govern every PR (on the Marketplace).
- **[Security](security.md)** — threat model and honest scope.

## Install

```bash
# source-available (All Rights Reserved); not on PyPI — install from source
pip install "umbra-core @ git+https://github.com/bkd-dotcom/umbra-core@v0.5.4"
```

- Source (install from here): <https://github.com/bkd-dotcom/umbra-core>
- Action (Marketplace): <https://github.com/marketplace/actions/umbra-admission>

## License & contributing

umbra-core is **source-available** — the code is public to read, evaluate, and
contribute to, but it is **not open source**. It is **All Rights Reserved
(© 2026 Binay Dalai)** and installed from source (not PyPI).

Contributions are welcome under a **Contributor License Agreement**: you can
contribute and you'll be **credited** (in `CONTRIBUTORS.md`, the Git history, and
release notes), but you gain no right to use, sell, or rebrand the project — the
owner retains all rights. See
[CONTRIBUTING.md](https://github.com/bkd-dotcom/umbra-core/blob/main/CONTRIBUTING.md),
the [CLA](https://github.com/bkd-dotcom/umbra-core/blob/main/CLA.md), and the
[good-first-issues board](https://github.com/bkd-dotcom/umbra-umbrella/issues/10).
