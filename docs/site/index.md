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
