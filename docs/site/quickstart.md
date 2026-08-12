# Quickstart

## Install

```bash
# source-available (All Rights Reserved); not on PyPI — install from source
pip install "signetry-core @ git+https://github.com/Signetry/core@v0.6.0"
signetry completion zsh >> ~/.zshrc   # optional: shell completion (bash | zsh | fish)
```

## Scaffold a contract

```bash
signetry init            # writes a conservative starter .signetry/admission.yaml
```

Edit the scope it generates, then govern a change. (Without any contract a
conservative default applies.)

## Govern a change from Python

```python
from pathlib import Path
from signetry_core import get_executor, run_admission, build_receipt, verify_receipt, public_key_b64

agent = get_executor("claude-code")          # or "codex-cli", or "none" for an existing diff
report = run_admission(
    repo_path=Path("checkout"),
    repo_label="acme/app",
    mission="update the vulnerable dependency; change only manifests",
    executor=agent,
)
print(report.authority_level, report.authority)   # e.g. 2 branch_pr
print(report.outcome)

envelope = build_receipt(
    repo=report.repo, base_commit=report.base_commit, contract=report.contract,
    contract_result=report.contract_result, verifier=report.verifier,
    trust_boundary=report.trust_boundary, proposed_change=report.proposed_change,
    providers=report.providers, authority_level=report.authority_level,
    authority=report.authority, executor=report.executor, diff=report.diff,
    checks=report.checks, model_identity=report.model_identity, outcome=report.outcome,
)
# Verify against a PINNED key. In production set SIGNETRY_SIGNING_KEY and pin the
# published key; the dev-fallback key is refused unless pinned explicitly.
assert verify_receipt(envelope, expected_public_key=public_key_b64())["verified"]
```

## Govern from the CLI

```bash
signetry admit . --agent none --mission "review the pending change" --min-authority 1
signetry verify receipt.json --public-key <base64-pubkey>
signetry gates receipt.json           # G1/G2/G3 proof-gate summary (non-zero unless all pass)
signetry comment report.json          # canonical PR-comment markdown from the pack
signetry provenance receipt.json      # in-toto / SLSA statement
signetry admit-extension ./my-skill   # govern a skill / MCP extension (+ --asbom)
signetry brake acme app --store passports.json --reason "incident-42"
```

`signetry admit` exits non-zero unless the change earns at least `--min-authority`,
so it gates a git pre-push hook or CI.

## Declare a contract

Add `.signetry/admission.yaml` to the repo:

```yaml
version: 2
allowed_paths:
  - "src/**"
  - "package.json"
forbidden_paths:
  - "**/deploy.y*ml"
  - ".github/workflows/**"
  - "**/.env*"
  - "**/*secret*"
max_files_changed: 10
required_checks:
  - "pytest"
# Capability graph (v2, optional — omit any line for no extra restriction):
allowed_tools:  [Read, Edit, Bash]
denied_bash:    ["docker\\s+run", "kubectl"]
allowed_mcp:    ["github:search"]
allowed_skills: ["web-search"]
policy_owner: platform-team
policy_version: "1.0"
```

Without one, a conservative default applies. See
[Capabilities & Proof](capabilities.md) for what each v2 field enforces.
