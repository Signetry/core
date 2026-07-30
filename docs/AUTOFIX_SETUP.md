# Live auto-fix PRs — setup

The `umbra-autofix.yml` workflow scans a repo, has a **live executor** (Codex or
Claude Code) draft a bounded fix per finding under the Umbra admission pipeline,
and opens a **branch-only pull request** for each fix that earns branch-PR (L2)
authority — with the Ed25519-signed receipt committed as `.umbra-receipt.json`.
Umbra **never merges**; a human reviews and merges the PR.

This page is the one-time setup to wire the executor credential.

## What you need

1. An **executor credential** for whichever agent drafts the fixes:
   - **Codex** (`--fix-agent codex-cli`): `OPENAI_API_KEY`, or a logged-in Codex CLI.
   - **Claude Code** (`--fix-agent claude-code`): `ANTHROPIC_API_KEY`.
2. The workflow's built-in `GITHUB_TOKEN` (no PAT needed) with `contents: write`
   and `pull-requests: write` — already declared in the workflow's `permissions`.

## 1. Add the executor secret

Repo → **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | For | Value |
|---|---|---|
| `OPENAI_API_KEY` | Codex | Your OpenAI/Codex API key |
| `ANTHROPIC_API_KEY` | Claude Code | Your Anthropic API key |

You only need the one matching your chosen `--fix-agent`. The workflow passes it to
the executor's CLI as an environment variable; **Umbra itself never uses it to push
or merge** — the credential only lets the agent draft the patch in a disposable
checkout.

CLI equivalent (GitHub CLI):

```bash
gh secret set OPENAI_API_KEY --body "$OPENAI_API_KEY"
# or
gh secret set ANTHROPIC_API_KEY --body "$ANTHROPIC_API_KEY"
```

## 2. Allow the workflow to open PRs

The workflow already requests the right permissions:

```yaml
permissions:
  contents: write        # create the fix branch
  pull-requests: write   # open the branch-only PR
```

Also enable **Settings → Actions → General → Workflow permissions →
"Read and write permissions"** and check **"Allow GitHub Actions to create and
approve pull requests"** (the latter lets the built-in token open PRs).

## 3. Choose the executor + cadence

`umbra-autofix.yml` runs on manual dispatch and a weekly schedule. Pick the agent
when dispatching, or edit the default:

```yaml
on:
  workflow_dispatch:
    inputs:
      fix_agent:
        description: "Executor that drafts fixes (codex-cli | claude-code)"
        default: "codex-cli"     # ← change to claude-code if you set ANTHROPIC_API_KEY
  schedule:
    - cron: "0 6 * * 1"          # weekly, Monday 06:00 UTC — adjust or remove
```

## 4. Run it

- **Manually:** repo → **Actions → "Umbra auto-fix" → Run workflow**, pick the agent.
- **Locally (to preview before enabling CI):**

  ```bash
  export OPENAI_API_KEY=...            # or ANTHROPIC_API_KEY for claude-code
  umbra --json scan . --fix --fix-agent codex-cli --max-fixes 5 > out.json
  ```

  The output is the findings report followed by a `{"fixes": [...]}` object; each
  fix carries `authority_level`, `branch_pr_ready`, `diff`, and a signed `receipt`.

## What actually happens (and what never does)

- For each finding, Umbra hands the agent a **bounded mission** ("fix this CWE at
  file:line; change only what's necessary"). The contract still bounds the change.
- The drafted change runs through the **admission pipeline** (contract → trust
  boundary → required checks → independent verifier) and earns L0/L1/L2 from
  evidence — the agent never grants its own authority.
- Only **L2 (branch-PR-ready)** fixes with a real diff become PRs. L0/L1 are
  reported but **not** opened as PRs.
- Every PR body shows the earned authority and the receipt hash; the receipt is
  committed so an auditor can run `umbra verify .umbra-receipt.json` offline.
- `auto_merge` is **always false**. Umbra opens branch-only PRs; a human merges.

## Costs & limits

- Each drafted fix is a live model call (Codex/Claude) — cost scales with
  `--max-fixes`. Start small (`--max-fixes 3–5`).
- Detection itself (the scan) is free/offline; only the **fix drafting** uses the
  paid executor. You can run scans everywhere and reserve `--fix` for repos you
  want remediated.

## Troubleshooting

- **No PRs opened:** either no findings earned L2 (report-only), or the executor
  wasn't available. Check the `umbra-autofix` artifact (`scan-and-fixes.json`) —
  each fix's `authority_level`/`outcome` explains why.
- **"resource not accessible by integration":** enable *Allow GitHub Actions to
  create and approve pull requests* (step 2).
- **Executor not found:** confirm the secret name matches the `--fix-agent`
  (`OPENAI_API_KEY` ↔ `codex-cli`, `ANTHROPIC_API_KEY` ↔ `claude-code`).
