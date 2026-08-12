# Live auto-fix PRs — setup

The `signetry-autofix.yml` workflow scans a repo, has a **live executor** (Codex or
Claude Code) draft a bounded fix per finding under the Umbra admission pipeline,
and opens a **branch-only pull request** for each fix that earns branch-PR (L2)
authority — with the Ed25519-signed receipt committed as `.signetry-receipt.json`.
Umbra **never merges**; a human reviews and merges the PR.

This page is the one-time setup to wire the executor credential.

## Using a gateway (IBM ICA and other OpenAI/Anthropic-compatible proxies)

Bring-your-own-key works with a gateway too. Pass the base URL and an entitled
model as workflow inputs; the key still lives only in your repo's secret.

| Input | Codex | Claude Code |
|---|---|---|
| `openai_base_url` | e.g. `https://api.nextgen-beta.ica.ibm.com/ica/v1` | — |
| `codex_model` | e.g. `gpt-5.5-gus` (an entitled model) | — |
| `anthropic_base_url` | — | e.g. `https://api.nextgen-beta.ica.ibm.com/ica` |
| `claude_model` | — | e.g. `claude-opus-4-8` |
| secret | `OPENAI_API_KEY` (the gateway key) | `ANTHROPIC_API_KEY` (the gateway key) |

Verified live on IBM ICA: both executors draft a real fix that earns **L2** (in-
scope, verified) with a signed receipt — see the demo PRs on
[umbra-autofix-demo](https://github.com/Signetry/autofix-demo).

> **Model note (IBM ICA):** Codex requires a model whose backend supports the
> Responses API. On ICA, `gpt-5.5-gus` works; the `gpt-5.6-*-dzus` models route to
> Azure OpenAI and reject Codex's Responses API version. Only models in your team's
> entitlement (`global-models`) are accessible.
>
> **Known CI limitation:** running `codex exec`'s multi-turn agent mode *inside
> GitHub Actions* against the ICA **beta** gateway can fail even when a one-shot
> call and a local run succeed (a Responses-API/tool-use quirk of the beta proxy,
> not of Umbra). If you hit this, run `--fix-agent claude-code` with the Anthropic
> gateway inputs, or run the fusion locally (`signetry scan --fix`) where it is proven
> to reach L2 + receipt + branch-only PR.

## Bring your own key — the security model

**Every user brings their own key. No one's credential is ever shared, and no key
leaks.** This is enforced by the mechanism, not just policy:

- **Your key lives in your repo.** The workflow reads
  `${{ secrets.OPENAI_API_KEY }}` / `${{ secrets.ANTHROPIC_API_KEY }}` from **your
  own repository's** Actions secrets. There is no central Umbra key and no shared
  credential — if you don't set a secret, no live fix runs (the scan still works;
  fusion degrades to the deterministic, no-change path). Publishing/adopting Umbra
  never exposes anyone else's key to you or yours to them.
- **Scoped to one step.** The credential is set in the *scan* step's `env` only.
  The PR-opening step runs without it. It is never written to disk or committed.
- **Never in git, artifacts, receipts, or PRs.** The engine redacts credential
  shapes (OpenAI/Anthropic/GitHub/AWS/Google/Slack keys, PEM private keys, and
  generic `secret=…`/`token=…` assignments) from the diff **and** the receipt
  before anything is serialised. The workflow also registers the values with the
  runner's log masker (`::add-mask::`) and **fails closed** if any credential shape
  is found in the output before a PR is opened.
- **Never reaches your build/checks.** Required-check subprocesses run with an
  **allowlisted** environment (only `PATH`/`HOME`/`LANG`/… are copied) — API keys
  cannot reach an untrusted check by construction, not merely by a denylist.
- **The executor only drafts; Umbra decides and never merges.** The key lets the
  agent write a patch in a disposable checkout. Umbra is never given push/merge
  credentials for the fix; `auto_merge` is always false.

If you self-host or run this across an org, each repo (or org secret you control)
carries its own key; a scan of repo A never uses repo B's credential.

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

`signetry-autofix.yml` runs on manual dispatch and a weekly schedule. Pick the agent
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
  signetry --json scan . --fix --fix-agent codex-cli --max-fixes 5 > out.json
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
  committed so an auditor can run `signetry verify .signetry-receipt.json` offline.
- `auto_merge` is **always false**. Umbra opens branch-only PRs; a human merges.

## Costs & limits

- Each drafted fix is a live model call (Codex/Claude) — cost scales with
  `--max-fixes`. Start small (`--max-fixes 3–5`).
- Detection itself (the scan) is free/offline; only the **fix drafting** uses the
  paid executor. You can run scans everywhere and reserve `--fix` for repos you
  want remediated.

## Troubleshooting

- **No PRs opened:** either no findings earned L2 (report-only), or the executor
  wasn't available. Check the `signetry-autofix` artifact (`scan-and-fixes.json`) —
  each fix's `authority_level`/`outcome` explains why.
- **"resource not accessible by integration":** enable *Allow GitHub Actions to
  create and approve pull requests* (step 2).
- **Executor not found:** confirm the secret name matches the `--fix-agent`
  (`OPENAI_API_KEY` ↔ `codex-cli`, `ANTHROPIC_API_KEY` ↔ `claude-code`).
