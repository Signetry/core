# Migrating the Umbra repos into a GitHub Organization

Status: **planned** — execute *after* the Claude Code plugin community-marketplace
review resolves, so the pending submission (pinned to `bkd-dotcom/umbra-plugins`)
isn't disrupted mid-review.

## Why the ordering matters

Three things are pinned to the `bkd-dotcom` account and **break or need re-linking**
on transfer. Do them in this order to avoid downtime:

| Coupling | What breaks on transfer | Fix |
|---|---|---|
| **GitHub Marketplace** (`umbra-action`) | Listing may unpublish/relink | Re-verify the Marketplace listing points at `<ORG>/umbra-action` after transfer |
| **Claude Code plugin review** (`umbra-plugins`) | Pending submission references the old path | Only transfer once the review has resolved; update `marketplace.json` links |

> Note: signetry-core is **source-available and not published to PyPI** (installed from
> source by tag). There is **no PyPI Trusted Publisher** to re-link — the
> `release.yml` workflow only cuts a GitHub Release.

GitHub **auto-redirects** old repo URLs (clones, links, `uses:` refs) after a
transfer, so external consumers keep working — but the three items above are not
covered by that redirect.

## Prerequisites

- The org exists (create at <https://github.com/organizations/plan>, Free plan).
- `gh` has `admin:org` + `repo` scope: `gh auth refresh -h github.com -s admin:org,repo`
- The plugin marketplace review has resolved.

## Transfer (run these once ORG is set)

```bash
ORG="<your-org>"     # e.g. umbra-sec
for r in signetry-core umbra-action umbra-plugins umbra-demo-repo; do
  gh api -X POST "repos/bkd-dotcom/$r/transfer" -f "new_owner=$ORG"
done
```

## Post-transfer fixes (all scripted/checked by hand)

1. **Branch protection** — re-apply on `<ORG>/signetry-core` `main`
   (`.github` protection JSON) and enable `enforce_admins`.
2. **CODEOWNERS** — change `@bkd-dotcom` → `@<ORG>/maintainers` (after creating a
   `maintainers` team) in both repos.
3. **Cross-repo links** — update `bkd-dotcom/…` → `<ORG>/…` in:
   READMEs, `docs/site/*`, `integrations/github-action/example-workflow.yml`,
   `umbra-action` README/`action.yml` comments, `umbra-plugins`
   `.claude-plugin/marketplace.json`, `docs/INTEGRATIONS.md`, `docs/LAUNCH.md`.
   Also update the `git+https://github.com/Signetry/core@vX.Y.Z` install
   references (READMEs, workflows, `action.yml`, install.sh) to the new owner.
4. **Action pin** — `uses: Signetry/action@v1` → `uses: <ORG>/umbra-action@v1`
   (the redirect keeps the old one working, but update docs for correctness).
5. **Docs site** — GitHub Pages / custom domain on `<ORG>/signetry-core`.
6. **Marketplace** — confirm the `umbra-action` listing shows the new owner.
7. **Re-run a release** — tag a patch (e.g. `v0.5.4`) to confirm the GitHub Release
   automation works under the org (no PyPI publish — source-available/git-install).

## Teams to create in the org

- `maintainers` — write access to all repos; used by `CODEOWNERS`.
- (optional) `security` — for triaging advisories.
