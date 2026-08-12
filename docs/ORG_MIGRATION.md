# Migrating the Signetry repos into a GitHub Organization

Status: **completed** — the repos now live under the `Signetry` GitHub
organization (`Signetry/core`, `Signetry/action`, `Signetry/plugins`, …). This
doc records how the move was sequenced so the history is clear if it ever needs
to be repeated for a new repo.

## Why the ordering mattered

Two things were pinned to the original `bkd-dotcom` account and **broke or needed
re-linking** on transfer. They were done in this order to avoid downtime:

| Coupling | What broke on transfer | Fix |
|---|---|---|
| **GitHub Marketplace** (`signetry-action`) | Listing may unpublish/relink | Re-verified the Marketplace listing points at `Signetry/action` after transfer |

> Note: signetry-core is **source-available and not published to PyPI** (installed from
> source by tag). There is **no PyPI Trusted Publisher** to re-link — the
> `release.yml` workflow only cuts a GitHub Release.

GitHub **auto-redirects** old repo URLs (clones, links, `uses:` refs) after a
transfer, so external consumers keep working — but the item above is not covered
by that redirect.

## Prerequisites (as they were)

- The org exists (created at <https://github.com/organizations/plan>, Free plan).
- `gh` has `admin:org` + `repo` scope: `gh auth refresh -h github.com -s admin:org,repo`

## Transfer (as run)

```bash
ORG="Signetry"
for r in core action plugins demo-repo; do
  gh api -X POST "repos/bkd-dotcom/signetry-$r/transfer" -f "new_owner=$ORG"
done
```

## Post-transfer fixes (all scripted/checked by hand)

1. **Branch protection** — re-applied on `Signetry/core` `main`
   (`.github` protection JSON) and enabled `enforce_admins`.
2. **CODEOWNERS** — changed `@bkd-dotcom` → `@Signetry/maintainers` (after creating a
   `maintainers` team) in all repos.
3. **Cross-repo links** — updated `bkd-dotcom/…` → `Signetry/…` in:
   READMEs, `docs/site/*`, `integrations/github-action/example-workflow.yml`,
   `signetry-action` README/`action.yml` comments, `signetry-plugins`
   `.claude-plugin/marketplace.json`, `docs/INTEGRATIONS.md`, `docs/LAUNCH.md`.
   Also updated the `git+https://github.com/Signetry/core@vX.Y.Z` install
   references (READMEs, workflows, `action.yml`, install.sh) to the new owner.
4. **Action pin** — `uses: Signetry/action@v1` confirmed as the canonical pin
   (the redirect keeps any old ones working, but docs use the new owner).
5. **Docs site** — GitHub Pages / custom domain on `Signetry/core`.
6. **Marketplace** — confirmed the `signetry-action` listing shows the new owner.
7. **Re-run a release** — tagged a patch (e.g. `v0.5.4`) to confirm the GitHub Release
   automation works under the org (no PyPI publish — source-available/git-install).

## Teams in the org

- `maintainers` — write access to all repos; used by `CODEOWNERS`.
- (optional) `security` — for triaging advisories.
