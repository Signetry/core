# Releasing signetry-core

signetry-core is source-available under **[BUSL-1.1](../LICENSE)** (it becomes
Apache-2.0 on 2030-08-31) and is **not published to PyPI** — it is distributed and
installed **from source by tag**:

```bash
pip install "signetry-core @ git+https://github.com/Signetry/core@v0.8.0"
```

Pushing a version tag runs [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which verifies + tests + builds the artifacts and cuts a **GitHub Release** (the
former PyPI Trusted-Publishing job was removed when distribution moved to git-by-tag,
as all prior PyPI releases were yanked).

## Cutting a release

1. Move `## [Unreleased]` in [`CHANGELOG.md`](../CHANGELOG.md) to `## [X.Y.Z] — <date>`.
   The release notes are extracted from that heading, so a release cut without it
   ships the fallback text instead of its own changelog.
2. Bump the version in [`pyproject.toml`](../pyproject.toml) (`[project].version`) to
   match. The workflow fails the release if the two disagree.
3. Update every `core@vX.Y.Z` pin that names the current release — the README, the
   docs, `install.sh`, and the bundled integrations all print an install command a
   user copies. `grep -rn 'core@v'` finds them; leave the `@v0.5.3 or later`-style
   floors alone.
4. Open a PR with those changes and merge it. `main` is protected and requires its
   status checks, so a release cannot be pushed straight to it.
5. Tag the merged commit and push the tag alone:
   ```bash
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
6. The `Release` workflow will:
   - verify the tag matches `pyproject.toml`,
   - run `ruff` + `pytest`,
   - build sdist + wheel and run `twine check`,
   - create a **GitHub Release** with the built artifacts and the git-source
     install command (no PyPI upload).

Verify locally before tagging:

```bash
uv build
uvx twine check dist/*
```

## Versioning

Semantic versioning. Until `1.0.0` the public API (the `signetry_core` top-level
exports, the `signetry` CLI, and the `run_admission` signature) may change between
minor versions; changes are noted in the release.
