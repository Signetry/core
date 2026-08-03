# Releasing umbra-core

umbra-core is **source-available** (All Rights Reserved) and is **not published to
PyPI** — it is distributed and installed **from source by tag**:

```bash
pip install "umbra-core @ git+https://github.com/bkd-dotcom/umbra-core@v0.5.4"
```

Pushing a version tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml),
which verifies + tests + builds the artifacts and cuts a **GitHub Release** (the
former PyPI Trusted-Publishing job was removed on the source-available lockdown, as
all prior PyPI releases were yanked).

## Cutting a release

1. Bump the version in [`pyproject.toml`](pyproject.toml) (`[project].version`).
2. Commit: `git commit -am "release: v0.5.3"`.
3. Tag and push:
   ```bash
   git tag v0.5.3
   git push origin main --tags
   ```
4. The `Release` workflow will:
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

Semantic versioning. Until `1.0.0` the public API (the `umbra_core` top-level
exports, the `umbra` CLI, and the `run_admission` signature) may change between
minor versions; changes are noted in the release.
