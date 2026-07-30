"""Fetch a repository into a disposable checkout for scanning.

Mirrors how a hosted agent scanner (e.g. Codex Security) operates on a repo URL:
clone shallowly into a temp directory, scan it, then delete it. Local paths are
returned as-is (no copy). The ``origin`` remote is removed after clone so the
scanned tree can never be pushed to.

Deterministic + minimal: shallow single-commit clone, no submodules, no network
auth handled here (public repos, or the caller's ambient git credentials).
"""
from __future__ import annotations

import contextlib
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path


def _looks_like_url(target: str) -> bool:
    return (
        target.startswith(("http://", "https://", "git@", "ssh://", "git://"))
        or target.endswith(".git")
    )


@contextlib.contextmanager
def resolve_scan_target(target: str, *, depth: int = 1) -> Iterator[Path]:
    """Yield a local directory to scan.

    - A local path is yielded unchanged (nothing is copied or deleted).
    - A git URL is shallow-cloned into a temp dir, the ``origin`` remote removed,
      yielded, then the temp dir is deleted on exit.

    Raises RuntimeError on a failed clone so the CLI can exit non-zero.
    """
    if not _looks_like_url(target):
        yield Path(target)
        return

    tmp = Path(tempfile.mkdtemp(prefix="umbra-scan-"))
    dest = tmp / "repo"
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", str(depth), "--single-branch", "--no-tags",
             target, str(dest)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0 or not dest.is_dir():
            raise RuntimeError(f"clone failed: {proc.stderr.strip() or 'unknown error'}")
        # Remove origin so the disposable checkout can never be pushed to.
        subprocess.run(["git", "remote", "remove", "origin"], cwd=dest,
                       capture_output=True, text=True, check=False)
        yield dest
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
