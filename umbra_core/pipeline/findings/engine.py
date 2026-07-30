"""The detection engine — walk a repo, run the layers, merge into one report.

Layer order and guarantees:
1. **Deterministic floor** (always): offline AST/regex SAST. This is the layer the
   whole engine can stand on with no dependency and no network.
2. **Semgrep** (opt-in, auto-detected): merged when the binary exists; deduped
   against the floor by (file, line, category). Absence is recorded, never fatal.
3. **LLM triage** (opt-in): advisory false-positive reduction + exploit scenarios.
   Can only drop/annotate/lower-confidence — never strengthen.

Merge policy: on a duplicate (file, line, category), keep the finding with the
higher confidence; if a deterministic and a semgrep finding collide, the
deterministic one wins its confidence but we keep the richer detail.
"""
from __future__ import annotations

from pathlib import Path

from .crossfile import analyze_repo_taint
from .deterministic import scan_source
from .lang_crossfile import analyze_repo_taint_multilang
from .model import Finding, FindingsReport, Source
from .semgrep_backend import scan_with_semgrep, semgrep_available
from .triage import SupportsTriage, triage_findings

# Files we never scan (vendored deps, VCS, build output, binaries).
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
              "build", ".next", "out", "vendor", ".mypy_cache", ".pytest_cache"}
_SCAN_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm",
              ".go", ".java", ".rb", ".php", ".cs"}
_MAX_FILE_BYTES = 1_000_000  # skip files > 1 MB (generated/minified)


def _iter_source_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in _SCAN_EXTS:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _merge(existing: dict[tuple[str, int, str], Finding], new: list[Finding]) -> None:
    """Merge ``new`` findings into ``existing`` keyed by (file, line, category),
    keeping the higher-confidence record on collision."""
    for f in new:
        k = f.key()
        prev = existing.get(k)
        if prev is None or f.confidence > prev.confidence:
            existing[k] = f


def scan_repository(
    repo_path: Path | str,
    *,
    use_semgrep: bool = False,
    semgrep_config: str = "auto",
    use_treesitter: bool = False,
    triage: SupportsTriage | None = None,
    cross_file: bool = True,
) -> FindingsReport:
    """Scan a checked-out repository and return a merged findings report.

    - ``use_semgrep``: opt in to the Semgrep layer (only runs if the binary exists).
    - ``use_treesitter``: opt in to the tree-sitter AST layer for higher-precision
      multi-language parsing (only runs if the optional packages are installed).
    - ``triage``: opt in to advisory LLM false-positive reduction.
    - ``cross_file``: run interprocedural/cross-file taint analysis (default on;
      dependency-free, closes source-in-one-file / sink-in-another gaps).

    Fully offline when semgrep/treesitter/triage are left off — the deterministic
    floor and the cross-file pass need no network.
    """
    root = Path(repo_path)
    layers: list[str] = []
    unavailable: list[str] = []

    # --- Layer 1: deterministic floor (always) ---
    merged: dict[tuple[str, int, str], Finding] = {}
    files_scanned = 0
    file_texts: dict[str, str] = {}
    for p in _iter_source_files(root):
        files_scanned += 1
        rel = str(p.relative_to(root))
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        file_texts[rel] = text
        _merge(merged, scan_source(rel, text))
    layers.append(Source.DETERMINISTIC.value)

    # --- Layer 1b: cross-file / interprocedural taint (dependency-free) ---
    if cross_file:
        _merge(merged, analyze_repo_taint(file_texts))
        _merge(merged, analyze_repo_taint_multilang(file_texts))

    # --- Layer 2: semgrep (opt-in, auto-detected) ---
    if use_semgrep:
        if semgrep_available():
            _merge(merged, scan_with_semgrep(root, config=semgrep_config))
            layers.append(Source.SEMGREP.value)
        else:
            unavailable.append(Source.SEMGREP.value)

    # --- Layer 2b: tree-sitter AST (opt-in, optional packages) ---
    if use_treesitter:
        from .treesitter_backend import scan_with_treesitter, treesitter_available
        if treesitter_available():
            _merge(merged, scan_with_treesitter(file_texts))
            layers.append("treesitter")
        else:
            unavailable.append("treesitter")

    findings = list(merged.values())

    # --- Layer 3: LLM triage (opt-in, advisory) ---
    if triage is not None:
        findings, ran = triage_findings(findings, triage)
        (layers if ran else unavailable).append(Source.LLM_TRIAGE.value)
    else:
        unavailable.append(Source.LLM_TRIAGE.value)

    # Stable, useful ordering: severity desc, then file, then line.
    findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line))

    return FindingsReport(
        findings=findings,
        files_scanned=files_scanned,
        layers=layers,
        layers_unavailable=unavailable,
    )
