"""Optional Semgrep backend for the detection engine.

Semgrep ships a large community ruleset with near state-of-art recall. This layer
shells out to a locally installed ``semgrep`` and merges its findings — but it is
**never a hard dependency**: if the binary is absent (or the run fails), the layer
is reported as unavailable and the deterministic floor still stands alone.

No network is used: we invoke ``semgrep --config auto`` only when the caller opts
in AND the binary exists. Callers that need a fully offline run leave it disabled.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .model import Finding, Severity, Source

_SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def scan_with_semgrep(
    root: Path,
    *,
    config: str = "auto",
    timeout: int = 120,
) -> list[Finding]:
    """Run semgrep over ``root`` and return findings. Returns [] on any failure so
    the caller can treat absence/error identically (and record it as unavailable).

    ``config="auto"`` fetches the registry ruleset (needs network the first time);
    pass a local ruleset path for an offline run.
    """
    if not semgrep_available():
        return []
    try:
        proc = subprocess.run(
            ["semgrep", "--config", config, "--json", "--quiet", str(root)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        sev = _SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
        cwe = None
        cwe_meta = meta.get("cwe")
        if isinstance(cwe_meta, list) and cwe_meta:
            cwe = str(cwe_meta[0]).split(":")[0].strip()
        elif isinstance(cwe_meta, str):
            cwe = cwe_meta.split(":")[0].strip()
        try:
            rel = str(Path(r.get("path", "")).relative_to(root))
        except ValueError:
            rel = r.get("path", "")
        category = "_".join((meta.get("category") or r.get("check_id", "semgrep")).split(".")[-1:]) or "semgrep"
        findings.append(Finding(
            rule_id=str(r.get("check_id", "semgrep.rule")),
            category=category,
            severity=sev,
            file=rel,
            line=int(r.get("start", {}).get("line", 0) or 0),
            title=str(extra.get("message", r.get("check_id", "semgrep finding")))[:120],
            detail=str(extra.get("message", "")),
            remediation=str(meta.get("references", [""])[0] if meta.get("references") else "See rule docs."),
            confidence=0.75,
            source=Source.SEMGREP,
            cwe=cwe,
        ))
    return findings
