"""Detection engine — layered SAST for umbra-core.

Public surface:
- ``scan_repository(path, ...)`` — walk a repo, run the layers, return a report.
- ``scan_source(file, text)`` — run the deterministic floor over one file.
- ``Finding`` / ``FindingsReport`` / ``Severity`` / ``Source`` — the data model.
"""
from __future__ import annotations

from .deterministic import scan_source
from .engine import scan_repository
from .fetch import resolve_scan_target
from .fusion import FixProposal, mission_for_finding, propose_fix, propose_fixes
from .model import Finding, FindingsReport, Severity, Source
from .sarif import to_sarif
from .semgrep_backend import scan_with_semgrep, semgrep_available
from .triage import triage_findings

__all__ = [
    "scan_repository",
    "scan_source",
    "resolve_scan_target",
    "to_sarif",
    "Finding",
    "FindingsReport",
    "Severity",
    "Source",
    "scan_with_semgrep",
    "semgrep_available",
    "triage_findings",
    "FixProposal",
    "propose_fix",
    "propose_fixes",
    "mission_for_finding",
]
