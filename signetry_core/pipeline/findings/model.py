"""Finding model for the detection engine.

A ``Finding`` is a single detected vulnerability, produced by any engine layer
(deterministic AST/regex floor, optional Semgrep backend, optional LLM triage).
The record is deliberately flat and JSON-serialisable so it can travel through the
admission pipeline, into a signed receipt, and out to CLI/SARIF/eval unchanged.

Design rules (mirroring the rest of signetry-core):
- Frozen dataclasses; ``to_public()`` returns a plain dict.
- No secret VALUES are ever stored — only kind/line/category.
- ``source`` records which layer produced the finding so provenance is honest.
- ``confidence`` is 0..1; the deterministic floor uses fixed, conservative values.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Source(str, Enum):
    """Which engine layer produced a finding — recorded so provenance stays honest."""

    DETERMINISTIC = "deterministic"
    SEMGREP = "semgrep"
    LLM_TRIAGE = "llm-triage"


@dataclass(frozen=True)
class Finding:
    """One detected vulnerability. ``rule_id`` is stable across runs; ``line`` is the
    1-indexed line in ``file`` where the issue was detected (best-effort)."""

    rule_id: str
    category: str
    severity: Severity
    file: str
    line: int
    title: str
    detail: str
    remediation: str
    confidence: float
    source: Source = Source.DETERMINISTIC
    cwe: str | None = None
    # Optional context added by later layers (e.g. LLM triage exploit scenario).
    exploit_scenario: str | None = None

    def key(self) -> tuple[str, int, str]:
        """Dedup key: same class of issue at the same location is the same finding,
        regardless of which layer found it."""
        return (self.file, self.line, self.category)

    def to_public(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "confidence": round(self.confidence, 3),
            "source": self.source.value,
        }
        if self.cwe:
            out["cwe"] = self.cwe
        if self.exploit_scenario:
            out["exploit_scenario"] = self.exploit_scenario
        return out


@dataclass
class FindingsReport:
    """The aggregate result of a scan across all engine layers."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    layers: list[str] = field(default_factory=list)
    # Layers that were requested but unavailable (e.g. semgrep not installed),
    # recorded truthfully rather than silently dropped.
    layers_unavailable: list[str] = field(default_factory=list)

    def by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def to_public(self) -> dict[str, Any]:
        return {
            "findings": [f.to_public() for f in self.findings],
            "files_scanned": self.files_scanned,
            "counts": self.counts(),
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "layers": list(self.layers),
            "layers_unavailable": list(self.layers_unavailable),
        }
