"""SARIF 2.1.0 export for detection findings.

SARIF (Static Analysis Results Interchange Format) is the industry-standard output
GitHub code scanning, VS Code, and most security dashboards consume — the same
format ``@openai/codex-security`` and ``claude-code-security-review`` can emit. This
lets Signetry's findings drop into the exact same pipelines, so adopting Signetry is a
format-compatible swap, not a migration.

Pure stdlib, deterministic (no timestamps injected), no network.
"""
from __future__ import annotations

from typing import Any

from .model import Finding, FindingsReport, Severity

# SARIF result levels (SARIF has: error / warning / note / none).
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# security-severity is GitHub's numeric ranking (0.0–10.0) used for sorting/alerts.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

_TOOL_URI = "https://github.com/Signetry/core"


def _rule_id(f: Finding) -> str:
    return f.rule_id


def _unique_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """One SARIF rule descriptor per distinct rule_id."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.rule_id, f)
    rules: list[dict[str, Any]] = []
    for rid, f in seen.items():
        rule: dict[str, Any] = {
            "id": rid,
            "name": f.category,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.detail},
            "help": {"text": f.remediation},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            "properties": {
                "tags": ["security", f.category] + ([f.cwe] if f.cwe else []),
                "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.0"),
            },
        }
        if f.cwe:
            rule["properties"]["cwe"] = f.cwe
        rules.append(rule)
    return rules


def _result(f: Finding) -> dict[str, Any]:
    msg = f.title
    if f.exploit_scenario:
        msg += f" — {f.exploit_scenario}"
    return {
        "ruleId": f.rule_id,
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(1, f.line)},
            }
        }],
        "properties": {
            "confidence": round(f.confidence, 3),
            "source": f.source.value,
            **({"cwe": f.cwe} if f.cwe else {}),
        },
    }


def to_sarif(report: FindingsReport, *, tool_version: str = "0.0.0") -> dict[str, Any]:
    """Render a FindingsReport as a SARIF 2.1.0 document (a plain dict; json.dumps it)."""
    findings = report.findings
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "signetry-core",
                    "informationUri": _TOOL_URI,
                    "version": tool_version,
                    "rules": _unique_rules(findings),
                }
            },
            "results": [_result(f) for f in findings],
            "properties": {
                "filesScanned": report.files_scanned,
                "layers": list(report.layers),
                "layersUnavailable": list(report.layers_unavailable),
            },
        }],
    }
