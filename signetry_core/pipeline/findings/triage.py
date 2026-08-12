"""Optional LLM triage layer for the detection engine.

Mirrors the false-positive-filtering approach of claude-code-security-review: a
model reviews the deterministic/semgrep findings in context and (a) marks likely
false positives and (b) adds an exploit scenario. It is **advisory only** and
obeys signetry-core's governing asymmetry:

- It can LOWER a finding's confidence or DROP it as a false positive.
- It can ANNOTATE a finding with an exploit scenario.
- It can NEVER raise severity, add a new blocking finding, or promote a finding to
  authority-granting on its own. The deterministic floor owns what is real; the
  model only reduces noise. (Same principle as verifier.py: a model finding can
  never grant authority.)

The layer is engine-agnostic: it takes a ``triage`` callable so callers can wire
any executor/reasoning backend (or a stub in tests) without this module importing
one. Absence of a callable == layer unavailable == findings pass through unchanged.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Protocol

from .model import Finding

# A triage function takes the findings + source excerpts and returns a JSON string
# with per-finding verdicts. Signature is intentionally simple so any model client
# can adapt to it.
TriageFn = Callable[[str], str]


class SupportsTriage(Protocol):
    def __call__(self, prompt: str) -> str: ...


_TRIAGE_PROMPT = """You are a senior security engineer triaging automated SAST findings to remove false positives. \
For EACH finding below, decide if it is a genuine, exploitable vulnerability.

Rules:
- You may ONLY mark a finding as a false positive or confirm it. You may NOT invent new findings.
- Respond with STRICT JSON only: {"verdicts": [{"index": 0, "false_positive": false, "confidence": 0.0, "exploit_scenario": "..."}]}
- false_positive=true means the flagged code is not actually exploitable (e.g. constant/trusted input, test-only).
- confidence is your confidence the finding is REAL (0..1).

FINDINGS:
__FINDINGS_JSON__
"""


def _build_prompt(findings: list[Finding]) -> str:
    payload = [
        {
            "index": i,
            "rule_id": f.rule_id,
            "category": f.category,
            "file": f.file,
            "line": f.line,
            "title": f.title,
            "detail": f.detail,
        }
        for i, f in enumerate(findings)
    ]
    return _TRIAGE_PROMPT.replace("__FINDINGS_JSON__", json.dumps(payload, indent=2))


def _parse_verdicts(raw: str) -> dict[int, dict[str, Any]]:
    """Parse the model's JSON verdicts; tolerate code fences and trailing prose."""
    import re

    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}
    out: dict[int, dict[str, Any]] = {}
    for v in data.get("verdicts", []):
        if isinstance(v, dict) and isinstance(v.get("index"), int):
            out[v["index"]] = v
    return out


def triage_findings(
    findings: list[Finding],
    triage: SupportsTriage | None,
    *,
    drop_false_positives: bool = True,
) -> tuple[list[Finding], bool]:
    """Apply advisory LLM triage. Returns (findings, layer_ran).

    If ``triage`` is None, findings pass through unchanged and ``layer_ran`` is
    False (recorded as unavailable by the engine). The model can only lower
    confidence, add an exploit scenario, or drop a finding as a false positive —
    never strengthen it. Original deterministic confidence is a floor the model
    cannot raise above.
    """
    if triage is None or not findings:
        return findings, False

    try:
        raw = triage(_build_prompt(findings))
    except Exception:  # noqa: BLE001 - advisory layer must never break a scan
        return findings, False

    verdicts = _parse_verdicts(raw)
    if not verdicts:
        return findings, True  # ran, but produced nothing usable → leave findings intact

    out: list[Finding] = []
    for i, f in enumerate(findings):
        v = verdicts.get(i)
        if v is None:
            out.append(f)
            continue
        if drop_false_positives and bool(v.get("false_positive")):
            continue  # model dropped it as a false positive
        # Model confidence can only LOWER the deterministic confidence, never raise it.
        model_conf = v.get("confidence")
        new_conf = f.confidence
        if isinstance(model_conf, (int, float)):
            new_conf = min(f.confidence, float(model_conf))
        scenario = v.get("exploit_scenario") if isinstance(v.get("exploit_scenario"), str) else f.exploit_scenario
        out.append(Finding(
            rule_id=f.rule_id, category=f.category, severity=f.severity, file=f.file,
            line=f.line, title=f.title, detail=f.detail, remediation=f.remediation,
            confidence=new_conf, source=f.source, cwe=f.cwe, exploit_scenario=scenario,
        ))
    return out, True
