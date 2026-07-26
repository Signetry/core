"""Render the canonical Admission Decision Pack into human surfaces.

The architecture freezes one result type — the Admission Decision Pack — and one
set of UX templates that every surface (PR comment, CLI, hosted UI) must render
from. Keeping that rendering in the kernel guarantees no surface can invent a
stronger claim than the receipt: the GitHub Action, a git hook, and the hosted
console all call the same function over the same ``{report, receipt}`` payload.

``render_pr_comment`` produces the GitHub PR-comment markdown (template A). It is
pure and deterministic — it only restates fields already present in the report and
signed receipt.
"""
from __future__ import annotations

from typing import Any

_AUTHORITY_BADGE = {
    0: "Observe (L0)",
    1: "Analyze (L1)",
    2: "Branch-PR (L2)",
}
_VERDICT = {0: "block", 1: "cap", 2: "admit"}


def _reasons(report: dict[str, Any]) -> list[str]:
    """Machine-readable-ish reason bullets, derived from the report evidence."""
    reasons: list[str] = []
    cr = report.get("contract_result") or {}
    if not cr.get("passed"):
        for v in cr.get("violations", [])[:5]:
            reasons.append(f"`contract_violation` — {v}")
    tb = report.get("trust_boundary") or {}
    if not tb.get("clean"):
        reasons.append(f"`injection_quarantined` — {tb.get('quarantined_count', 0)} untrusted span(s) removed on disk before the run")
    v = report.get("verifier") or {}
    if v.get("blocked"):
        reasons.append("`verifier_blocked` — a blocking safety check failed")
    if v.get("hijack_signal"):
        reasons.append(f"`injection_hijack_signal` — {v.get('independent_detail') or 'change correlates with a quarantined injection surface'}")
    checks = report.get("checks") or {}
    contract = report.get("contract") or {}
    if contract.get("required_checks") and not checks.get("all_passed"):
        reasons.append(f"`check_failed` — required checks ran={checks.get('ran')} all_passed={checks.get('all_passed')}")
    pa = report.get("plan_adherence") or {}
    if pa.get("within_plan") is False:
        for d in pa.get("deviations", [])[:3]:
            reasons.append(f"`plan_deviation` — {d}")
    if report.get("blocked_reason"):
        reasons.append(report["blocked_reason"])
    if not reasons:
        reasons.append("No blocking reasons — the change stayed in scope and was independently verified.")
    return reasons


def render_pr_comment(payload: dict[str, Any]) -> str:
    """Render the canonical GitHub PR-comment markdown from a ``{report, receipt}``
    payload (the shape emitted by ``umbra --json admit``)."""
    report = payload.get("report") or payload  # tolerate a bare report
    envelope = payload.get("receipt") or {}
    receipt = envelope.get("receipt") or {}
    gates = envelope.get("gates") or {}

    level = report.get("authority_level", 0)
    label = _AUTHORITY_BADGE.get(level, "—")
    verdict = _VERDICT.get(level, "block")

    cr = report.get("contract_result") or {}
    tb = report.get("trust_boundary") or {}
    v = report.get("verifier") or {}
    checks = report.get("checks") or {}
    ledger = report.get("providers") or receipt.get("provider_ledger") or {}

    change_provider = ledger.get("change") or report.get("executor", "n/a")
    executor_cell = f"`{report.get('executor', 'n/a')}`"
    if ledger.get("change") and ledger["change"] != report.get("executor"):
        executor_cell += f" (change via `{change_provider}`)"

    contract_cell = f"{'PASS' if cr.get('passed') else 'VIOLATED'} · {len(cr.get('changed_files', []))} file(s)"
    tb_cell = "clean" if tb.get("clean") else f"quarantined {tb.get('quarantined_count', 0)} span(s)"
    checks_cell = (
        f"ran={checks.get('ran')} · all_passed={checks.get('all_passed')} · tier={checks.get('enforcement', 'n/a')}"
        if checks else "n/a"
    )
    verifier_cell = (
        f"deterministic {'blocked' if v.get('blocked') else 'ok'}"
        f" · independent {'hijack_signal' if v.get('hijack_signal') else (v.get('independent_status') or 'n/a')}"
        if v else "n/a"
    )
    receipt_hash = envelope.get("canonical_hash") or "n/a"
    key_note = " ⚠ dev-fallback key (not trustworthy provenance)" if envelope.get("key_ephemeral") else ""

    gate_line = ""
    if gates.get("gates"):
        gate_line = " · ".join(f"{g['id']} {g['status']}" for g in gates["gates"])

    lines = [
        f"## Umbra Admission — {verdict} · Authority L{level} ({label})",
        "",
        "| | |",
        "|---|---|",
        f"| Executor | {executor_cell} |",
        f"| Contract | {contract_cell} |",
        f"| Trust boundary | {tb_cell} |",
        f"| Checks | {checks_cell} |",
        f"| Verifier | {verifier_cell} |",
    ]
    if gate_line:
        lines.append(f"| Proof gates | {gate_line} |")
    lines += [
        f"| Receipt | `{receipt_hash}`{key_note} (artifact attached) |",
        "| Auto-merge | never |",
        "",
        "**Reasons:**",
        "",
    ]
    lines += [f"- {r}" for r in _reasons(report)]
    lines.append("")
    if level >= 2:
        lines.append("This change may open/keep a **branch-only** PR. A human must merge.")
    elif level == 1:
        lines.append("**Analyze only** — do not grant branch-PR authority.")
    else:
        lines.append("**Blocked** — out of policy or failed verification.")
    lines += [
        "",
        "> `auto_merge` is always false. Umbra governs the agent; it never merges. "
        "Verify the signed receipt against Umbra's pinned public key.",
    ]
    return "\n".join(lines)
