"""Tests for the canonical PR-comment renderer (Admission Decision Pack → markdown)."""
from __future__ import annotations

from umbra_core.pipeline import render_pr_comment


def _payload(level, **overrides):
    report = {
        "authority_level": level,
        "executor": "codex-cli",
        "contract_result": {"passed": True, "changed_files": ["package.json"], "violations": []},
        "trust_boundary": {"clean": True, "quarantined_count": 0},
        "verifier": {"blocked": False, "hijack_signal": False, "independent_status": "clean"},
        "checks": {"ran": True, "all_passed": True, "enforcement": "sandboxed"},
        "contract": {"required_checks": ["npm test"]},
        "providers": {"change": "codex-cli"},
        "plan_adherence": {"within_plan": True},
        "outcome": "ADMITTED",
    }
    report.update(overrides)
    envelope = {"canonical_hash": "sha256:deadbeef", "key_ephemeral": False,
                "gates": {"gates": [{"id": "G1", "status": "pass"}, {"id": "G2", "status": "pass"}, {"id": "G3", "status": "pass"}]}}
    return {"report": report, "receipt": envelope}


def test_l2_renders_admit_and_branch_pr_line():
    md = render_pr_comment(_payload(2))
    assert "admit · Authority L2" in md
    assert "branch-only" in md
    assert "| Auto-merge | never |" in md
    assert "`codex-cli`" in md


def test_l0_renders_block():
    md = render_pr_comment(_payload(
        0,
        contract_result={"passed": False, "changed_files": ["deploy.yml"], "violations": ["Changed a forbidden path: deploy.yml"]},
        blocked_reason="Changed a forbidden path: deploy.yml",
    ))
    assert "block · Authority L0" in md
    assert "**Blocked**" in md
    assert "`contract_violation`" in md
    assert "deploy.yml" in md


def test_l1_renders_cap():
    md = render_pr_comment(_payload(
        1,
        checks={"ran": True, "all_passed": False, "enforcement": "sandboxed"},
    ))
    assert "cap · Authority L1" in md
    assert "Analyze only" in md
    assert "`check_failed`" in md


def test_hijack_signal_surfaces_reason():
    md = render_pr_comment(_payload(
        1,
        verifier={"blocked": False, "hijack_signal": True, "independent_status": "hijack_signal",
                  "independent_detail": "change correlates with secret_access"},
    ))
    assert "`injection_hijack_signal`" in md
    assert "independent hijack_signal" in md


def test_quarantine_surfaces_in_table_and_reasons():
    md = render_pr_comment(_payload(
        2,
        trust_boundary={"clean": False, "quarantined_count": 3},
    ))
    assert "quarantined 3 span(s)" in md
    assert "`injection_quarantined`" in md


def test_ephemeral_key_flagged():
    p = _payload(2)
    p["receipt"]["key_ephemeral"] = True
    md = render_pr_comment(p)
    assert "dev-fallback key" in md


def test_gates_row_rendered():
    md = render_pr_comment(_payload(2))
    assert "| Proof gates | G1 pass · G2 pass · G3 pass |" in md


def test_plan_deviation_reason():
    md = render_pr_comment(_payload(
        1,
        plan_adherence={"within_plan": False, "deviations": ["touched a path outside the plan's allowed scope: lib/x.py"]},
    ))
    assert "`plan_deviation`" in md
    assert "lib/x.py" in md


def test_tolerates_bare_report():
    # A bare report (no {report, receipt} wrapper) should still render.
    md = render_pr_comment(_payload(2)["report"])
    assert "Authority L2" in md
