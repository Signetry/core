"""Tests for the G1/G2/G3 proof-gate summary."""
from __future__ import annotations

from signetry_core import evaluate_gates


def _envelope(receipt=None, *, key_ephemeral=False, signature="sig", canonical_hash="sha256:abc"):
    return {
        "receipt": receipt or {},
        "canonical_hash": canonical_hash,
        "signature": signature,
        "public_key": "pk",
        "algorithm": "Ed25519",
        "key_ephemeral": key_ephemeral,
    }


def _g(summary, gid):
    return next(g for g in summary.gates if g.id == gid)


# --- G1 capability integrity -------------------------------------------------

def test_g1_pass_when_plan_bound_and_within():
    r = {
        "plan_capability_set": {"plan_hash": "sha256:plan"},
        "plan_adherence": {"within_plan": True, "deviations": []},
        "policy_hash": "sha256:contract",
    }
    assert _g(evaluate_gates(_envelope(r)), "G1").status == "pass"


def test_g1_fail_on_deviation():
    r = {
        "plan_capability_set": {"plan_hash": "sha256:plan"},
        "plan_adherence": {"within_plan": False, "deviations": ["out of scope"]},
    }
    assert _g(evaluate_gates(_envelope(r)), "G1").status == "fail"


def test_g1_unproven_without_plan():
    assert _g(evaluate_gates(_envelope({})), "G1").status == "unproven"


# --- G2 behavioral authenticity ----------------------------------------------

def test_g2_pass_when_checks_ran_sandboxed_and_passed():
    r = {
        "contract": {"required_checks": ["npm test"]},
        "checks": {"ran": True, "all_passed": True, "enforcement": "sandboxed"},
    }
    assert _g(evaluate_gates(_envelope(r)), "G2").status == "pass"


def test_g2_unproven_when_host_restricted():
    r = {
        "contract": {"required_checks": ["npm test"]},
        "checks": {"ran": True, "all_passed": True, "enforcement": "host-restricted"},
    }
    assert _g(evaluate_gates(_envelope(r)), "G2").status == "unproven"


def test_g2_fail_when_checks_did_not_run():
    r = {
        "contract": {"required_checks": ["npm test"]},
        "checks": {"ran": False, "all_passed": False, "enforcement": "declared"},
    }
    assert _g(evaluate_gates(_envelope(r)), "G2").status == "fail"


def test_g2_fail_when_checks_failed():
    r = {
        "contract": {"required_checks": ["npm test"]},
        "checks": {"ran": True, "all_passed": False, "enforcement": "sandboxed"},
    }
    assert _g(evaluate_gates(_envelope(r)), "G2").status == "fail"


def test_g2_unproven_without_required_checks():
    r = {"contract": {"required_checks": []}, "checks": {}}
    assert _g(evaluate_gates(_envelope(r)), "G2").status == "unproven"


# --- G3 interaction auditability ---------------------------------------------

def test_g3_pass_with_managed_key():
    assert _g(evaluate_gates(_envelope({}, key_ephemeral=False)), "G3").status == "pass"


def test_g3_unproven_with_ephemeral_key():
    assert _g(evaluate_gates(_envelope({}, key_ephemeral=True)), "G3").status == "unproven"


def test_g3_fail_when_unsigned():
    assert _g(evaluate_gates(_envelope({}, signature=None)), "G3").status == "fail"


def test_g3_strengthened_by_transparency_log():
    log = {"root": "deadbeefcafe0000", "size": 3, "entry": {"index": 2}}
    gate = _g(evaluate_gates(_envelope({}), log_inclusion=log), "G3")
    assert gate.status == "pass"
    assert "transparency log" in gate.reason
    assert gate.evidence["transparency_log"]["logged"] is True


# --- summary -----------------------------------------------------------------

def test_all_pass_summary():
    r = {
        "plan_capability_set": {"plan_hash": "sha256:plan"},
        "plan_adherence": {"within_plan": True},
        "contract": {"required_checks": ["npm test"]},
        "checks": {"ran": True, "all_passed": True, "enforcement": "sandboxed"},
    }
    summary = evaluate_gates(_envelope(r, key_ephemeral=False))
    assert summary.all_pass is True
    pub = summary.to_public()
    assert pub["all_pass"] is True
    assert [g["id"] for g in pub["gates"]] == ["G1", "G2", "G3"]


def test_ephemeral_key_blocks_all_pass():
    r = {
        "plan_capability_set": {"plan_hash": "sha256:plan"},
        "plan_adherence": {"within_plan": True},
        "contract": {"required_checks": ["npm test"]},
        "checks": {"ran": True, "all_passed": True, "enforcement": "sandboxed"},
    }
    assert evaluate_gates(_envelope(r, key_ephemeral=True)).all_pass is False
