"""Tests for the PlanCapabilitySet binding (CaMeL / DRIFT out-of-band control)."""
from __future__ import annotations

from umbra_core.pipeline import (
    Contract,
    derive_plan,
    evaluate_plan_adherence,
)


def _contract():
    return Contract(
        allowed_paths=("package.json", "src/**"),
        forbidden_paths=("**/.env*", "deploy.yml"),
        max_files_changed=2,
        allowed_tools=("Read", "Edit"),
        network="deny",
    )


def test_derive_plan_is_deterministic():
    c = _contract()
    a = derive_plan("bump left-pad", c)
    b = derive_plan("bump left-pad", c)
    assert a.hash() == b.hash()
    assert a.mission_digest == b.mission_digest


def test_plan_binds_contract_capabilities():
    plan = derive_plan("mission", _contract())
    pub = plan.to_public()
    assert pub["allowed_paths"] == ["package.json", "src/**"]
    assert pub["allowed_tools"] == ["Read", "Edit"]
    assert pub["contract_hash"] == _contract().hash()
    assert pub["plan_hash"].startswith("sha256:")


def test_mission_changes_plan_hash():
    c = _contract()
    assert derive_plan("mission A", c).hash() != derive_plan("mission B", c).hash()


def test_mission_not_stored_verbatim():
    # Only a digest of the mission is bound — untrusted prose is never embedded.
    plan = derive_plan("secret internal mission text", _contract())
    assert "secret internal mission text" not in str(plan.to_public())
    assert plan.mission_digest.startswith("sha256:")


def test_in_plan_change_adheres():
    plan = derive_plan("m", _contract())
    result = evaluate_plan_adherence(plan, ["package.json", "src/app.py"])
    assert result.within_plan is True
    assert result.deviations == []


def test_forbidden_path_is_deviation():
    plan = derive_plan("m", _contract())
    result = evaluate_plan_adherence(plan, ["deploy.yml"])
    assert result.within_plan is False
    assert any("forbid" in d for d in result.deviations)


def test_out_of_scope_path_is_deviation():
    plan = derive_plan("m", _contract())
    result = evaluate_plan_adherence(plan, ["lib/other.py"])
    assert result.within_plan is False
    assert any("outside the plan" in d for d in result.deviations)


def test_budget_overrun_is_deviation():
    plan = derive_plan("m", _contract())
    result = evaluate_plan_adherence(plan, ["package.json", "src/a.py", "src/b.py"])
    assert result.within_plan is False
    assert any("budget" in d for d in result.deviations)


def test_plan_adherence_carries_plan_hash():
    plan = derive_plan("m", _contract())
    result = evaluate_plan_adherence(plan, ["package.json"])
    assert result.plan_hash == plan.hash()
