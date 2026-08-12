"""Tests for the independent (masked) second opinion in the verifier.

The masked re-check correlates a proposed changeset against the manipulation
categories detected in the untrusted repository text. When a change does what an
injection surface pushed for, it raises a *hijack signal* — never blocking, but
capping earned authority at ≤ L1 for human review.
"""
from __future__ import annotations

from signetry_core import masked_recheck, verify_change
from signetry_core.pipeline import ContractResult


def _passing_contract_result(files):
    return ContractResult(status="pass", changed_files=list(files), contract_hash="sha256:test")


# --- masked_recheck unit -----------------------------------------------------

def test_no_trust_boundary_findings_is_clean():
    status, hijack, _ = masked_recheck({"src/a.py": "x = 1"}, [])
    assert status == "clean" and hijack is False


def test_secret_access_injection_plus_secret_read_is_hijack():
    # Repo text tried to induce secret access; change now reads env secrets.
    changes = {"src/util.py": "import os\nkey = os.environ['API_KEY']\n"}
    status, hijack, detail = masked_recheck(changes, ["secret_access"])
    assert hijack is True
    assert status == "hijack_signal"
    assert "secret_access" in detail


def test_command_injection_plus_shell_exec_is_hijack():
    changes = {"src/run.py": "import subprocess\nsubprocess.run(cmd, shell=True)\n"}
    status, hijack, _ = masked_recheck(changes, ["command_injection"])
    assert hijack is True


def test_injection_detected_but_change_unrelated_is_clean():
    # A manipulation was quarantined, but the change is a benign version bump.
    changes = {"package.json": '{"dependencies": {"lodash": "4.17.21"}}'}
    status, hijack, detail = masked_recheck(changes, ["secret_access"])
    assert hijack is False
    assert status == "clean"
    assert "none of the behaviours" in detail


def test_unmatched_category_does_not_fire():
    # A category with no signal mapping (e.g. agent_directive) alone is not a hit.
    changes = {"src/a.py": "def f():\n    return 1\n"}
    status, hijack, _ = masked_recheck(changes, ["agent_directive"])
    assert hijack is False


# --- verify_change integration ----------------------------------------------

def test_verify_change_surfaces_hijack_signal():
    changes = {"src/leak.py": "import os\nprint(os.environ['SECRET'])\n"}
    report = verify_change(
        changes,
        _passing_contract_result(changes),
        trust_boundary_categories=["secret_access"],
    )
    pub = report.to_public()
    assert pub["hijack_signal"] is True
    assert pub["independent_status"] == "hijack_signal"
    # An independent check appears in the report and is non-blocking.
    masked = next(c for c in pub["checks"] if c["name"] == "independent_masked")
    assert masked["status"] == "fail"
    assert masked["blocking"] is False
    # A hijack signal alone does NOT block (the deterministic path owns blocking).
    assert report.blocked is False


def test_verify_change_clean_when_no_categories():
    changes = {"package.json": '{"dependencies": {"left-pad": "1.3.0"}}'}
    report = verify_change(changes, _passing_contract_result(changes))
    assert report.hijack_signal is False
    assert report.independent_status == "clean"
