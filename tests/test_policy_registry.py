"""The registry's own evidence.

Every shipped policy declares the paths it blocks and the paths it allows. This module
runs those declarations through the real ``evaluate_contract`` — the same function the
admission pipeline uses — so a policy whose claims do not hold fails CI instead of
misleading whoever adopts it.

The pattern is deliberate: the registry does not get to assert that a policy works. It
has to demonstrate it, per claim, with the production code path.
"""
from __future__ import annotations

import pytest

from signetry_core import is_policy_placeholder
from signetry_core.cli import main as cli_main
from signetry_core.pipeline.contract import evaluate_contract, load_contract
from signetry_core.policy_registry import (
    POLICY_DIR,
    REQUIRED_META,
    available_policies,
    load_policy,
    policy_ids,
)

ENTRIES = available_policies()
IDS = [e.id for e in ENTRIES]

# Fail loudly if the registry is empty. Every per-policy test below is parametrized over
# ENTRIES, so an empty registry would make this whole file vacuously green — the exact
# "no evidence reads as success" failure the project exists to prevent.
def test_the_registry_is_not_empty():
    assert ENTRIES, f"no policies found in {POLICY_DIR}"


def test_every_yaml_file_in_the_dir_is_a_loadable_entry():
    """A file that fails to parse must not be silently skipped."""
    on_disk = {p.stem for p in POLICY_DIR.glob("*.yaml")}
    assert on_disk == set(IDS), f"unloadable or unlisted policy files: {on_disk ^ set(IDS)}"


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_metadata_is_complete(entry):
    for key in REQUIRED_META:
        assert getattr(entry, key), f"{entry.id}: empty required metadata {key!r}"
    assert entry.id == entry.path.stem


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_policy_enforces_something(entry):
    """A contract with no scope rules is a no-op that ``load_contract`` would silently
    replace with the default scope — so it would govern nothing while appearing to."""
    c = entry.contract
    assert c.allowed_paths or c.forbidden_paths, f"{entry.id}: declares no scope at all"
    assert c.max_files_changed > 0, f"{entry.id}: unbounded diff budget"


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_declared_blocks_are_actually_blocked(entry):
    """Each ``@policy blocks:`` path must be refused by the real evaluator."""
    for path in entry.blocks:
        result = evaluate_contract([path], entry.contract)
        assert not result.passed, (
            f"{entry.id} claims to block {path!r} but the contract admits it"
        )


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_declared_allows_are_actually_allowed(entry):
    """And each ``@policy allows:`` path must pass. This is the direction that catches an
    over-broad forbidden glob quietly making a policy useless."""
    for path in entry.allows:
        result = evaluate_contract([path], entry.contract)
        assert result.passed, (
            f"{entry.id} claims to allow {path!r} but the contract refuses it: "
            f"{'; '.join(result.violations)}"
        )


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_blocks_and_allows_do_not_overlap(entry):
    """A path in both lists means the policy's own documentation contradicts itself."""
    overlap = set(entry.blocks) & set(entry.allows)
    assert not overlap, f"{entry.id}: {overlap} declared as both blocked and allowed"


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_a_template_never_claims_declared_provenance(entry):
    """The registry must not hand an adopter a policy that already looks change-controlled.

    A shipped template with a real-looking ``policy_owner`` would make every receipt
    report ``policy_status: declared`` — asserting that a human owns rules nobody at the
    adopting org has read. Templates must resolve to ``placeholder``."""
    contract = entry.contract
    assert is_policy_placeholder(contract.policy_owner), (
        f"{entry.id}: policy_owner {contract.policy_owner!r} is not a recognised placeholder"
    )
    assert contract.policy_status()["status"] == "placeholder"


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_installing_a_policy_writes_it_byte_for_byte(tmp_path, entry):
    """``init --policy`` copies the published bytes. No templating, no merge, no rewrite —
    so an adopter can diff their installed file against the registry and get nothing."""
    assert cli_main(["init", str(tmp_path), "--policy", entry.id]) == 0
    dest = tmp_path / ".signetry" / "admission.yaml"
    assert dest.read_text(encoding="utf-8") == entry.text


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_an_installed_policy_survives_the_real_loader(tmp_path, entry):
    """The bytes we ship must round-trip through ``load_contract`` unchanged in meaning.

    This is what catches a policy that parses in isolation but gets its scope replaced by
    the default contract on load (the "present but empty" merge path)."""
    assert cli_main(["init", str(tmp_path), "--policy", entry.id]) == 0
    loaded = load_contract(tmp_path)
    assert loaded.source == "repo"
    assert loaded.allowed_paths == entry.contract.allowed_paths
    assert loaded.forbidden_paths == entry.contract.forbidden_paths
    assert loaded.max_files_changed == entry.contract.max_files_changed
    assert loaded.required_checks == entry.contract.required_checks
    # And the blocks it advertised still hold after a real load from disk.
    for path in entry.blocks:
        assert not evaluate_contract([path], loaded).passed


# --- loader behaviour --------------------------------------------------------


def test_load_policy_is_case_insensitive_and_trims():
    first = IDS[0]
    assert load_policy(f"  {first.upper()}  ").id == first


def test_unknown_policy_raises_and_names_the_valid_ids():
    with pytest.raises(KeyError) as exc:
        load_policy("no-such-policy")
    message = str(exc.value)
    assert "no-such-policy" in message
    for pid in IDS:
        assert pid in message


def test_policy_ids_matches_available_policies():
    assert policy_ids() == IDS


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_to_public_is_json_serializable(entry):
    import json

    payload = entry.to_public()
    json.loads(json.dumps(payload))
    assert payload["id"] == entry.id
    assert payload["contract"]["policy_status"]["status"] == "placeholder"


# --- CLI surface -------------------------------------------------------------


def test_policies_command_lists_every_entry(capsys):
    assert cli_main(["policies"]) == 0
    out = capsys.readouterr().out
    for entry in ENTRIES:
        assert entry.id in out
        assert entry.title in out


def test_policies_json_is_machine_readable(capsys):
    import json

    assert cli_main(["policies", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [p["id"] for p in payload["policies"]] == IDS


def test_init_with_unknown_policy_fails_without_writing(tmp_path, capsys):
    assert cli_main(["init", str(tmp_path), "--policy", "nope"]) == 2
    assert not (tmp_path / ".signetry" / "admission.yaml").exists()
    err = capsys.readouterr().err
    assert "nope" in err and IDS[0] in err


def test_init_prints_the_caution_when_a_policy_carries_one(tmp_path, capsys):
    """A policy that documents a risk must surface it at the moment of adoption, not only
    in a file the adopter may never reopen."""
    cautioned = [e for e in ENTRIES if e.caution]
    assert cautioned, "expected at least one policy to carry a @policy caution"
    entry = cautioned[0]
    assert cli_main(["init", str(tmp_path), "--policy", entry.id]) == 0
    out = capsys.readouterr().out
    assert "CAUTION" in out
    assert entry.caution.split(".")[0][:40] in out


def test_init_tells_the_adopter_the_policy_is_unowned(tmp_path, capsys):
    assert cli_main(["init", str(tmp_path), "--policy", IDS[0]]) == 0
    out = capsys.readouterr().out
    assert "policy_owner" in out


def test_init_without_a_policy_still_writes_the_starter(tmp_path):
    """The registry is additive — the bare `signetry init` path is unchanged."""
    assert cli_main(["init", str(tmp_path)]) == 0
    text = (tmp_path / ".signetry" / "admission.yaml").read_text()
    assert "task_type: dependency-remediation" in text
    assert "@policy" not in text


def test_policy_respects_force_like_the_starter_does(tmp_path):
    assert cli_main(["init", str(tmp_path), "--policy", IDS[0]]) == 0
    assert cli_main(["init", str(tmp_path), "--policy", IDS[-1]]) == 1  # refuses to clobber
    assert cli_main(["init", str(tmp_path), "--policy", IDS[-1], "--force"]) == 0
    assert (tmp_path / ".signetry" / "admission.yaml").read_text() == load_policy(IDS[-1]).text
