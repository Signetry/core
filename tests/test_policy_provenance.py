"""Scaffold provenance must not read as declared provenance.

``signetry init`` writes ``policy_owner: your-team``. Before this was fixed,
``policy_status()`` reported ``declared`` — *"Policy declares a human owner and version
(change-controlled metadata)"* — for a file no human had read, so every receipt from a
freshly initialised repo asserted change-control that did not exist.

The rule these tests pin down: a placeholder is treated as **absent**. Not "probably
fine", not "close enough" — absent, with a distinct status saying why.
"""
from __future__ import annotations

import pytest

from signetry_core import is_policy_placeholder
from signetry_core.pipeline.contract import contract_from_dict


def _status(owner: str | None, version: str | None = "1.0") -> dict:
    payload = {"version": 2, "task_type": "feature-work", "allowed_paths": ["src/**"]}
    if owner is not None:
        payload["policy_owner"] = owner
    if version is not None:
        payload["policy_version"] = version
    return contract_from_dict(payload, source="test").policy_status()


# The exact string `signetry init` writes. If this ever reports `declared` again, the
# regression is back and every starter repo is lying in its receipts.
def test_the_string_signetry_init_writes_is_not_declared():
    assert _status("your-team")["status"] == "placeholder"


@pytest.mark.parametrize(
    "owner",
    [
        "your-team", "your-org", "YOUR-TEAM", "  your-team  ", "<your-team>",
        "[your-org]", "{your-team}", "TODO", "tbd", "changeme", "example",
        "acme-corp", "placeholder", "n/a", "unset", "signetry-registry",
    ],
)
def test_recognised_placeholder_forms(owner):
    """Case, surrounding whitespace and <>/[]{} wrappers must not defeat the check —
    those are exactly the forms a scaffold or a docs example uses."""
    assert is_policy_placeholder(owner)
    assert _status(owner)["status"] == "placeholder"


@pytest.mark.parametrize(
    "owner",
    ["platform-team", "security@acme.com", "Team Yourself", "org-infra", "sre"],
)
def test_a_real_owner_is_still_declared(owner):
    """The fix must not swallow legitimate owners. ``Team Yourself`` and ``org-infra``
    contain placeholder substrings; matching is on the whole value, not a substring,
    so they stay declared."""
    assert not is_policy_placeholder(owner)
    assert _status(owner)["status"] == "declared"


def test_missing_owner_is_incomplete_not_placeholder():
    """The three statuses are distinguishable: nothing declared is ``incomplete``,
    scaffold text is ``placeholder``. Collapsing them would lose the actionable part."""
    assert _status(None, None)["status"] == "incomplete"
    assert _status("platform-team", None)["status"] == "incomplete"


def test_every_status_explains_itself():
    """A consumer that surfaces the status to a human needs a note with it — otherwise
    ``placeholder`` is just a word and nobody knows what to do about it."""
    for owner, version in [("platform-team", "1.0"), ("your-team", "1.0"), (None, None)]:
        result = _status(owner, version)
        assert result["note"], f"{result['status']}: empty note"
        assert len(result["note"]) > 40

    placeholder_note = _status("your-team")["note"]
    assert "your-team" in placeholder_note      # names the offending value's shape
    assert "policy_owner" in placeholder_note   # and the field to fix


def test_placeholder_owner_is_still_reported_verbatim():
    """The receipt must not hide what the file actually said. The status is the judgement;
    ``owner`` stays the raw value so a reader can see the scaffold text for themselves."""
    result = _status("your-team")
    assert result["owner"] == "your-team"


def test_empty_and_whitespace_owners_are_not_placeholders_but_incomplete():
    """An empty value is absent, which is already handled by the ``incomplete`` path.
    ``is_policy_placeholder("")`` must not be True, or "" would end up in the set of
    things that look like scaffold text and the two cases would blur."""
    assert not is_policy_placeholder("")
    assert not is_policy_placeholder("   ")
    assert _status("")["status"] == "incomplete"
    assert _status("   ")["status"] == "incomplete"
