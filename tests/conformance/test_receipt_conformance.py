"""Conformance suite for the Signetry Remediation Receipt format (RECEIPT_SPEC v1).

This suite is deliberately written against the *specification*, not against the
implementation's internals. It reads static JSON vectors from ``vectors/`` and
asserts the outcomes the spec mandates. Two consequences follow, and both are the
point:

1. **Any implementation can use it.** The vectors are language-agnostic JSON with
   published test-key seeds. A Rust or Go verifier can be checked against exactly
   these files. This directory and the spec are Apache-2.0 even though the engine
   is not — see LICENSING.md.
2. **A passing signature is not a passing receipt.** Several vectors are correctly
   signed and still MUST fail, because the format forbids what they claim. An
   implementation that only checks cryptography fails here, which is the whole
   reason the suite exists.

Regenerate the vectors with ``python tests/conformance/generate_vectors.py``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from signetry_core.pipeline.receipt import (
    _canonical,
    _sha256,
    check_invariants,
    verify_receipt,
)

VECTORS = Path(__file__).parent / "vectors"


def vector(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text())


# --- §5 Canonicalization -----------------------------------------------------


def test_canonicalization_matches_the_published_vector():
    """The canonical form is byte-exact, or receipts do not survive a round trip.

    This vector carries non-ASCII text and deliberately out-of-order keys. The most
    common way to fail it is a JSON serializer that escapes non-ASCII to \\uXXXX by
    default (Python's ``json.dumps`` does) — that produces different bytes, a
    different hash, and a signature nobody else can check.
    """
    v = vector("canonicalization")
    assert _canonical(v["payload"]) == v["expected_canonical"]
    assert _sha256(v["expected_canonical"]) == v["expected_canonical_hash"]


def test_canonicalization_is_order_independent():
    """Two dicts with the same content in different insertion orders canonicalize
    identically — otherwise the hash would depend on how the issuer happened to
    build the object."""
    a = {"z": 1, "a": {"y": 2, "b": 3}}
    b = {"a": {"b": 3, "y": 2}, "z": 1}
    assert _canonical(a) == _canonical(b)


# --- §8 Verification ---------------------------------------------------------


def test_valid_receipt_verifies_against_the_pinned_key():
    v = vector("valid")
    result = verify_receipt(v["envelope"], expected_public_key=v["pinned_public_key"])
    assert result["verified"] is True
    assert result["signature_valid"] is True
    assert result["hash_matches"] is True
    assert result["key_matches_pinned"] is True
    assert result["conforming"] is True


def test_tampered_payload_does_not_verify():
    """One field edited after signing (authority_level 2 -> 3). Both the hash and
    the signature must catch it."""
    v = vector("tampered-payload")
    result = verify_receipt(v["envelope"], expected_public_key=v["pinned_public_key"])
    assert result["verified"] is False
    assert result["hash_matches"] is False
    assert result["signature_valid"] is False


def test_receipt_signed_by_another_key_does_not_verify(capsys):
    """§8.1, the load-bearing rule.

    This envelope is *internally perfect*: the hash matches, the signature verifies
    against ``envelope['public_key']``, nothing is malformed. It was simply signed
    by someone else's keypair. An implementation that verifies against the embedded
    key passes every other test in this file and reports this forgery as valid.
    """
    v = vector("resigned-other-key")
    result = verify_receipt(v["envelope"], expected_public_key=v["pinned_public_key"])
    assert result["verified"] is False
    assert result["signature_valid"] is False
    assert result["key_matches_pinned"] is False

    # Prove the envelope really is self-consistent, so the failure above is
    # attributable to key pinning and nothing else.
    embedded = v["envelope"]["public_key"]
    self_consistent = verify_receipt(v["envelope"], expected_public_key=embedded)
    assert self_consistent["verified"] is True


def test_missing_canonical_hash_is_not_a_pass():
    """The signature here is genuine; the hash was stripped. Absence of evidence
    must not read as evidence — no hash, not verified."""
    v = vector("no-canonical-hash")
    result = verify_receipt(v["envelope"], expected_public_key=v["pinned_public_key"])
    assert result["hash_matches"] is False
    assert result["verified"] is False


def test_ephemeral_key_with_no_pinned_key_is_refused(monkeypatch):
    """§8.1 fail-closed. The dev seed is published in the source tree, so verifying
    against it proves nothing. The verifier must refuse and say why rather than
    return a green result a reader would misread as proof."""
    monkeypatch.delenv("SIGNETRY_SIGNING_KEY", raising=False)
    v = vector("ephemeral-no-pinned-key")
    result = verify_receipt(v["envelope"])  # no pinned key on purpose
    assert result["verified"] is False
    assert result["key_ephemeral"] is True
    assert "refus" in result["reason"].lower()


# --- §4.3 Invariants ---------------------------------------------------------


def test_auto_merge_true_is_non_conforming_despite_a_valid_signature():
    """The separation the spec insists on: cryptography and conformance are
    different questions. This receipt is signed correctly and must still be
    rejected, because the format does not permit what it says."""
    v = vector("auto-merge-true")
    result = verify_receipt(v["envelope"], expected_public_key=v["pinned_public_key"])
    assert result["signature_valid"] is True
    assert result["hash_matches"] is True
    assert result["conforming"] is False
    assert any("auto_merge" in m for m in result["invariant_violations"])


@pytest.mark.parametrize(
    ("mutation", "expected_fragment"),
    [
        ({"auto_merge": True}, "auto_merge"),
        ({"human_review_required": False}, "human_review_required"),
        ({"kind": "something.else"}, "kind"),
        ({"version": 2}, "version"),
        ({"authority_level": 4}, "authority_level"),
        ({"authority_level": "2"}, "authority_level"),
    ],
)
def test_each_invariant_is_enforced(mutation, expected_fragment):
    receipt = dict(vector("valid")["envelope"]["receipt"])
    assert check_invariants(receipt) == []  # baseline is conforming
    receipt.update(mutation)
    violations = check_invariants(receipt)
    assert any(expected_fragment in m for m in violations), violations


def test_issued_receipts_are_conforming_by_construction():
    """Whatever the pipeline is asked to do, it cannot emit a receipt that claims
    self-merge authority — the invariant is set at construction, inside the signed
    payload."""
    from signetry_core.pipeline.receipt import build_receipt

    envelope = build_receipt(
        repo="Signetry/conformance",
        base_commit="0" * 40,
        contract={},
        contract_result={"ok": True},
        verifier=None,
        trust_boundary=None,
        proposed_change=None,
        providers=None,
        authority_level=0,
        authority="analyze",
    )
    assert check_invariants(envelope["receipt"]) == []
    assert envelope["receipt"]["auto_merge"] is False
    assert envelope["receipt"]["human_review_required"] is True


# --- Vector hygiene ----------------------------------------------------------


def test_every_vector_is_exercised():
    """A vector nobody asserts on is decoration. If you add a file to vectors/,
    add a test and list it here."""
    covered = {
        "canonicalization", "valid", "tampered-payload", "resigned-other-key",
        "no-canonical-hash", "ephemeral-no-pinned-key", "auto-merge-true",
    }
    present = {p.stem for p in VECTORS.glob("*.json")} - {"keys"}
    assert present == covered, f"unexercised or missing vectors: {present ^ covered}"


def test_every_vector_documents_what_it_proves():
    for path in VECTORS.glob("*.json"):
        assert json.loads(path.read_text()).get("_note"), f"{path.name} has no _note"
