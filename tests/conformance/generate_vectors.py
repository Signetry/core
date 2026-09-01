#!/usr/bin/env python3
"""Regenerate the RECEIPT_SPEC conformance vectors in ``vectors/``.

Run from the repository root::

    python tests/conformance/generate_vectors.py

The vectors are committed rather than generated at test time on purpose: a
conformance suite that computes its own expected values cannot detect a change in
how those values are computed. Committed vectors turn any change to the
canonicalization or signing rules into a visible diff, which is exactly what
RECEIPT_SPEC §9's change contract requires.

The two test keys are derived from published seed strings so an independent
implementation can regenerate these files byte for byte. They are TEST keys. Do
not sign anything real with them.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path(__file__).parent / "vectors"

SEED_LABEL_A = b"signetry-conformance-vector-key-A"
SEED_LABEL_B = b"signetry-conformance-vector-key-B"


def canonical(payload: dict) -> str:
    # Must match signetry_core.pipeline.receipt._canonical exactly. Duplicated
    # here, not imported, so the vectors are not silently redefined by a change to
    # the implementation — see RECEIPT_SPEC §5.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def sha256_tagged(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def keypair(label: bytes) -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label).digest())
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, base64.b64encode(raw).decode()


KEY_A, PUB_A = keypair(SEED_LABEL_A)
KEY_B, PUB_B = keypair(SEED_LABEL_B)

RECEIPT = {
    "kind": "signetry.remediation-receipt",
    "version": 1,
    "generated_at": "2026-08-31T12:00:00+00:00",
    "repo": "Signetry/conformance",
    "base_commit": "0" * 40,
    "executor": "none",
    "policy_hash": "sha256:" + "a" * 64,
    "diff_hash": "sha256:" + "b" * 64,
    "authority_level": 2,
    "authority": "branch_pr_only",
    "outcome": "Conformance fixture — not a real remediation.",
    "auto_merge": False,
    "human_review_required": True,
}


def envelope(receipt: dict, key: Ed25519PrivateKey, public_key: str, *,
             drop_hash: bool = False, ephemeral: bool = False) -> dict:
    text = canonical(receipt)
    env = {
        "receipt": receipt,
        "canonical_hash": sha256_tagged(text),
        "signature": base64.b64encode(key.sign(text.encode("utf-8"))).decode(),
        "public_key": public_key,
        "algorithm": "Ed25519",
        "key_ephemeral": ephemeral,
    }
    if drop_hash:
        del env["canonical_hash"]
    return env


def write(name: str, obj: dict, note: str) -> None:
    obj = {**obj, "_note": note}
    (OUT / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    print(f"  {name}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    canon_payload = {
        "zeta": 1,
        "alpha": {"nested_z": True, "nested_a": [3, 2, 1]},
        "unicode": "receipt — Ünïcödé ✓ 日本語",
        "empty": {},
        "null": None,
    }
    text = canonical(canon_payload)
    write("canonicalization.json", {
        "payload": canon_payload,
        "expected_canonical": text,
        "expected_canonical_hash": sha256_tagged(text),
    }, "Keys MUST sort recursively; no whitespace; Unicode emitted raw, NOT "
       "\\uXXXX-escaped. A serializer that escapes non-ASCII produces a different "
       "hash and fails here.")

    write("valid.json", {
        "envelope": envelope(RECEIPT, KEY_A, PUB_A),
        "pinned_public_key": PUB_A,
        "expect": {"verified": True, "hash_matches": True, "signature_valid": True,
                   "key_matches_pinned": True, "conforming": True},
    }, "The happy path. Verifies against the pinned key.")

    tampered = {**RECEIPT, "authority_level": 3}
    env = envelope(RECEIPT, KEY_A, PUB_A)
    env["receipt"] = tampered
    write("tampered-payload.json", {
        "envelope": env,
        "pinned_public_key": PUB_A,
        "expect": {"verified": False, "hash_matches": False, "signature_valid": False},
    }, "authority_level escalated 2 -> 3 after signing. MUST NOT verify.")

    write("resigned-other-key.json", {
        "envelope": envelope(RECEIPT, KEY_B, PUB_B),
        "pinned_public_key": PUB_A,
        "expect": {"verified": False, "signature_valid": False, "key_matches_pinned": False},
    }, "Attacker minted their own keypair and signed a plausible receipt. Every hash "
       "matches and the signature verifies against the EMBEDDED key. It MUST still "
       "fail against the pinned key. An implementation that verifies against "
       "envelope.public_key passes the other vectors and fails here.")

    write("no-canonical-hash.json", {
        "envelope": envelope(RECEIPT, KEY_A, PUB_A, drop_hash=True),
        "pinned_public_key": PUB_A,
        "expect": {"verified": False, "hash_matches": False},
    }, "Signature is genuine but canonical_hash was stripped. An absent hash is NOT "
       "a pass.")

    write("ephemeral-no-pinned-key.json", {
        "envelope": envelope(RECEIPT, KEY_A, PUB_A, ephemeral=True),
        "pinned_public_key": None,
        "expect": {"verified": False, "refused": True},
    }, "key_ephemeral is true and the verifier was given no key to pin. Verifying "
       "here proves nothing, so the verifier MUST refuse and say why rather than "
       "return a green result.")

    write("auto-merge-true.json", {
        "envelope": envelope({**RECEIPT, "auto_merge": True}, KEY_A, PUB_A),
        "pinned_public_key": PUB_A,
        "expect": {"signature_valid": True, "conforming": False},
    }, "Correctly signed, but auto_merge violates a signed invariant. The signature "
       "is valid AND the receipt MUST be rejected as non-conforming. These are "
       "separate checks.")

    (OUT / "keys.json").write_text(json.dumps({
        "_note": "TEST keys only. Seeds are published so vectors are reproducible. "
                 "Never use these to sign anything real.",
        "key_A": {"seed": "sha256('signetry-conformance-vector-key-A')", "public_key": PUB_A},
        "key_B": {"seed": "sha256('signetry-conformance-vector-key-B')", "public_key": PUB_B},
    }, indent=2) + "\n")
    print("  keys.json")


if __name__ == "__main__":
    main()
