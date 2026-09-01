# Receipt conformance suite

Test vectors and assertions for the
[Signetry Remediation Receipt format](../../docs/RECEIPT_SPEC.md) (`version: 1`).

**This directory and `docs/RECEIPT_SPEC.md` are licensed
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), not BUSL-1.1 like the rest
of this repository.** That is deliberate. A receipt is meant to outlive the tool that
issued it — an auditor in 2032 should be able to verify a receipt written in 2026
without licensing anything from us. Writing a competing issuer or an independent
verifier against this spec is a supported use, not a tolerated one.

## Running it

```bash
python -m pytest tests/conformance/ -q
```

To regenerate the vectors after an intentional format change:

```bash
python tests/conformance/generate_vectors.py
```

The vectors are **committed, not generated at test time**. A suite that recomputes
its own expected values cannot notice a change in how those values are computed;
committed vectors turn any change to canonicalization or signing into a visible diff
— which is what [RECEIPT_SPEC §9](../../docs/RECEIPT_SPEC.md#9-change-contract)
requires. If a diff appears in `vectors/` and you did not intend a format change,
something regressed.

## Using it from another language

The vectors are plain JSON and the two test keys are derived from published seed
strings, so any implementation can be checked against exactly these files:

```
key_A seed = SHA-256("signetry-conformance-vector-key-A")   # 32 raw bytes
key_B seed = SHA-256("signetry-conformance-vector-key-B")
```

These are **test keys**. Their seeds are public on purpose. Never sign anything real
with them.

Each vector has an `expect` block (or, for `canonicalization.json`, the expected
output directly) and a `_note` explaining what it proves. A conforming
implementation reproduces every `expect`.

## The vectors

| Vector | What it proves |
|---|---|
| `canonicalization.json` | Canonical bytes are exact: recursive key sort, no whitespace, **raw Unicode**. The usual failure is a serializer that escapes non-ASCII by default — Python's `json.dumps` does, hence `ensure_ascii=False`. |
| `valid.json` | The happy path verifies against a pinned key. |
| `tampered-payload.json` | One field edited after signing (`authority_level` 2 → 3) fails both the hash and the signature. |
| `resigned-other-key.json` | **The load-bearing one.** A self-consistent envelope signed with the attacker's own keypair, embedded key swapped to match. Every internal check passes. It MUST still fail against the pinned key — see [§8.1](../../docs/RECEIPT_SPEC.md#81-the-pinned-key-rule). |
| `no-canonical-hash.json` | A genuine signature with the hash stripped is **not** verified. Absence of evidence is not evidence. |
| `ephemeral-no-pinned-key.json` | A dev-key receipt with no key to pin against must be **refused**, not reported green. The dev seed is in this source tree; verifying against it proves nothing. |
| `auto-merge-true.json` | A correctly signed receipt claiming `auto_merge: true` is **non-conforming**. Signature validity and format conformance are separate questions. |

## Why two of these matter more than the rest

An implementation that only checks cryptography passes most of this suite. It fails
`resigned-other-key.json` and `auto-merge-true.json`, and those two are where the
format's guarantees actually live:

- **Pin the key.** Verifying a signature against the public key carried inside the
  same document is a no-op — the attacker supplies both halves. Every real
  verification is against a key you obtained some other way.
- **A valid signature is not a valid receipt.** `auto_merge: false` and
  `human_review_required: true` are invariants *inside the signed payload*, so they
  cannot be flipped or dropped without breaking the signature. That makes "Signetry
  never merges on its own judgement" a checkable property of every receipt rather
  than a promise in a README — but only if the verifier actually checks it.
