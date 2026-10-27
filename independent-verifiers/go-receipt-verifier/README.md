# go-receipt-verifier

An independent, standalone Go implementation of the verification algorithm in
[Signetry's `RECEIPT_SPEC.md` v1](https://github.com/Signetry/core/blob/main/docs/RECEIPT_SPEC.md).

This is **not** affiliated with, nor dependent on, `signetry-core`. It is written
purely against the published specification and checked against the Apache-2.0
conformance vectors in
[`tests/conformance/vectors/`](https://github.com/Signetry/core/tree/main/tests/conformance/vectors)
(copied verbatim into [`testdata/vectors/`](./testdata/vectors) here — they are
static JSON fixtures, not code, so copying them creates no dependency).

A Signetry remediation receipt is a signed record of what an AI coding agent was
allowed to change and what evidence gated it. The spec is designed so a receipt
outlives the tool that issued it: anyone, in any language, should be able to verify
one with nothing but the spec, SHA-256, and Ed25519. This is that second
implementation, in Go.

## Why this exists

An implementation that only checks cryptography passes most of the conformance
suite and still fails the two vectors that matter most:

- **`resigned-other-key.json`** — a self-consistent envelope signed with the
  attacker's own keypair, with the embedded public key swapped to match. Every
  internal check passes. It must still fail against the *pinned* key, because
  verifying a signature against the key carried inside the same document is a
  no-op (RECEIPT_SPEC §8.1).
- **`auto-merge-true.json`** — a correctly, genuinely signed receipt that claims
  `auto_merge: true` is non-conforming. Signature validity and format
  conformance are separate questions.

This implementation checks both.

## Build

Requires Go 1.21+.

```bash
go build -o go-receipt-verifier ./cmd/go-receipt-verifier
```

## Usage

```bash
# From a file:
./go-receipt-verifier --public-key <base64-ed25519-public-key> receipt.json

# From stdin:
cat receipt.json | ./go-receipt-verifier --public-key <base64-ed25519-public-key>

# Machine-readable output:
./go-receipt-verifier --public-key <base64-key> --json receipt.json
```

`receipt.json` is the **envelope** object (`{"receipt": ..., "canonical_hash": ...,
"signature": ..., "public_key": ..., "algorithm": ..., "key_ephemeral": ...}`), not
the bare `receipt` payload.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | The receipt is verified **and** conforming. |
| `1` | The receipt is not verified, not conforming, or was refused outright. |
| `2` | Usage error — bad flags, unreadable file, malformed JSON. |

The `--public-key` flag is the **pinned key**, obtained out of band — this tool
never verifies a signature against the key embedded in the envelope being checked
(RECEIPT_SPEC §8.1). Omitting it is only useful to exercise the "refuse an
unpinnable receipt" path (see `ephemeral-no-pinned-key.json` below).

## Conformance results

Run against the 8 committed vectors in
[`testdata/vectors/`](./testdata/vectors) (identical to
`tests/conformance/vectors/` in `Signetry/core`):

```bash
go test ./...
```

| Vector | Result | Notes |
|---|---|---|
| `canonicalization.json` | ✅ pass | Reproduces the published canonical bytes and SHA-256 exactly — recursive key sort, no whitespace, raw (non-escaped) Unicode. |
| `valid.json` | ✅ pass | Verifies against the pinned key; `conforming: true`. |
| `tampered-payload.json` | ✅ pass | `authority_level` edited after signing (2 → 3): hash and signature both fail. |
| `resigned-other-key.json` | ✅ pass | **The load-bearing vector.** Fails against the pinned key despite being internally self-consistent (verified separately to confirm it *would* pass if checked against its own embedded key — proving the rejection is attributable to key pinning, not a bug). |
| `no-canonical-hash.json` | ✅ pass | Genuine signature, stripped hash → not verified. Absence of evidence is not evidence. |
| `ephemeral-no-pinned-key.json` | ✅ pass | No pinned key + `key_ephemeral: true` → refused outright, not reported green. |
| `auto-merge-true.json` | ✅ pass | Signature is genuinely valid; receipt is still rejected as non-conforming. |
| canonicalization order-independence (not a committed vector; internal check) | ✅ pass | Two maps with identical content built in different key orders canonicalize to identical bytes. |

All 8 vectors in `tests/conformance/vectors/` (plus `keys.json`, which carries no
`expect` block and is not itself a test) produce exactly the outcome their `expect`
block states.

## How canonicalization is implemented

RECEIPT_SPEC §5 requires: JSON keys sorted lexicographically and recursively, no
insignificant whitespace, and Unicode emitted raw (not `\uXXXX`-escaped). The spec's
implementer's note calls out that this is the step most languages get wrong by
default — Python needs `ensure_ascii=False`, and Go's `encoding/json` HTML-escapes
`<`, `>`, `&` (and U+2028/U+2029) unless you disable it.

This implementation ([`internal/receipt/receipt.go`](./internal/receipt/receipt.go)):

1. Decodes JSON with `json.Decoder.UseNumber()` so numeric literals (`1` vs `1.0`)
   round-trip exactly instead of collapsing through `float64`.
2. Relies on `encoding/json`'s built-in behavior of sorting every map's keys,
   recursively, and emitting compact (whitespace-free) output — both already match
   the spec for free.
3. Calls `Encoder.SetEscapeHTML(false)` so Unicode (and `<`, `>`, `&`) are emitted
   as raw UTF-8 bytes, matching §5 rule 3 exactly.

Verified against `canonicalization.json`, which deliberately includes out-of-order
keys and non-ASCII text (`"receipt — Ünïcödé ✓ 日本語"`).

## Licence

Apache-2.0 — see [`LICENSE`](./LICENSE). Matches the licence `RECEIPT_SPEC.md` and
`tests/conformance/` carry in `Signetry/core`, independent of that repository's
BUSL-1.1 licence for the rest of the engine.
