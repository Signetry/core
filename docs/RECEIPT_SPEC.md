# Signetry Remediation Receipt — Specification v1

**Status:** stable · **Kind:** `signetry.remediation-receipt` · **Version:** `1`
**Licence:** [Apache-2.0](../LICENSE-Apache-2.0.txt) — this specification and its
conformance suite are explicitly excluded from the engine's BUSL-1.1 `Licensed Work`
(see [`LICENSE`](../LICENSE)), so they carry no restriction and no Change Date.

---

## 0. Why this document exists

A coding agent proposed a change to your repository. Later — in code review, in an
incident, in an audit two years from now — someone has to answer:

1. **What was this agent allowed to do?**
2. **Did the checks actually run, or did something claim they did?**
3. **Can I detect if this record has been altered since?**

A pull-request description cannot answer those questions, because the thing that
wrote the description is the thing under scrutiny. A **receipt** answers them with
evidence that is verifiable *without* trusting, running, or licensing the tool that
produced it.

This specification is deliberately unencumbered. A receipt is meant to outlive the
tool that issued it: an auditor in 2032 must be able to verify a receipt written in
2026 with nothing but this document, a SHA-256 implementation, and an Ed25519
verifier. If you want to write a competing issuer or an independent verifier, that is
a **supported** use, not a tolerated one.

## 1. Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY, and OPTIONAL
are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

- **Issuer** — the party producing and signing a receipt.
- **Verifier** — any party checking a receipt. A verifier need not be the issuer and
  MUST NOT be required to trust the issuer's software.
- **Envelope** — the outer object: the receipt plus its hash, signature and key material.
- **Receipt** — the signed payload: the accountability record itself.
- **Pinned key** — an Ed25519 public key the verifier obtained **out of band**, not
  from the envelope.

## 2. Threat model

The receipt is designed against a specific adversary: **the agent, and the tooling
around it, may misreport what happened.** Concretely:

| Attack | Defence in this spec |
|---|---|
| Agent claims checks passed when they never ran | `checks` and `baseline_checks` are inside the signed payload; §7 G2 passes only on evidence of real execution |
| Agent edits the receipt after the fact | Signature over canonical JSON (§5, §6); any byte change invalidates it |
| Attacker mints a plausible receipt with their own keypair | Verification is against a **pinned** key, never the embedded one (§8) |
| Attacker strips the signature and presents an unsigned record | A receipt with no `canonical_hash` or no valid signature is NOT verified (§8) |
| Issuer signs with a key whose seed is publicly known | `key_ephemeral` MUST be declared; §7 G3 fails on an ephemeral key |
| Change quietly grants itself merge rights | `auto_merge` and `human_review_required` are invariants *inside* the signed payload (§4.3) |
| Agent widens its own permissions mid-run | `contract` + `policy_hash` are signed; §7 G1 binds the change to a pre-bound plan |

**Explicit non-goals.** A receipt does not prove the change is *correct*, that the
code is *secure*, or that a human read it. It proves what authority was earned, on
what evidence, under what policy — and that the record has not been altered.

## 3. Envelope

The envelope is a JSON object. REQUIRED members:

| Member | Type | Meaning |
|---|---|---|
| `receipt` | object | The signed payload (§4). |
| `canonical_hash` | string | `"sha256:" + hex` of the canonical serialization of `receipt` (§5). |
| `signature` | string | Base64 Ed25519 signature over the canonical serialization (§6). |
| `public_key` | string | Base64 of the raw 32-byte Ed25519 public key. Informational only — a verifier MUST NOT trust it (§8). |
| `algorithm` | string | `"Ed25519"`. |
| `key_ephemeral` | boolean | `true` when signed with a key whose seed is not a managed secret. |

OPTIONAL:

| Member | Type | Meaning |
|---|---|---|
| `gates` | object | The G1/G2/G3 summary (§7). Computed over the envelope, so it is deliberately **outside** the signed payload — G3 depends on the signature itself. |

## 4. Receipt payload

### 4.1 Identity and provenance

| Field | Type | Notes |
|---|---|---|
| `kind` | string | MUST be `"signetry.remediation-receipt"`. |
| `version` | number | MUST be `1` for this specification. |
| `generated_at` | string | RFC 3339 / ISO 8601 timestamp, UTC. |
| `repo` | string | Repository identifier. |
| `base_commit` | string \| null | The commit the change was computed against. |
| `executor` | string \| null | The agent that drafted the change (e.g. `codex-cli`, `claude-code`). |
| `model_identity` | object \| null | Model provenance as reported by the executor. |
| `provider_ledger` | object | Every external provider consulted during the run. |

### 4.2 Authority and evidence

| Field | Type | Notes |
|---|---|---|
| `contract` | object | The change contract that applied (§9). |
| `policy_hash` | string \| null | Hash of that contract, so the governing policy is pinned. |
| `contract_result` | object | Whether the change stayed inside the contract. |
| `trust_boundary` | object \| null | What untrusted repository text was quarantined before the agent read it. |
| `verifier` | object \| null | An independent verification of the result, not the agent's own claim. |
| `checks` | object \| null | The checks that actually ran, and their outcomes. |
| `baseline_checks` | object \| null | The same checks on the unmodified tree, so a change cannot earn authority by *weakening* an already-failing check. |
| `check_diagnosis` | object \| null | Why a check failed, when it did. |
| `context_manifest` | object \| null | What the agent was allowed to see. |
| `plan_capability_set` | object \| null | Capabilities bound *before* the run. |
| `plan_adherence` | object \| null | Whether the change stayed within that plan. |
| `proposed_change` | object \| null | Change summary. |
| `diff_hash` | string \| null | `"sha256:" + hex` of the exact diff, binding the change without embedding it. |
| `authority_level` | number | Earned level, `0`–`3` (§10). |
| `authority` | string | Symbolic authority, e.g. `branch_pr_only`. |

### 4.3 Outcome and invariants

| Field | Type | Notes |
|---|---|---|
| `human_decision` | string \| null | Recorded human disposition, if any. |
| `pr_url` | string \| null | Where the change was proposed. |
| `outcome` | string \| null | Human-readable summary. |
| `auto_merge` | boolean | **Invariant: MUST be `false`.** |
| `human_review_required` | boolean | **Invariant: MUST be `true`.** |

The two invariants live *inside the signed payload* on purpose. They cannot be
quietly dropped or flipped without invalidating the signature — so "Signetry never
merges on its own judgement" is a checkable property of every receipt, not a promise
in a README.

A verifier encountering `auto_merge: true` MUST treat the receipt as
**non-conforming**, regardless of signature validity.

## 5. Canonicalization

The signature and hash are computed over a canonical serialization of the `receipt`
object. An issuer MUST produce, and a verifier MUST recompute, exactly this form:

1. JSON object keys sorted lexicographically, recursively (`sort_keys=true`).
2. No insignificant whitespace: item separator `,`, key separator `:`.
3. Unicode NOT escaped — emit characters directly (`ensure_ascii=false`), UTF-8 encoded.
4. Values that are not natively JSON-serializable are rendered as their string form.

Reference (Python):

```python
json.dumps(receipt, sort_keys=True, separators=(",", ":"),
           default=str, ensure_ascii=False)
```

> **Implementer's note.** Rule 3 is the one that bites. A serializer that escapes
> non-ASCII by default (Python's `json.dumps` without `ensure_ascii=False`, Go's
> `encoding/json` for HTML-sensitive bytes) produces a *different byte string* and
> therefore a different hash. Compare against the test vectors in §11 before
> trusting your implementation.

`canonical_hash` is then `"sha256:"` followed by the lowercase hex SHA-256 digest of
the UTF-8 bytes of that string.

## 6. Signing

The signature is Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) over the
**UTF-8 bytes of the canonical string** — not over the hash, and not over
pretty-printed JSON. It is base64-encoded (standard alphabet, with padding).

Because the canonical payload binds `base_commit`, `diff_hash`, `checks`,
`verifier`, `contract`, and `model_identity`, signing transitively binds all of them.

Issuers MUST declare `key_ephemeral: true` whenever the signing key is derived from a
value that is not a managed secret — for example a deterministic development
fallback. An ephemeral key produces a structurally valid signature that proves
nothing about provenance, and §7 G3 MUST fail for it.

## 7. Proof gates

`gates` distils the evidence into three questions, each reported as `pass`, `fail`, or
`unproven`. **A gate MUST NOT report `pass` on missing evidence** — absent evidence is
`unproven`, never green.

| Gate | Question | Passes only when |
|---|---|---|
| **G1 — Capability integrity** | What was this agent allowed to do? | A plan was bound *before* the run and the change stayed within it; contract hash present. |
| **G2 — Behavioural authenticity** | Did the checks and sandbox actually run? | The contract's required checks genuinely ran under real isolation and passed. A host-restricted or unavailable sandbox does NOT pass — it reports honestly. |
| **G3 — Interaction auditability** | Is the history tamper-evident? | The signature verifies **and** the signing key is non-ephemeral. |

Gates are computed over the envelope rather than inside the receipt because G3
depends on the signature, which cannot exist inside the payload it signs.

## 8. Verification algorithm

A conforming verifier, given an envelope and OPTIONALLY a pinned public key:

1. If `receipt` is absent or not an object, or `signature` is absent → **not verified**.
2. **Determine the key to verify against.** Use the pinned key if supplied.
   If no pinned key is supplied *and* the issuing instance would sign with an
   ephemeral key, the verifier MUST **refuse to verify** and say why. Verifying a
   receipt against a key whose seed is public proves nothing, and returning "valid"
   there would be actively misleading.
3. Recompute the canonical serialization of `receipt` (§5) and its SHA-256 (§5).
4. `hash_matches` = `canonical_hash` is present **and** equals the recomputed hash.
   An envelope carrying no `canonical_hash` MUST NOT be treated as verified.
5. `signature_valid` = Ed25519 verification of `signature` over the canonical bytes
   **against the pinned key** — never against `envelope.public_key`.
6. `verified` = `signature_valid` **AND** `hash_matches`.
7. Report `key_matches_pinned` = whether the embedded key equals the pinned key. This
   is diagnostic: a mismatch means the receipt was issued by a different key than the
   one you trust.
8. Reject as non-conforming if `auto_merge` is `true` or `human_review_required` is
   `false` (§4.3).

Verification MUST NOT raise on malformed input; it returns a negative result with a
reason. A verifier that throws on hostile input is a denial-of-service surface.

### 8.1 The pinned-key rule

This is the single most important rule in the specification, and the easiest to get
wrong:

> **A verifier MUST NOT verify a receipt's signature against the public key contained
> in that same receipt.**

An attacker can generate a keypair, mint an internally consistent envelope claiming
whatever authority they like, and embed their own public key. Every hash will match
and the signature will verify — against *their* key. Self-consistency is not
provenance. The key MUST come from somewhere the attacker does not control.

## 9. Change contract

The `contract` object records the policy in force. A v1 contract carries
`version`, `task_type`, `allowed_paths`, `forbidden_paths`, `max_files_changed`,
`required_checks`, `network`, and `authority_on_success`.

A v2 contract MAY additionally carry a **capability graph**: `allowed_tools`,
`denied_bash`, `allowed_mcp`, `allowed_skills`. These are additive and may only
**restrict**. An empty or absent list means "no additional restriction from this
class" and MUST NOT be interpreted as a widening. Provenance fields
(`policy_owner`, `policy_version`, `policy_approved_at`) are OPTIONAL; when absent
the policy MUST be treated as unsigned and surfaced as such, never silently trusted.

## 10. Authority ladder

| Level | Meaning |
|---|---|
| **L0** | No authority. Analysis only. |
| **L1** | Advisory. May report, may not propose a change for merge. |
| **L2** | `branch_pr_only`. May open a branch and a pull request. **Never merges.** |
| **L3** | Reserved for higher authority; requires evidence beyond L2 and is not granted by the default pipeline. |

Authority is *earned on evidence*, never asserted. A change that weakens a
previously-passing check MUST NOT earn a higher level than one that does not.

## 11. Conformance

An implementation is **conforming** if it satisfies every MUST here and reproduces the
test vectors in `tests/conformance/` — which include:

- a canonicalization vector with non-ASCII content and keys deliberately out of order
- a valid envelope that MUST verify against a supplied pinned key
- the same envelope with one byte of `receipt` changed, which MUST NOT verify
- an envelope whose `signature` was re-signed with a different key, which MUST NOT
  verify against the pinned key (§8.1)
- an envelope with `canonical_hash` removed, which MUST NOT be treated as verified
- an ephemeral-key envelope with no pinned key, which MUST be refused rather than
  reported valid
- an envelope with `auto_merge: true`, which MUST be rejected as non-conforming

The vectors are language-agnostic JSON with published test-key seeds, and
`tests/conformance/` is **Apache-2.0 even though the engine is BUSL-1.1** — an
independent verifier in any language can be checked against exactly those files. See
[`tests/conformance/README.md`](../tests/conformance/README.md) for the per-vector
table and the key-derivation strings.

Run the suite against the reference implementation:

```
python -m pytest tests/conformance/ -q
```

Or check a single receipt from the command line:

```
signetry verify <receipt.json> --public-key <base64-key>
```

`signetry verify` exits non-zero when the signature does not verify against the
supplied key **or** when the payload breaks a §4.3 invariant, and prints which of the
two failed. A receipt that is correctly signed but non-conforming reports both —
never a bare `VERIFIED`.

## 12. Versioning

`version` is incremented only for a change that would make an existing conforming
verifier reject a valid receipt. Adding an OPTIONAL field is not such a change, so
verifiers MUST ignore unknown members rather than reject them. A verifier
encountering a `version` it does not implement MUST report that clearly instead of
guessing.

`kind` is stable and MUST NOT be reused for an incompatible record type.
