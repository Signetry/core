// Package receipt is an independent, dependency-free implementation of the
// verification algorithm in Signetry's RECEIPT_SPEC v1 (docs/RECEIPT_SPEC.md
// in https://github.com/Signetry/core). It is written purely against the
// published specification and its Apache-2.0 conformance vectors — it does
// not import, vendor, or otherwise depend on signetry-core.
package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// ReceiptKind is the only `kind` value RECEIPT_SPEC §4.1 permits.
const ReceiptKind = "signetry.remediation-receipt"

// ReceiptVersion is the only `version` this implementation understands.
// RECEIPT_SPEC §12: a verifier encountering a version it does not implement
// MUST report that clearly instead of guessing.
const ReceiptVersion = 1

// DecodeJSON decodes JSON into a generic interface{}, preserving the exact
// numeric literal of every number as json.Number rather than normalizing it
// to float64. This matters for canonicalization (§5): Python's json
// round-trips `1` as the int `1` and `1.0` as the float `1.0`, re-emitting
// each in its original form. Decoding straight to float64 would collapse
// that distinction and silently produce different canonical bytes — and a
// different hash — for numerically-equal-but-differently-written inputs.
func DecodeJSON(data []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Canonical renders v as the RECEIPT_SPEC §5 canonical serialization:
//
//  1. JSON object keys sorted lexicographically, recursively.
//  2. No insignificant whitespace (item separator `,`, key separator `:`).
//  3. Unicode NOT escaped — raw UTF-8 bytes, not \uXXXX.
//
// encoding/json already sorts every map's keys (recursively, by Go string
// comparison — byte-wise over UTF-8, which agrees with Python's code-point
// ordering for valid UTF-8) and already emits compact output with `,`/`:`
// separators, so (1) and (2) are free. (3) is the one that bites: by
// default encoding/json HTML-escapes `<`, `>`, `&` (and U+2028/U+2029) to
// \u-sequences. That is NOT the same thing the spec's warning is about
// (Python's ensure_ascii, which would escape *all* non-ASCII, like “—” or
// “日本語”) — plain non-ASCII runes already pass through encoding/json
// untouched. But to emit *raw* Unicode with no conditional escaping at all,
// as §5 rule 3 requires, we still disable the HTML-escaping pass.
func Canonical(v interface{}) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; the canonical form has
	// none.
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// Sha256Tagged returns "sha256:" followed by the lowercase hex SHA-256
// digest of the UTF-8 bytes of text, per RECEIPT_SPEC §5.
func Sha256Tagged(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifySignature checks an Ed25519 signature (base64, standard alphabet)
// over canonicalText against a base64-encoded raw 32-byte public key. It
// never panics on malformed input (RECEIPT_SPEC §8: "Verification MUST NOT
// raise on malformed input; it returns a negative result with a reason");
// any decoding failure or key/signature of the wrong length is treated as
// signature_valid = false, not an error.
func VerifySignature(canonicalText, signatureB64, publicKeyB64 string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(canonicalText), sig)
}

// asExactInt reports whether v (as decoded by DecodeJSON) is a JSON number
// written as a whole integer literal (no decimal point, no exponent), and
// returns that integer. "2.0" or "2e0" are JSON numbers but not exact
// integers in this sense — mirroring Python, where json.loads("2.0") yields
// a float, and `isinstance(2.0, int)` is false.
func asExactInt(v interface{}) (int64, bool) {
	num, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := num.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}

// CheckInvariants returns the RECEIPT_SPEC §4.3 invariant violations found
// in receipt (an empty slice means conforming). These are deliberately
// independent of signature validity: a receipt can be signed perfectly and
// still be non-conforming, e.g. an issuer that set auto_merge: true has
// signed a claim the format does not permit.
func CheckInvariants(r map[string]interface{}) []string {
	var violations []string

	if kind, _ := r["kind"].(string); kind != ReceiptKind {
		violations = append(violations, fmt.Sprintf("kind must be %q (got %#v)", ReceiptKind, r["kind"]))
	}
	if v, ok := asExactInt(r["version"]); !ok || v != ReceiptVersion {
		violations = append(violations, fmt.Sprintf("version must be 1 (got %#v)", r["version"]))
	}
	if b, ok := r["auto_merge"].(bool); !ok || b != false {
		violations = append(violations, "auto_merge must be false (RECEIPT_SPEC §4.3)")
	}
	if b, ok := r["human_review_required"].(bool); !ok || b != true {
		violations = append(violations, "human_review_required must be true (RECEIPT_SPEC §4.3)")
	}
	if level, ok := asExactInt(r["authority_level"]); !ok || level < 0 || level > 3 {
		violations = append(violations, fmt.Sprintf("authority_level must be an integer 0-3 (got %#v)", r["authority_level"]))
	}

	return violations
}

// Result is the outcome of Verify. Field names intentionally mirror the
// reference Python implementation's verify_receipt() so the two can be
// compared field-by-field against the same conformance vectors.
type Result struct {
	Verified            bool     `json:"verified"`
	SignatureValid      bool     `json:"signature_valid"`
	HashMatches         bool     `json:"hash_matches"`
	KeyMatchesPinned    bool     `json:"key_matches_pinned"`
	Conforming          bool     `json:"conforming"`
	InvariantViolations []string `json:"invariant_violations"`
	Refused             bool     `json:"refused"`
	KeyEphemeral        *bool    `json:"key_ephemeral,omitempty"`
	ComputedHash        string   `json:"computed_hash,omitempty"`
	ClaimedHash         string   `json:"claimed_hash,omitempty"`
	Reason              string   `json:"reason,omitempty"`
}

// Verify independently verifies a receipt envelope against pinnedKey.
//
// pinnedKey is a pointer so "no key supplied" (nil) is distinguishable from
// "supplied, empty string". Per RECEIPT_SPEC §8.1 — the single most
// important rule in the spec — this function NEVER verifies the signature
// against envelope["public_key"]; that field is informational only. If no
// pinnedKey is supplied, verification is refused outright rather than
// falling back to the embedded key, which would make verification a no-op
// (the attacker supplies both halves of the self-consistent pair).
func Verify(envelope map[string]interface{}, pinnedKey *string) Result {
	receiptRaw, hasReceipt := envelope["receipt"]
	receiptMap, isMap := receiptRaw.(map[string]interface{})
	sig, hasSig := envelope["signature"].(string)

	if !hasReceipt || !isMap || !hasSig || sig == "" {
		return Result{
			Conforming:          false,
			InvariantViolations: []string{"receipt or signature missing"},
			Reason:              "Receipt or signature missing.",
		}
	}

	keyEphemeral, _ := envelope["key_ephemeral"].(bool)

	// §8 step 2: no pinned key means there is nothing safe to verify
	// against — verifying against the embedded key is forbidden by §8.1,
	// and an ephemeral signing key's seed may be public, so even the
	// envelope's own claims about itself prove nothing. Refuse, don't
	// guess.
	if pinnedKey == nil {
		violations := CheckInvariants(receiptMap)
		reason := "No pinned public key supplied. RECEIPT_SPEC §8.1: a verifier MUST NOT " +
			"verify a signature against the public key embedded in the envelope being " +
			"checked — pass a public key obtained out of band."
		if keyEphemeral {
			reason = "Refusing to verify: key_ephemeral is true and no pinned public key " +
				"was supplied. The signing key's seed may be public, so a 'valid' result " +
				"here would be actively misleading. Supply a pinned key from a trusted " +
				"source to verify this receipt."
		}
		return Result{
			Refused:             true,
			KeyEphemeral:        &keyEphemeral,
			Conforming:          len(violations) == 0,
			InvariantViolations: violations,
			Reason:              reason,
		}
	}

	violations := CheckInvariants(receiptMap)

	canonical, err := Canonical(receiptMap)
	if err != nil {
		return Result{
			Conforming:          false,
			InvariantViolations: violations,
			Reason:              fmt.Sprintf("could not canonicalize receipt: %v", err),
		}
	}

	computedHash := Sha256Tagged(canonical)
	claimedHash, _ := envelope["canonical_hash"].(string)
	// An envelope carrying no canonical_hash MUST NOT be treated as
	// verified (§8 step 4) — absence of evidence is not evidence.
	hashMatches := claimedHash != "" && claimedHash == computedHash

	// Signature is checked against pinnedKey, never against
	// envelope["public_key"]. This is the §8.1 pinned-key rule.
	signatureValid := VerifySignature(canonical, sig, *pinnedKey)

	embeddedKey, _ := envelope["public_key"].(string)
	keyMatchesPinned := embeddedKey != "" && embeddedKey == *pinnedKey

	return Result{
		Verified:            signatureValid && hashMatches,
		SignatureValid:      signatureValid,
		HashMatches:         hashMatches,
		KeyMatchesPinned:    keyMatchesPinned,
		Conforming:          len(violations) == 0,
		InvariantViolations: violations,
		KeyEphemeral:        &keyEphemeral,
		ComputedHash:        computedHash,
		ClaimedHash:         claimedHash,
	}
}
