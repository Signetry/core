package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// vector loads tests/conformance/vectors/<name>.json, copied verbatim from
// https://github.com/Signetry/core (Apache-2.0: docs/RECEIPT_SPEC.md and
// tests/conformance/ are explicitly carved out of that repository's BUSL-1.1
// licence). These are static JSON fixtures, not code — copying them creates
// no dependency on signetry-core.
func vector(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", name+".json"))
	if err != nil {
		t.Fatalf("reading vector %s: %v", name, err)
	}
	decoded, err := DecodeJSON(data)
	if err != nil {
		t.Fatalf("decoding vector %s: %v", name, err)
	}
	v, ok := decoded.(map[string]interface{})
	if !ok {
		t.Fatalf("vector %s is not a JSON object", name)
	}
	return v
}

func envelopeOf(t *testing.T, v map[string]interface{}) map[string]interface{} {
	t.Helper()
	env, ok := v["envelope"].(map[string]interface{})
	if !ok {
		t.Fatalf("vector has no envelope object")
	}
	return env
}

func pinnedKeyOf(v map[string]interface{}) *string {
	raw, ok := v["pinned_public_key"]
	if !ok || raw == nil {
		return nil
	}
	s, ok := raw.(string)
	if !ok {
		return nil
	}
	return &s
}

// --- §5 Canonicalization -----------------------------------------------

func TestCanonicalizationMatchesThePublishedVector(t *testing.T) {
	v := vector(t, "canonicalization")
	payload, ok := v["payload"].(map[string]interface{})
	if !ok {
		t.Fatal("canonicalization vector missing payload object")
	}

	got, err := Canonical(payload)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	want, _ := v["expected_canonical"].(string)
	if got != want {
		t.Fatalf("canonical mismatch:\n got:  %q\n want: %q", got, want)
	}

	gotHash := Sha256Tagged(got)
	wantHash, _ := v["expected_canonical_hash"].(string)
	if gotHash != wantHash {
		t.Fatalf("canonical hash mismatch: got %s want %s", gotHash, wantHash)
	}
}

func TestCanonicalizationIsOrderIndependent(t *testing.T) {
	a := map[string]interface{}{"z": json1(1), "a": map[string]interface{}{"y": json1(2), "b": json1(3)}}
	b := map[string]interface{}{"a": map[string]interface{}{"b": json1(3), "y": json1(2)}, "z": json1(1)}
	ca, err := Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	if ca != cb {
		t.Fatalf("expected order-independent canonical form, got %q vs %q", ca, cb)
	}
}

// --- §8 Verification -----------------------------------------------------

func TestValidReceiptVerifiesAgainstThePinnedKey(t *testing.T) {
	v := vector(t, "valid")
	result := Verify(envelopeOf(t, v), pinnedKeyOf(v))
	if !result.Verified || !result.SignatureValid || !result.HashMatches || !result.KeyMatchesPinned || !result.Conforming {
		t.Fatalf("expected a fully verified, conforming receipt; got %+v", result)
	}
}

func TestTamperedPayloadDoesNotVerify(t *testing.T) {
	v := vector(t, "tampered-payload")
	result := Verify(envelopeOf(t, v), pinnedKeyOf(v))
	if result.Verified || result.HashMatches || result.SignatureValid {
		t.Fatalf("tampered payload must fail hash and signature; got %+v", result)
	}
}

// TestReceiptSignedByAnotherKeyDoesNotVerify is RECEIPT_SPEC §8.1, the
// load-bearing rule. This envelope is internally perfect — the hash
// matches, the signature verifies against envelope["public_key"], nothing
// is malformed. It was simply signed by someone else's keypair. An
// implementation that verifies against the embedded key passes every other
// test here and reports this forgery as valid.
func TestReceiptSignedByAnotherKeyDoesNotVerify(t *testing.T) {
	v := vector(t, "resigned-other-key")
	env := envelopeOf(t, v)

	result := Verify(env, pinnedKeyOf(v))
	if result.Verified || result.SignatureValid || result.KeyMatchesPinned {
		t.Fatalf("expected rejection against the pinned key; got %+v", result)
	}

	// Prove the envelope really is self-consistent, so the failure above is
	// attributable to key pinning and nothing else.
	embedded, _ := env["public_key"].(string)
	selfConsistent := Verify(env, &embedded)
	if !selfConsistent.Verified {
		t.Fatalf("expected the envelope to self-verify against its own embedded key (proving it's a well-formed forgery); got %+v", selfConsistent)
	}
}

func TestMissingCanonicalHashIsNotAPass(t *testing.T) {
	v := vector(t, "no-canonical-hash")
	result := Verify(envelopeOf(t, v), pinnedKeyOf(v))
	if result.HashMatches || result.Verified {
		t.Fatalf("an absent canonical_hash must never read as a match; got %+v", result)
	}
}

func TestEphemeralKeyWithNoPinnedKeyIsRefused(t *testing.T) {
	v := vector(t, "ephemeral-no-pinned-key")
	result := Verify(envelopeOf(t, v), nil) // no pinned key, on purpose
	if result.Verified {
		t.Fatalf("must not verify an ephemeral-keyed receipt with no pinned key; got %+v", result)
	}
	if !result.Refused {
		t.Fatalf("expected refused=true; got %+v", result)
	}
	if result.KeyEphemeral == nil || !*result.KeyEphemeral {
		t.Fatalf("expected key_ephemeral=true; got %+v", result)
	}
	if result.Reason == "" {
		t.Fatalf("a refusal must say why")
	}
}

// --- §4.3 Invariants -------------------------------------------------------

func TestAutoMergeTrueIsNonConformingDespiteAValidSignature(t *testing.T) {
	v := vector(t, "auto-merge-true")
	result := Verify(envelopeOf(t, v), pinnedKeyOf(v))
	if !result.SignatureValid {
		t.Fatalf("this vector's signature is genuinely valid; got %+v", result)
	}
	if result.Conforming {
		t.Fatalf("auto_merge: true MUST be rejected as non-conforming; got %+v", result)
	}
	if !containsSubstring(result.InvariantViolations, "auto_merge") {
		t.Fatalf("expected an auto_merge violation, got %v", result.InvariantViolations)
	}
}

func TestEachInvariantIsEnforced(t *testing.T) {
	v := vector(t, "valid")
	base := envelopeOf(t, v)["receipt"].(map[string]interface{})
	if got := CheckInvariants(base); len(got) != 0 {
		t.Fatalf("baseline receipt must be conforming, got violations: %v", got)
	}

	cases := []struct {
		name     string
		mutate   func(map[string]interface{})
		fragment string
	}{
		{"auto_merge true", func(r map[string]interface{}) { r["auto_merge"] = true }, "auto_merge"},
		{"human_review_required false", func(r map[string]interface{}) { r["human_review_required"] = false }, "human_review_required"},
		{"kind wrong", func(r map[string]interface{}) { r["kind"] = "something.else" }, "kind"},
		{"version wrong", func(r map[string]interface{}) { r["version"] = json1(2) }, "version"},
		{"authority_level out of range", func(r map[string]interface{}) { r["authority_level"] = json1(4) }, "authority_level"},
		{"authority_level not an int", func(r map[string]interface{}) { r["authority_level"] = "2" }, "authority_level"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipt := cloneMap(base)
			tc.mutate(receipt)
			violations := CheckInvariants(receipt)
			if !containsSubstring(violations, tc.fragment) {
				t.Fatalf("expected a %q violation, got %v", tc.fragment, violations)
			}
		})
	}
}

// --- helpers ---------------------------------------------------------------

func containsSubstring(items []string, substr string) bool {
	for _, item := range items {
		if len(item) >= len(substr) && indexOf(item, substr) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// json1 produces a json.Number the same way decoding "1" would, so
// hand-built test maps behave like decoded JSON.
func json1(n int64) interface{} {
	return json.Number(strconv.FormatInt(n, 10))
}
