// Command go-receipt-verifier is a standalone verifier for Signetry
// Remediation Receipts (RECEIPT_SPEC v1). It has no dependency on
// signetry-core: it reads a receipt envelope as JSON (stdin or a file
// argument) and a pinned Ed25519 public key, and reports whether the
// receipt verifies and conforms.
//
// Usage:
//
//	go-receipt-verifier --public-key <base64> [receipt.json]
//	cat receipt.json | go-receipt-verifier --public-key <base64>
//
// Exit codes:
//
//	0  the receipt is verified AND conforming
//	1  the receipt is not verified, not conforming, or was refused
//	2  usage error (bad flags, unreadable file, malformed JSON)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/signetry-community/go-receipt-verifier/internal/receipt"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("go-receipt-verifier", flag.ContinueOnError)
	fs.SetOutput(stderr)
	publicKey := fs.String("public-key", "", "Base64 Ed25519 public key to verify against (pinned, out of band). "+
		"Omit only to exercise the 'refuse an ephemeral/unpinned receipt' path.")
	asJSON := fs.Bool("json", false, "Emit the full result as JSON instead of a human-readable report.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: go-receipt-verifier [--public-key BASE64] [--json] [receipt.json]")
		fmt.Fprintln(stderr, "       (reads from stdin if receipt.json is omitted or '-')")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var data []byte
	var err error
	switch fs.NArg() {
	case 0:
		data, err = io.ReadAll(stdin)
	case 1:
		if fs.Arg(0) == "-" {
			data, err = io.ReadAll(stdin)
		} else {
			data, err = os.ReadFile(fs.Arg(0))
		}
	default:
		fmt.Fprintln(stderr, "error: at most one receipt file argument is allowed")
		fs.Usage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot read receipt: %v\n", err)
		return 2
	}

	decoded, err := receipt.DecodeJSON(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: malformed JSON: %v\n", err)
		return 2
	}
	envelope, ok := decoded.(map[string]interface{})
	if !ok {
		fmt.Fprintln(stderr, "error: top-level JSON value must be an object (an envelope)")
		return 2
	}

	var pinned *string
	if *publicKey != "" {
		pinned = publicKey
	}

	result := receipt.Verify(envelope, pinned)

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
	} else {
		printHuman(stdout, result)
	}

	if result.Verified && result.Conforming {
		return 0
	}
	return 1
}

func printHuman(w io.Writer, r receipt.Result) {
	switch {
	case r.Refused:
		fmt.Fprintln(w, "REFUSED — "+r.Reason)
	case !r.Verified:
		if r.Reason != "" {
			fmt.Fprintln(w, "NOT VERIFIED — "+r.Reason)
		} else {
			fmt.Fprintf(w, "NOT VERIFIED  (signature_valid=%v, hash_matches=%v)\n", r.SignatureValid, r.HashMatches)
		}
	default:
		fmt.Fprintf(w, "VERIFIED  (signature_valid=%v, hash_matches=%v, key_matches_pinned=%v)\n",
			r.SignatureValid, r.HashMatches, r.KeyMatchesPinned)
	}

	for _, v := range r.InvariantViolations {
		fmt.Fprintln(w, "NON-CONFORMING — "+v)
	}

	if r.Verified && !r.Conforming {
		fmt.Fprintln(w, "WARNING: signature is valid but the receipt is NON-CONFORMING — see violations above.")
	}
}
