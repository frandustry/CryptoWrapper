// SPDX-License-Identifier: GPL-3.0-only

package cli

import "testing"

func TestClassifyKeyText(t *testing.T) {
	tests := map[string]string{
		"ED25519 Private-Key":               "ed25519",
		"ML-DSA-65 Private-Key":             "ml-dsa",
		"ASN1 OID: prime256v1":              "ec",
		"PSS parameter restrictions:":       "rsa-pss",
		"Private-Key: (3072 bit, 2 primes)": "rsa",
	}
	for input, want := range tests {
		if got := classifyKeyText(input); got != want {
			t.Errorf("classifyKeyText(%q) = %q, want %q", input, got, want)
		}
	}
}
