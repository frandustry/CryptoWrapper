// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"strings"
	"testing"
)

func TestValidateLibcryptoVersion(t *testing.T) {
	version, err := validateLibcryptoVersion("OpenSSL 3.6.3 1 Jan 2026")
	if err != nil {
		t.Fatal(err)
	}
	if version.String() != "3.6.3" {
		t.Fatalf("validateLibcryptoVersion() = %s, want 3.6.3", version)
	}
}

func TestValidateLibcryptoVersionRejectsOldLibraryWithGuidance(t *testing.T) {
	_, err := validateLibcryptoVersion("OpenSSL 3.6.2 1 Jan 2026")
	if err == nil {
		t.Fatal("validateLibcryptoVersion() unexpectedly accepted OpenSSL 3.6.2")
	}
	for _, text := range []string{"3.6.2", "rebuild CryptoWrapper", "3.6.3+", "cw doctor"} {
		if !strings.Contains(err.Error(), text) {
			t.Errorf("validateLibcryptoVersion() error %q does not contain %q", err, text)
		}
	}
}
