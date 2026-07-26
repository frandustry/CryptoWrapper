// SPDX-License-Identifier: GPL-3.0-only

package policy

import "testing"

func TestSLHDSAPassThrough(t *testing.T) {
	got, err := RequireKey("slh-dsa-sha2-128s", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.OpenSSLName != "SLH-DSA-SHA2-128S" {
		t.Fatalf("unexpected OpenSSL name %q", got.OpenSSLName)
	}
}

func TestLegacyKeyRequiresOptIn(t *testing.T) {
	if _, err := RequireKey("dsa", false); err == nil {
		t.Fatal("expected legacy error")
	}
}
