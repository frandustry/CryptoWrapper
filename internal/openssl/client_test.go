// SPDX-License-Identifier: GPL-3.0-only

package openssl

import "testing"

func TestParseVersion(t *testing.T) {
	version, err := ParseVersion("OpenSSL 3.6.3 9 Jun 2026")
	if err != nil {
		t.Fatal(err)
	}
	if version.String() != "3.6.3" || !version.Supported() {
		t.Fatalf("unexpected version: %#v", version)
	}
}

func TestSupportedVersionFloor(t *testing.T) {
	tests := []struct {
		version Version
		want    bool
	}{
		{Version{Major: 3, Minor: 6, Patch: 2}, false},
		{Version{Major: 3, Minor: 6, Patch: 3}, true},
		{Version{Major: 3, Minor: 7, Patch: 0}, true},
		{Version{Major: 4, Minor: 0, Patch: 0}, false},
		{Version{Major: 4, Minor: 0, Patch: 1}, true},
		{Version{Major: 5, Minor: 0, Patch: 0}, false},
	}
	for _, test := range tests {
		if got := test.version.Supported(); got != test.want {
			t.Errorf("%s Supported() = %v, want %v", test.version, got, test.want)
		}
	}
}
