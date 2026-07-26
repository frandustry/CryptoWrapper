// SPDX-License-Identifier: GPL-3.0-only

package openssl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestRequireSupportedRejectsOldOpenSSLWithUpgradeGuidance(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "openssl-old")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf '%s\\n' 'OpenSSL 3.6.2 1 Jan 2026'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	client := &Client{Path: executable}

	_, err := client.RequireSupported(context.Background())
	if err == nil {
		t.Fatal("RequireSupported() unexpectedly accepted OpenSSL 3.6.2")
	}
	for _, text := range []string{"3.6.2", executable, "3.6.3+", "--openssl/CW_OPENSSL", "cw doctor"} {
		if !strings.Contains(err.Error(), text) {
			t.Errorf("RequireSupported() error %q does not contain %q", err, text)
		}
	}
}

func TestRequireSupportedAcceptsMinimumVersion(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "openssl-supported")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf '%s\\n' 'OpenSSL 3.6.3 1 Jan 2026'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	client := &Client{Path: executable}

	version, err := client.RequireSupported(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version.String() != "3.6.3" {
		t.Fatalf("RequireSupported() version = %s, want 3.6.3", version)
	}
}

func TestRequireSupportedRejectsNonOpenSSLWithUpgradeGuidance(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "openssl")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf '%s\\n' 'LibreSSL 3.3.6'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	client := &Client{Path: executable}

	_, err := client.RequireSupported(context.Background())
	if err == nil {
		t.Fatal("RequireSupported() unexpectedly accepted LibreSSL")
	}
	for _, text := range []string{"LibreSSL 3.3.6", "3.6.3+", "--openssl/CW_OPENSSL", "cw doctor"} {
		if !strings.Contains(err.Error(), text) {
			t.Errorf("RequireSupported() error %q does not contain %q", err, text)
		}
	}
}
