// SPDX-License-Identifier: GPL-3.0-only

package secureio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicPathRejectsOverwrite(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "secret")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := AtomicPath(target, 0o600, false, func(temp string) error {
		return os.WriteFile(temp, []byte("replacement"), 0o600)
	})
	if err == nil {
		t.Fatal("expected overwrite error")
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "original" {
		t.Fatalf("target changed: %q", got)
	}
}

func TestAtomicPathSetsMode(t *testing.T) {
	target := filepath.Join(t.TempDir(), "secret")
	if err := AtomicPath(target, 0o600, false, func(temp string) error {
		return os.WriteFile(temp, []byte("secret"), 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}
