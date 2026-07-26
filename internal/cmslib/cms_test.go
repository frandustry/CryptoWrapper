// SPDX-License-Identifier: GPL-3.0-only

//go:build cgo

package cmslib

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSymmetricCMSRoundTrip(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input")
	encrypted := filepath.Join(directory, "encrypted.cms")
	output := filepath.Join(directory, "output")
	plaintext := []byte("authenticated symmetric CMS")
	key := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptKey(input, encrypted, key, "AES-256-GCM"); err != nil {
		t.Fatal(err)
	}
	if err := DecryptKey(encrypted, output, key); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}

func TestPasswordCMSRoundTripAndWrongPassword(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input")
	encrypted := filepath.Join(directory, "encrypted.cms")
	output := filepath.Join(directory, "output")
	plaintext := []byte("authenticated password CMS")
	password := []byte("correct horse battery staple")
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptPassword(input, encrypted, password); err != nil {
		t.Fatal(err)
	}
	if err := DecryptPassword(encrypted, output, []byte("wrong password")); err == nil {
		t.Fatal("expected wrong-password failure")
	}
	if err := DecryptPassword(encrypted, output, password); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}
