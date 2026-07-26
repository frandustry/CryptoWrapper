// SPDX-License-Identifier: GPL-3.0-only

package rpcapi

import (
	"bytes"
	"strings"
	"testing"
)

func TestSecretFrameRoundTrip(t *testing.T) {
	frame, err := AppendSecretFrame(nil, "request-secret", []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecretReader(bytes.NewReader(frame)).Read("request-secret")
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "correct horse battery staple" {
		t.Fatalf("unexpected secret: %q", secret)
	}
	zero(secret)
}

func TestSecretFrameRejectsMismatchedReference(t *testing.T) {
	frame, err := AppendSecretFrame(nil, "first", []byte("must-not-leak"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSecretReader(bytes.NewReader(frame)).Read("second")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Read() error = %v, want reference mismatch", err)
	}
	if strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestSecretFrameLimits(t *testing.T) {
	tooLarge := make([]byte, maxSecretBytes+1)
	if _, err := AppendSecretFrame(nil, "secret", tooLarge); err == nil {
		t.Fatal("AppendSecretFrame() accepted an oversized secret")
	}
	if _, err := AppendSecretFrame(nil, "", nil); err == nil {
		t.Fatal("AppendSecretFrame() accepted an empty reference")
	}
}
