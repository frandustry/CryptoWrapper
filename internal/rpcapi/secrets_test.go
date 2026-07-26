// SPDX-License-Identifier: GPL-3.0-only

package rpcapi

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSecretFrameRoundTrip(t *testing.T) {
	frame, err := AppendSecretFrame(nil, "request-secret", []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewSecretReader(bytes.NewReader(frame)).Read(context.Background(), "request-secret")
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "correct horse battery staple" {
		t.Fatalf("unexpected secret: %q", secret)
	}
	zero(secret)
}

func TestSecretFramesAreDemultiplexedByReference(t *testing.T) {
	frame, err := AppendSecretFrame(nil, "second", []byte("second-secret"))
	if err != nil {
		t.Fatal(err)
	}
	frame, err = AppendSecretFrame(frame, "first", []byte("first-secret"))
	if err != nil {
		t.Fatal(err)
	}
	reader := NewSecretReader(bytes.NewReader(frame))
	first, err := reader.Read(context.Background(), "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := reader.Read(context.Background(), "second")
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != "first-secret" || string(second) != "second-secret" {
		t.Fatalf("unexpected secrets: %q %q", first, second)
	}
	zero(first)
	zero(second)
	reader.Close()
}

func TestSecretFrameMissingReferenceDoesNotLeak(t *testing.T) {
	frame, err := AppendSecretFrame(nil, "first", []byte("must-not-leak"))
	if err != nil {
		t.Fatal(err)
	}
	reader := NewSecretReader(bytes.NewReader(frame))
	_, err = reader.Read(context.Background(), "second")
	if err == nil || !strings.Contains(err.Error(), "read secret frame header") {
		t.Fatalf("Read() error = %v, want exhausted channel", err)
	}
	if strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("secret leaked in error: %v", err)
	}
	reader.Close()
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
