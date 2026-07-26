// SPDX-License-Identifier: GPL-3.0-only

package demo

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"
)

//go:embed cryptowrapper.cast
var cryptoWrapperCast string

func TestCryptoWrapperCast(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader(cryptoWrapperCast))
	if !scanner.Scan() {
		t.Fatal("recording is empty")
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &header); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if header.Version != 2 {
		t.Fatalf("recording version = %d, want 2", header.Version)
	}

	var output strings.Builder
	exitStatus := ""
	for scanner.Scan() {
		var event []json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		if len(event) != 3 {
			t.Fatalf("event has %d fields, want 3", len(event))
		}
		var eventType, payload string
		if err := json.Unmarshal(event[1], &eventType); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(event[2], &payload); err != nil {
			t.Fatal(err)
		}
		switch eventType {
		case "o":
			output.WriteString(payload)
		case "x":
			exitStatus = payload
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if exitStatus != "0" {
		t.Fatalf("recorded command exit status = %q, want 0", exitStatus)
	}

	recorded := output.String()
	for _, expected := range []string{
		"$ cw doctor",
		"$ cw keygen ed25519",
		"$ cw sign",
		"$ cw verify",
		"Signature verified",
		"$ cw hash sha256",
		"Done. The signature is valid",
	} {
		if !strings.Contains(recorded, expected) {
			t.Errorf("recording does not contain %q", expected)
		}
	}
	for _, forbidden := range []string{
		"/Users/",
		"BEGIN PRIVATE KEY",
		"PRIVATE KEY-----",
	} {
		if strings.Contains(recorded, forbidden) {
			t.Errorf("recording contains forbidden text %q", forbidden)
		}
	}
}
