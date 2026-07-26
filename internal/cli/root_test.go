// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVersionJSON(t *testing.T) {
	cmd := New("1.2.3", "abc123", "2026-07-26")
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--json", "version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := output.String(); !strings.Contains(got, `"schema_version":"1"`) ||
		!strings.Contains(got, `"version":"1.2.3"`) {
		t.Fatalf("unexpected JSON output: %s", got)
	}
}

func TestRPCSymmetricKeyGeneration(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "vault.key")
	request := `{"jsonrpc":"2.0","id":1,"method":"key.generateSymmetric","params":{` +
		`"algorithm":"aes-256","out":` + mustJSON(t, outputPath) + `}}` + "\n"
	cmd := New("1.2.3", "abc123", "2026-07-26")
	inputReader, inputWriter := io.Pipe()
	var output synchronizedBuffer
	cmd.SetIn(inputReader)
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"rpc", "--stdio"})

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()
	if _, err := io.WriteString(inputWriter, request); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(output.String(), `"id":1`) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(output.String(), `"id":1`) ||
		!strings.Contains(output.String(), `"schema_version":"1"`) {
		t.Fatalf("unexpected RPC output: %s", output.String())
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

type synchronizedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *synchronizedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(value)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}
