// SPDX-License-Identifier: GPL-3.0-only

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/frandustry/CryptoWrapper/internal/rpcapi"
)

func TestRPCEncryptedKeySignAndVerify(t *testing.T) {
	requireIntegration(t)
	directory := t.TempDir()
	message := filepath.Join(directory, "message.txt")
	privateKey := filepath.Join(directory, "signing.key.pem")
	publicKey := filepath.Join(directory, "signing.pub.pem")
	signature := filepath.Join(directory, "message.sig")
	writeFile(t, message, "JSON-RPC integration test\n", 0o600)

	secretRead, secretWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer secretWrite.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath, "rpc", "--stdio", "--secret-fd", "3")
	command.Dir = repoRoot
	command.ExtraFiles = []*os.File{secretRead}
	var stderr synchronizedBuffer
	command.Stderr = &stderr
	requestWriter, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	responseReader, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = secretRead.Close()

	client := jrpc2.NewClient(channel.Line(responseReader, requestWriter), nil)
	defer func() {
		_ = client.Close()
		_ = command.Wait()
	}()

	passphrase := []byte("RPC integration secret")
	defer clearBytes(passphrase)
	var frames []byte
	// Deliberately send frames in the opposite order from the operations to
	// verify reference-based demultiplexing.
	frames, err = rpcapi.AppendSecretFrame(frames, "sign-secret", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	frames, err = rpcapi.AppendSecretFrame(frames, "key-secret", passphrase)
	if err != nil {
		clearBytes(frames)
		t.Fatal(err)
	}
	if _, err := secretWrite.Write(frames); err != nil {
		clearBytes(frames)
		t.Fatal(err)
	}
	clearBytes(frames)

	var handshake map[string]any
	if err := client.CallResult(ctx, "system.handshake", nil, &handshake); err != nil {
		t.Fatal(err)
	}
	if handshake["protocol_version"] != "1" {
		t.Fatalf("unexpected handshake: %v", handshake)
	}

	var result json.RawMessage
	if err := client.CallResult(ctx, "key.generate", map[string]any{
		"algorithm":  "ed25519",
		"out":        privateKey,
		"public_out": publicKey,
		"secret_ref": "key-secret",
	}, &result); err != nil {
		t.Fatalf("key.generate: %v\nstderr: %s", err, stderr.String())
	}
	if err := client.CallResult(ctx, "file.sign", map[string]any{
		"in":         message,
		"key":        privateKey,
		"out":        signature,
		"secret_ref": "sign-secret",
	}, &result); err != nil {
		t.Fatalf("file.sign: %v\nstderr: %s", err, stderr.String())
	}
	if err := client.CallResult(ctx, "file.verify", map[string]any{
		"in":        message,
		"key":       publicKey,
		"signature": signature,
	}, &result); err != nil {
		t.Fatalf("file.verify: %v\nstderr: %s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), string(passphrase)) {
		t.Fatal("passphrase leaked to RPC stderr")
	}
	for _, path := range []string{privateKey, publicKey, signature} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(fmt.Errorf("expected RPC output %s: %w", path, err))
		}
	}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
