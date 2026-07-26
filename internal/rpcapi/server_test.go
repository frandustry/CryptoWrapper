// SPDX-License-Identifier: GPL-3.0-only

package rpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHandshakeAdvertisesVersionedCapabilities(t *testing.T) {
	service := newTestService(t, nil, successfulRunner)
	output := serveRequests(t, service,
		`{"jsonrpc":"2.0","id":"hello","method":"system.handshake"}`+"\n")

	response := responseWithID(t, output, `"hello"`)
	var result HandshakeResult
	decodeResult(t, response, &result)
	if result.ProtocolVersion != ProtocolVersion || result.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected versions: %#v", result)
	}
	if result.Transport != "json-rpc-2.0/stdio-line" {
		t.Fatalf("unexpected transport: %s", result.Transport)
	}
	if result.SecretChannel.Available {
		t.Fatal("secret channel unexpectedly advertised as available")
	}
	if !contains(result.Methods, "file.sign") || !contains(result.Methods, "operation.cancel") {
		t.Fatalf("expected methods missing: %v", result.Methods)
	}
}

func TestStrictParametersRejectUnknownFields(t *testing.T) {
	service := newTestService(t, nil, successfulRunner)
	output := serveRequests(t, service,
		`{"jsonrpc":"2.0","id":1,"method":"key.generateSymmetric","params":{"algorithm":"aes-256","out":"key","unexpected":true}}`+"\n")

	response := responseWithID(t, output, `1`)
	errorObject := response["error"].(map[string]any)
	if got := int(errorObject["code"].(float64)); got != -32602 {
		t.Fatalf("error code = %d, want -32602", got)
	}
}

func TestSecretIsSeparateFromJSONArgumentsAndCleared(t *testing.T) {
	const secretText = "rpc-super-secret-value"
	frame, err := AppendSecretFrame(nil, "key-passphrase", []byte(secretText))
	if err != nil {
		t.Fatal(err)
	}
	var (
		seenArguments []string
		seenSecret    []byte
	)
	runner := func(_ context.Context, arguments []string, secret []byte) (json.RawMessage, *CommandError) {
		seenArguments = append([]string(nil), arguments...)
		seenSecret = secret
		return json.RawMessage(`{"schema_version":"1","ok":true}`), nil
	}
	service := newTestService(t, bytes.NewReader(frame), runner)
	request := `{"jsonrpc":"2.0","id":2,"method":"key.generate","params":{` +
		`"algorithm":"ed25519","out":"private.pem","secret_ref":"key-passphrase"}}` + "\n"
	output := serveRequests(t, service, request)

	response := responseWithID(t, output, `2`)
	if _, ok := response["result"]; !ok {
		t.Fatalf("missing result: %v", response)
	}
	if strings.Contains(output, secretText) || strings.Contains(strings.Join(seenArguments, " "), secretText) {
		t.Fatal("secret leaked into JSON-RPC output or command arguments")
	}
	if strings.Contains(strings.Join(seenArguments, " "), "key-passphrase") {
		t.Fatal("secret reference leaked into command arguments")
	}
	for index, value := range seenSecret {
		if value != 0 {
			t.Fatalf("secret byte %d was not cleared", index)
		}
	}
}

func TestCommandExitCodeMapsToStructuredRPCError(t *testing.T) {
	runner := func(context.Context, []string, []byte) (json.RawMessage, *CommandError) {
		return nil, &CommandError{ExitCode: 3, Message: "OpenSSL is unavailable"}
	}
	service := newTestService(t, nil, runner)
	output := serveRequests(t, service,
		`{"jsonrpc":"2.0","id":3,"method":"system.doctor"}`+"\n")
	response := responseWithID(t, output, `3`)
	errorObject := response["error"].(map[string]any)
	if got := int(errorObject["code"].(float64)); got != int(errorDependency) {
		t.Fatalf("error code = %d, want %d", got, errorDependency)
	}
	data := errorObject["data"].(map[string]any)
	if got := int(data["cli_exit_code"].(float64)); got != 3 {
		t.Fatalf("cli_exit_code = %d, want 3", got)
	}
}

func TestOperationCancelPropagatesToRunnerContext(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	var once sync.Once
	runner := func(ctx context.Context, _ []string, _ []byte) (json.RawMessage, *CommandError) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		close(cancelled)
		return nil, &CommandError{ExitCode: 1, Message: "cancelled"}
	}
	service := newTestService(t, nil, runner)

	inputReader, inputWriter := io.Pipe()
	var output lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- service.Serve(context.Background(), inputReader, &output)
	}()
	if _, err := io.WriteString(inputWriter,
		`{"jsonrpc":"2.0","id":"long","method":"system.doctor"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not start")
	}
	if _, err := io.WriteString(inputWriter,
		`{"jsonrpc":"2.0","id":"cancel","method":"operation.cancel","params":{"request_id":"long"}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("operation context was not cancelled")
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RPC server did not stop")
	}
	if !strings.Contains(output.String(), `"id":"cancel"`) {
		t.Fatalf("cancel response missing: %s", output.String())
	}
}

func newTestService(t *testing.T, secrets io.Reader, runner Runner) *Service {
	t.Helper()
	service, err := New(Config{
		Version:        "test",
		Commit:         "abc123",
		BuildDate:      "2026-07-26",
		LibraryVersion: "unavailable",
		Runner:         runner,
	}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func successfulRunner(context.Context, []string, []byte) (json.RawMessage, *CommandError) {
	return json.RawMessage(`{"schema_version":"1","ok":true}`), nil
}

func serveRequests(t *testing.T, service *Service, input string) string {
	t.Helper()
	inputReader, inputWriter := io.Pipe()
	var output lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- service.Serve(context.Background(), inputReader, &output)
	}()
	if _, err := io.WriteString(inputWriter, input); err != nil {
		t.Fatal(err)
	}
	if !output.waitForResponse(2 * time.Second) {
		t.Fatalf("RPC response timed out; output:\n%s", output.String())
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func responseWithID(t *testing.T, output, id string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var message map[string]any
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			t.Fatalf("decode protocol line %q: %v", line, err)
		}
		encodedID, err := json.Marshal(message["id"])
		if err != nil {
			t.Fatal(err)
		}
		if string(encodedID) == id {
			return message
		}
	}
	t.Fatalf("response id %s not found in:\n%s", id, output)
	return nil
}

func decodeResult(t *testing.T, response map[string]any, target any) {
	t.Helper()
	encoded, err := json.Marshal(response["result"])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatal(err)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func (b *lockedBuffer) waitForResponse(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
			if line == "" {
				continue
			}
			var message map[string]json.RawMessage
			if json.Unmarshal([]byte(line), &message) == nil && len(message["id"]) != 0 &&
				(len(message["result"]) != 0 || len(message["error"]) != 0) {
				return true
			}
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
