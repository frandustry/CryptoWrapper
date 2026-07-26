// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"golang.org/x/term"
)

const maxSecretBytes = 64 * 1024

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 {
		return errors.New("usage: go run ./examples/go-rpc-client /path/to/cw /path/to/private.pem")
	}
	cwPath := os.Args[1]
	outputPath := os.Args[2]

	secretRead, secretWrite, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create secret pipe: %w", err)
	}
	defer secretWrite.Close()

	command := exec.Command(cwPath, "rpc", "--stdio", "--secret-fd", "3")
	command.ExtraFiles = []*os.File{secretRead}
	command.Stderr = os.Stderr
	requestWriter, err := command.StdinPipe()
	if err != nil {
		return fmt.Errorf("open RPC input: %w", err)
	}
	responseReader, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open RPC output: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start CryptoWrapper: %w", err)
	}
	_ = secretRead.Close()

	client := jrpc2.NewClient(channel.Line(responseReader, requestWriter), &jrpc2.ClientOptions{
		OnNotify: func(request *jrpc2.Request) {
			if request.Method() == "operation.progress" {
				fmt.Fprintln(os.Stderr, request.ParamString())
			}
		},
	})
	defer func() {
		_ = client.Close()
		_ = command.Wait()
	}()

	ctx := context.Background()
	var handshake map[string]any
	if err := client.CallResult(ctx, "system.handshake", nil, &handshake); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if handshake["protocol_version"] != "1" {
		return fmt.Errorf("unsupported protocol version %v", handshake["protocol_version"])
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("a terminal is required to read the private-key passphrase")
	}
	fmt.Fprint(os.Stderr, "Private-key passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	defer zero(passphrase)

	const secretReference = "go-example-key-passphrase"
	frame, err := secretFrame(secretReference, passphrase)
	if err != nil {
		return err
	}
	if _, err := secretWrite.Write(frame); err != nil {
		zero(frame)
		return fmt.Errorf("write secret frame: %w", err)
	}
	zero(frame)

	var result json.RawMessage
	if err := client.CallResult(ctx, "key.generate", map[string]any{
		"algorithm":  "ed25519",
		"out":        outputPath,
		"secret_ref": secretReference,
	}, &result); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	fmt.Println(string(result))
	return nil
}

func secretFrame(reference string, secret []byte) ([]byte, error) {
	if reference == "" || len(reference) > 256 {
		return nil, errors.New("secret reference must contain 1 to 256 bytes")
	}
	if len(secret) > maxSecretBytes {
		return nil, fmt.Errorf("secret exceeds %d bytes", maxSecretBytes)
	}
	var frame bytes.Buffer
	frame.WriteString("CWS1")
	if err := binary.Write(&frame, binary.BigEndian, uint16(len(reference))); err != nil {
		return nil, err
	}
	if err := binary.Write(&frame, binary.BigEndian, uint32(len(secret))); err != nil {
		return nil, err
	}
	frame.WriteString(reference)
	frame.Write(secret)
	return frame.Bytes(), nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
