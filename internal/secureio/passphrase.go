// SPDX-License-Identifier: GPL-3.0-only

package secureio

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

type PassphraseOptions struct {
	File    string
	Env     string
	None    bool
	Confirm bool
	Prompt  string
}

func ReadPassphrase(options PassphraseOptions) ([]byte, error) {
	sources := 0
	if options.File != "" {
		sources++
	}
	if options.Env != "" {
		sources++
	}
	if options.None {
		sources++
	}
	if sources > 1 {
		return nil, errors.New("choose exactly one of --passphrase-file, --passphrase-env, or --no-passphrase")
	}
	if options.None {
		return nil, nil
	}
	if options.File != "" {
		value, err := os.ReadFile(options.File)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		return trimLineEnding(value), nil
	}
	if options.Env != "" {
		value, ok := os.LookupEnv(options.Env)
		if !ok {
			return nil, fmt.Errorf("passphrase environment variable %s is not set", options.Env)
		}
		return []byte(value), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("no interactive terminal; use --passphrase-file, --passphrase-env, or --no-passphrase")
	}
	prompt := options.Prompt
	if prompt == "" {
		prompt = "Passphrase: "
	}
	fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if options.Confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		confirmation, confirmErr := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if confirmErr != nil {
			Zero(value)
			return nil, fmt.Errorf("confirm passphrase: %w", confirmErr)
		}
		defer Zero(confirmation)
		if !bytes.Equal(value, confirmation) {
			Zero(value)
			return nil, errors.New("passphrases do not match")
		}
	}
	return value, nil
}

func trimLineEnding(value []byte) []byte {
	return bytes.TrimSuffix(bytes.TrimSuffix(value, []byte{'\n'}), []byte{'\r'})
}

func Zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
