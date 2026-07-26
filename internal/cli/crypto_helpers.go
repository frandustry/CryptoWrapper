// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/openssl"
	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

var safeAlgorithmName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type passphraseFlags struct {
	file string
	env  string
	none bool
}

func addPassphraseFlags(command *cobra.Command, flags *passphraseFlags, allowNone bool) {
	command.Flags().StringVar(&flags.file, "passphrase-file", "", "read the passphrase from the first line of a file")
	command.Flags().StringVar(&flags.env, "passphrase-env", "", "read the passphrase from an environment variable")
	if allowNone {
		command.Flags().BoolVar(&flags.none, "no-passphrase", false, "use an unencrypted private key")
	}
}

func (flags passphraseFlags) read(confirm bool, prompt string) ([]byte, error) {
	return secureio.ReadPassphrase(secureio.PassphraseOptions{
		File:    flags.file,
		Env:     flags.env,
		None:    flags.none,
		Confirm: confirm,
		Prompt:  prompt,
	})
}

func defaultPublicPath(privatePath string) string {
	for _, suffix := range []string{".key.pem", ".pem", ".key"} {
		if strings.HasSuffix(privatePath, suffix) {
			return strings.TrimSuffix(privatePath, suffix) + ".pub.pem"
		}
	}
	return privatePath + ".pub.pem"
}

func fileFingerprint(ctx context.Context, client *openssl.Client, kind, path string) (string, error) {
	var args []string
	switch kind {
	case "public":
		args = []string{"pkey", "-pubin", "-in", path, "-outform", "DER"}
	case "certificate":
		args = []string{"x509", "-in", path, "-outform", "DER"}
	default:
		return "", fmt.Errorf("unsupported fingerprint kind %q", kind)
	}
	der, err := client.Run(ctx, args...)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func requireInput(path string) error {
	if path == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--in is required")}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("inspect input: %w", err)}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ExitError{Code: 2, Err: fmt.Errorf("input must be a regular non-symlink file: %s", path)}
	}
	return nil
}

func absoluteOutput(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}

func validateAlgorithmName(name string) error {
	if !safeAlgorithmName.MatchString(name) {
		return ExitError{Code: 2, Err: fmt.Errorf("invalid algorithm name %q", name)}
	}
	return nil
}
