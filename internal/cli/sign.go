// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/openssl"
	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newSignCommand(g *globals) *cobra.Command {
	var (
		key       string
		input     string
		output    string
		keyType   string
		digest    string
		force     bool
		passFlags passphraseFlags
	)
	command := &cobra.Command{
		Use:   "sign",
		Short: "Create a detached OpenSSL signature",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if key == "" || output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--key and --out are required")}
			}
			if err := requireInput(input); err != nil {
				return err
			}
			passphrase, err := passFlags.read(false, "Private-key passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			client, err := clientFor(g)
			if err != nil {
				return err
			}
			if keyType == "" {
				keyType, err = inferPrivateKeyType(cmd.Context(), client, key, passphrase)
				if err != nil {
					return ExitError{Code: 1, Err: err}
				}
			}
			signArgs, err := signatureArgs("sign", keyType, digest)
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			err = secureio.AtomicPath(output, 0o644, force, func(temp string) error {
				args := append([]string{"pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", input, "-out", temp}, signArgs...)
				if passphrase != nil {
					args = append(args, "-passin", "fd:3")
					_, runErr := client.RunPassphrase(cmd.Context(), passphrase, args...)
					return runErr
				}
				_, runErr := client.Run(cmd.Context(), args...)
				return runErr
			})
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK:        true,
					Algorithm: keyType,
					Outputs:   map[string]string{"signature": absoluteOutput(output)},
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Signature: %s (%s)\n", output, keyType)
			return nil
		},
	}
	command.Flags().StringVar(&key, "key", "", "private-key path")
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	command.Flags().StringVarP(&output, "out", "o", "", "signature output path")
	command.Flags().StringVar(&keyType, "key-type", "", "override detected key type")
	command.Flags().StringVar(&digest, "digest", "", "digest override")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	addPassphraseFlags(command, &passFlags, true)
	return command
}

func newVerifyCommand(g *globals) *cobra.Command {
	var (
		key       string
		input     string
		signature string
		keyType   string
		digest    string
	)
	command := &cobra.Command{
		Use:   "verify",
		Short: "Verify a detached OpenSSL signature",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if key == "" || signature == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--key and --signature are required")}
			}
			if err := requireInput(input); err != nil {
				return err
			}
			if err := requireInput(signature); err != nil {
				return err
			}
			client, err := clientFor(g)
			if err != nil {
				return err
			}
			if keyType == "" {
				keyType, err = inferPublicKeyType(cmd.Context(), client, key)
				if err != nil {
					return ExitError{Code: 1, Err: err}
				}
			}
			verifyArgs, err := signatureArgs("verify", keyType, digest)
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			args := append([]string{
				"pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", key,
				"-in", input, "-sigfile", signature,
			}, verifyArgs...)
			if _, err := client.Run(cmd.Context(), args...); err != nil {
				return ExitError{Code: 4, Err: fmt.Errorf("signature verification failed: %w", err)}
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{OK: true, Algorithm: keyType})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Signature verified")
			return nil
		},
	}
	command.Flags().StringVar(&key, "key", "", "public-key path")
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	command.Flags().StringVar(&signature, "signature", "", "signature file")
	command.Flags().StringVar(&keyType, "key-type", "", "override detected key type")
	command.Flags().StringVar(&digest, "digest", "", "digest override")
	return command
}

func inferPrivateKeyType(ctx context.Context, client *openssl.Client, key string, passphrase []byte) (string, error) {
	args := []string{"pkey", "-in", key, "-text", "-noout"}
	var output []byte
	var err error
	if passphrase != nil {
		args = append(args, "-passin", "fd:3")
		output, err = client.RunPassphrase(ctx, passphrase, args...)
	} else {
		output, err = client.Run(ctx, args...)
	}
	if err != nil {
		return "", err
	}
	return classifyKeyText(string(output)), nil
}

func inferPublicKeyType(ctx context.Context, client *openssl.Client, key string) (string, error) {
	output, err := client.Run(ctx, "pkey", "-pubin", "-in", key, "-text", "-noout")
	if err != nil {
		return "", err
	}
	return classifyKeyText(string(output)), nil
}

func classifyKeyText(text string) string {
	upper := strings.ToUpper(text)
	for _, name := range []string{
		"SLH-DSA", "ML-DSA", "ED25519", "ED448", "SM2", "X25519", "X448",
	} {
		if strings.Contains(upper, name) {
			return strings.ToLower(name)
		}
	}
	if strings.Contains(upper, "ASN1 OID") || strings.Contains(upper, "NIST CURVE") {
		return "ec"
	}
	if strings.Contains(upper, "PSS PARAMETER") {
		return "rsa-pss"
	}
	return "rsa"
}

func signatureArgs(operation, keyType, digest string) ([]string, error) {
	_ = operation
	keyType = strings.ToLower(keyType)
	switch {
	case keyType == "rsa" || keyType == "rsa-pss":
		if digest == "" {
			digest = "sha256"
		}
		if err := validateAlgorithmName(digest); err != nil {
			return nil, err
		}
		return []string{
			"-digest", digest,
			"-pkeyopt", "rsa_padding_mode:pss",
			"-pkeyopt", "rsa_pss_saltlen:digest",
		}, nil
	case keyType == "ec":
		if digest == "" {
			digest = "sha256"
		}
		return []string{"-digest", digest}, validateAlgorithmName(digest)
	case keyType == "sm2":
		if digest == "" {
			digest = "sm3"
		}
		return []string{"-digest", digest}, validateAlgorithmName(digest)
	case keyType == "ed25519" || keyType == "ed448" ||
		strings.HasPrefix(keyType, "ml-dsa") || strings.HasPrefix(keyType, "slh-dsa"):
		if digest != "" {
			return nil, fmt.Errorf("%s uses its native one-shot signing mode and does not accept --digest", keyType)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("key type %q does not support signatures", keyType)
	}
}
