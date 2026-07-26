// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/cmslib"
	"github.com/frandustry/CryptoWrapper/internal/openssl"
	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newEncryptCommand(g *globals) *cobra.Command {
	var (
		input      string
		output     string
		recipients []string
		cipher     string
		force      bool
	)
	command := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a file for one or more X.509 recipients using CMS",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireInput(input); err != nil {
				return err
			}
			if output == "" || len(recipients) == 0 {
				return ExitError{Code: 2, Err: fmt.Errorf("--out and at least one --recipient are required")}
			}
			cipher = strings.ToLower(cipher)
			if err := validateAlgorithmName(cipher); err != nil {
				return err
			}
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			err = secureio.AtomicPath(output, 0o644, force, func(temp string) error {
				args := []string{
					"cms", "-encrypt", "-binary", "-outform", "DER",
					"-in", input, "-out", temp, "-" + cipher,
				}
				for _, certificate := range recipients {
					if err := requireInput(certificate); err != nil {
						return err
					}
					keyType, typeErr := certificateKeyType(cmd.Context(), client, certificate)
					if typeErr != nil {
						return typeErr
					}
					args = append(args, "-recip", certificate)
					switch {
					case keyType == "rsa":
						args = append(args,
							"-keyopt", "rsa_padding_mode:oaep",
							"-keyopt", "rsa_oaep_md:sha256",
							"-keyopt", "rsa_mgf1_md:sha256",
						)
					case keyType == "ec":
						args = append(args, "-keyopt", "ecdh_kdf_md:sha256")
					case strings.HasPrefix(keyType, "ml-kem"):
						args = append(args, "-recip_kdf", "HKDF-SHA256")
					}
				}
				_, runErr := client.Run(cmd.Context(), args...)
				return runErr
			})
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return printEncryptionResult(cmd, g, cipher, output, len(recipients))
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	command.Flags().StringVarP(&output, "out", "o", "", "CMS DER output path")
	command.Flags().StringSliceVar(&recipients, "recipient", nil, "recipient X.509 certificate (repeatable)")
	command.Flags().StringVar(&cipher, "cipher", "aes-256-gcm", "CMS content cipher")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	return command
}

func newDecryptCommand(g *globals) *cobra.Command {
	var (
		input       string
		output      string
		certificate string
		key         string
		force       bool
		passFlags   passphraseFlags
	)
	command := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a CMS file with a recipient certificate and private key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireInput(input); err != nil {
				return err
			}
			if certificate == "" || key == "" || output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--cert, --key, and --out are required")}
			}
			passphrase, err := passFlags.read(cmd.Context(), false, "Private-key passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			err = secureio.AtomicPath(output, 0o600, force, func(temp string) error {
				args := []string{
					"cms", "-decrypt", "-binary", "-inform", "DER",
					"-in", input, "-out", temp,
					"-recip", certificate, "-inkey", key,
				}
				if passphrase != nil {
					args = append(args, "-passin", "fd:3")
					_, runErr := client.RunPassphrase(cmd.Context(), passphrase, args...)
					return runErr
				}
				_, runErr := client.Run(cmd.Context(), args...)
				return runErr
			})
			if err != nil {
				return ExitError{Code: 4, Err: fmt.Errorf("CMS decryption failed: %w", err)}
			}
			return printDecryptionResult(cmd, g, output)
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "CMS DER input path")
	command.Flags().StringVarP(&output, "out", "o", "", "plaintext output path")
	command.Flags().StringVar(&certificate, "cert", "", "recipient X.509 certificate")
	command.Flags().StringVar(&key, "key", "", "recipient private key")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	addPassphraseFlags(command, &passFlags, true)
	return command
}

func newSymEncryptCommand(g *globals) *cobra.Command {
	var input, output, keyFile, cipher string
	var force bool
	command := &cobra.Command{
		Use:   "sym-encrypt",
		Short: "Encrypt a file as CMS EncryptedData using a raw symmetric key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireSupportedLibcrypto("sym-encrypt"); err != nil {
				return err
			}
			if err := requireInput(input); err != nil {
				return err
			}
			if output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			key, err := readHexKey(keyFile)
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(key)
			if cipher == "" {
				cipher, err = inferAESCipher(len(key))
				if err != nil {
					return ExitError{Code: 2, Err: err}
				}
			}
			cipher = strings.ToLower(cipher)
			if err := validateCMSKeyCipher(cipher, len(key)); err != nil {
				return ExitError{Code: 2, Err: err}
			}
			err = secureio.AtomicPath(output, 0o644, force, func(temp string) error {
				return cmslib.EncryptKey(input, temp, key, strings.ToUpper(cipher))
			})
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return printEncryptionResult(cmd, g, cipher, output, 0)
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	command.Flags().StringVarP(&output, "out", "o", "", "CMS DER output path")
	command.Flags().StringVar(&keyFile, "key", "", "hexadecimal symmetric-key file")
	command.Flags().StringVar(&cipher, "cipher", "", "CMS cipher (AES-GCM inferred by key length)")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	return command
}

func newSymDecryptCommand(g *globals) *cobra.Command {
	var input, output, keyFile string
	var force bool
	command := &cobra.Command{
		Use:   "sym-decrypt",
		Short: "Decrypt CMS EncryptedData using a raw symmetric key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireSupportedLibcrypto("sym-decrypt"); err != nil {
				return err
			}
			if err := requireInput(input); err != nil {
				return err
			}
			if output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			key, err := readHexKey(keyFile)
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(key)
			err = secureio.AtomicPath(output, 0o600, force, func(temp string) error {
				return cmslib.DecryptKey(input, temp, key)
			})
			if err != nil {
				return ExitError{Code: 4, Err: fmt.Errorf("CMS symmetric-key decryption failed: %w", err)}
			}
			return printDecryptionResult(cmd, g, output)
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "CMS DER input path")
	command.Flags().StringVarP(&output, "out", "o", "", "plaintext output path")
	command.Flags().StringVar(&keyFile, "key", "", "hexadecimal symmetric-key file")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	return command
}

func newPassEncryptCommand(g *globals) *cobra.Command {
	var input, output string
	var force bool
	var passFlags passphraseFlags
	command := &cobra.Command{
		Use:   "pass-encrypt",
		Short: "Encrypt a file using CMS PasswordRecipientInfo",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireSupportedLibcrypto("pass-encrypt"); err != nil {
				return err
			}
			if err := requireInput(input); err != nil {
				return err
			}
			if output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			passphrase, err := passFlags.read(cmd.Context(), true, "Encryption passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			err = secureio.AtomicPath(output, 0o644, force, func(temp string) error {
				return cmslib.EncryptPassword(input, temp, passphrase)
			})
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return printEncryptionResult(cmd, g, "aes-256-gcm", output, 0)
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	command.Flags().StringVarP(&output, "out", "o", "", "CMS DER output path")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	addPassphraseFlags(command, &passFlags, false)
	return command
}

func newPassDecryptCommand(g *globals) *cobra.Command {
	var input, output string
	var force bool
	var passFlags passphraseFlags
	command := &cobra.Command{
		Use:   "pass-decrypt",
		Short: "Decrypt CMS PasswordRecipientInfo",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireSupportedLibcrypto("pass-decrypt"); err != nil {
				return err
			}
			if err := requireInput(input); err != nil {
				return err
			}
			if output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			passphrase, err := passFlags.read(cmd.Context(), false, "Decryption passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			err = secureio.AtomicPath(output, 0o600, force, func(temp string) error {
				return cmslib.DecryptPassword(input, temp, passphrase)
			})
			if err != nil {
				return ExitError{Code: 4, Err: fmt.Errorf("CMS password decryption failed: %w", err)}
			}
			return printDecryptionResult(cmd, g, output)
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "CMS DER input path")
	command.Flags().StringVarP(&output, "out", "o", "", "plaintext output path")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	addPassphraseFlags(command, &passFlags, false)
	return command
}

func certificateKeyType(ctx context.Context, client *openssl.Client, certificate string) (string, error) {
	publicKey, err := client.Run(ctx, "x509", "-in", certificate, "-pubkey", "-noout")
	if err != nil {
		return "", err
	}
	text, err := client.RunInput(ctx, strings.NewReader(string(publicKey)),
		"pkey", "-pubin", "-text", "-noout")
	if err != nil {
		return "", err
	}
	return classifyKeyText(string(text)), nil
}

func readHexKey(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("--key is required")
	}
	if err := requireInput(path); err != nil {
		return nil, err
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read symmetric key: %w", err)
	}
	trimmed := bytes.TrimSpace(encoded)
	key := make([]byte, hex.DecodedLen(len(trimmed)))
	decodedLength, err := hex.Decode(key, trimmed)
	secureio.Zero(encoded)
	if err != nil {
		secureio.Zero(key)
		return nil, fmt.Errorf("symmetric key must be hexadecimal: %w", err)
	}
	key = key[:decodedLength]
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		secureio.Zero(key)
		return nil, fmt.Errorf("symmetric key must be 128, 192, or 256 bits")
	}
	return key, nil
}

func inferAESCipher(length int) (string, error) {
	switch length {
	case 16:
		return "aes-128-gcm", nil
	case 24:
		return "aes-192-gcm", nil
	case 32:
		return "aes-256-gcm", nil
	default:
		return "", fmt.Errorf("cannot infer AES cipher from %d-byte key", length)
	}
}

func validateCMSKeyCipher(cipher string, keyLength int) error {
	allowed := map[string]int{
		"aes-128-gcm": 16, "aes-192-gcm": 24, "aes-256-gcm": 32,
		"aes-128-cbc": 16, "aes-192-cbc": 24, "aes-256-cbc": 32,
		"camellia-128-cbc": 16, "camellia-192-cbc": 24, "camellia-256-cbc": 32,
		"aria-128-cbc": 16, "aria-192-cbc": 24, "aria-256-cbc": 32,
		"sm4-cbc": 16,
	}
	want, ok := allowed[cipher]
	if !ok {
		return fmt.Errorf("unsupported CMS symmetric cipher %q", cipher)
	}
	if want != keyLength {
		return fmt.Errorf("%s requires a %d-bit key, got %d bits", cipher, want*8, keyLength*8)
	}
	return nil
}

func printEncryptionResult(cmd *cobra.Command, g *globals, algorithm, output string, recipients int) error {
	if g.jsonOutput {
		data := map[string]any{}
		if recipients > 0 {
			data["recipients"] = recipients
		}
		return writeJSON(cmd.OutOrStdout(), result{
			OK:        true,
			Algorithm: algorithm,
			Outputs:   map[string]string{"cms": absoluteOutput(output)},
			Data:      data,
		})
	}
	if recipients > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Encrypted CMS: %s (%s, %d recipient(s))\n", output, algorithm, recipients)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Encrypted CMS: %s (%s)\n", output, algorithm)
	}
	return nil
}

func printDecryptionResult(cmd *cobra.Command, g *globals, output string) error {
	if g.jsonOutput {
		return writeJSON(cmd.OutOrStdout(), result{
			OK:      true,
			Outputs: map[string]string{"plaintext": absoluteOutput(output)},
		})
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Plaintext: %s\n", output)
	return nil
}
