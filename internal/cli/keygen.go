// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/policy"
	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newKeygenCommand(g *globals) *cobra.Command {
	var (
		output       string
		publicOutput string
		bits         int
		curve        string
		force        bool
		opensslName  string
		pkeyOptions  []string
		passFlags    passphraseFlags
	)
	command := &cobra.Command{
		Use:   "keygen <algorithm>",
		Short: "Generate an asymmetric private/public key pair",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.ToLower(args[0])
			algorithm, err := policy.RequireKey(name, g.allowLegacy)
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			if algorithm.Name == "dsa" {
				return ExitError{Code: 3, Err: fmt.Errorf("DSA generation requires explicit parameters and is not exposed by the safe CLI")}
			}
			if opensslName != "" {
				if err := validateAlgorithmName(opensslName); err != nil {
					return err
				}
				algorithm.OpenSSLName = opensslName
			}
			if output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			if publicOutput == "" {
				publicOutput = defaultPublicPath(output)
			}
			if output == publicOutput {
				return ExitError{Code: 2, Err: fmt.Errorf("private and public output paths must differ")}
			}
			if name == "rsa" || name == "rsa-pss" {
				if bits == 0 {
					bits = 3072
				}
				if bits < 2048 {
					return ExitError{Code: 2, Err: fmt.Errorf("RSA keys must be at least 2048 bits")}
				}
			}
			if name == "ec" {
				if curve == "" {
					curve = "P-256"
				}
				allowedCurves := map[string]bool{"P-256": true, "P-384": true, "P-521": true, "secp256k1": true}
				if !allowedCurves[curve] {
					return ExitError{Code: 2, Err: fmt.Errorf("unsupported EC curve %q", curve)}
				}
			}
			for _, option := range pkeyOptions {
				if !strings.Contains(option, ":") || strings.HasPrefix(option, "-") {
					return ExitError{Code: 2, Err: fmt.Errorf("invalid --pkeyopt %q; expected name:value", option)}
				}
			}
			passphrase, err := passFlags.read(true, "Private-key passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			client, err := clientFor(g)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			err = secureio.AtomicPair(
				secureio.OutputSpec{Path: output, Mode: 0o600},
				secureio.OutputSpec{Path: publicOutput, Mode: 0o644},
				force,
				func(privateTemp, publicTemp string) error {
					opensslArgs := []string{
						"genpkey", "-algorithm", algorithm.OpenSSLName,
						"-out", privateTemp, "-outpubkey", publicTemp,
					}
					switch name {
					case "rsa", "rsa-pss":
						opensslArgs = append(opensslArgs, "-pkeyopt", "rsa_keygen_bits:"+strconv.Itoa(bits))
					case "ec":
						opensslArgs = append(opensslArgs, "-pkeyopt", "ec_paramgen_curve:"+curve)
					}
					for _, option := range pkeyOptions {
						opensslArgs = append(opensslArgs, "-pkeyopt", option)
					}
					if passphrase != nil {
						opensslArgs = append(opensslArgs, "-aes-256-cbc", "-pass", "fd:3")
						_, runErr := client.RunPassphrase(ctx, passphrase, opensslArgs...)
						return runErr
					}
					_, runErr := client.Run(ctx, opensslArgs...)
					return runErr
				},
			)
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			fingerprint, err := fileFingerprint(ctx, client, "public", publicOutput)
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK:        true,
					Algorithm: algorithm.Name,
					Outputs: map[string]string{
						"private_key": absoluteOutput(output),
						"public_key":  absoluteOutput(publicOutput),
					},
					Fingerprints: map[string]string{"public_key": fingerprint},
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Private key: %s\nPublic key: %s\nFingerprint: %s\n",
				output, publicOutput, fingerprint)
			return nil
		},
	}
	command.Flags().StringVarP(&output, "out", "o", "", "private-key output path")
	command.Flags().StringVar(&publicOutput, "public-out", "", "public-key output path")
	command.Flags().IntVar(&bits, "bits", 0, "RSA key size (default 3072)")
	command.Flags().StringVar(&curve, "curve", "", "EC curve (default P-256)")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace existing regular files")
	command.Flags().StringVar(&opensslName, "openssl-name", "", "validated provider-specific OpenSSL algorithm name")
	command.Flags().StringSliceVar(&pkeyOptions, "pkeyopt", nil, "OpenSSL key option name:value")
	addPassphraseFlags(command, &passFlags, true)
	return command
}

func newSymKeyCommand(g *globals) *cobra.Command {
	var (
		output string
		force  bool
	)
	command := &cobra.Command{
		Use:   "symkey <algorithm>",
		Short: "Generate a symmetric key as restricted hexadecimal text",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.ToLower(args[0])
			bits, ok := policy.SymmetricKeyBits(name)
			if !ok {
				return ExitError{Code: 2, Err: fmt.Errorf("unsupported symmetric-key algorithm %q", name)}
			}
			if output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			key := make([]byte, bits/8)
			if _, err := rand.Read(key); err != nil {
				return ExitError{Code: 1, Err: fmt.Errorf("generate random key: %w", err)}
			}
			defer secureio.Zero(key)
			encoded := []byte(hex.EncodeToString(key) + "\n")
			err := secureio.AtomicPath(output, 0o600, force, func(temp string) error {
				return os.WriteFile(temp, encoded, 0o600)
			})
			secureio.Zero(encoded)
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK:        true,
					Algorithm: name,
					Outputs:   map[string]string{"key": absoluteOutput(output)},
					Data:      map[string]int{"bits": bits},
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Symmetric key: %s (%s, %d bits)\n", output, name, bits)
			return nil
		},
	}
	command.Flags().StringVarP(&output, "out", "o", "", "symmetric-key output path")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	return command
}
