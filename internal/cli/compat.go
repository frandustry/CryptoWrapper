// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newCompatCommand(g *globals) *cobra.Command {
	command := &cobra.Command{
		Use:   "compat",
		Short: "Explicitly use unauthenticated OpenSSL enc compatibility formats",
	}
	command.AddCommand(newCompatCryptCommand(g, false))
	command.AddCommand(newCompatCryptCommand(g, true))
	return command
}

func newCompatCryptCommand(g *globals, decrypt bool) *cobra.Command {
	var (
		input                string
		output               string
		cipher               string
		force                bool
		allowUnauthenticated bool
		passFlags            passphraseFlags
	)
	use := "encrypt"
	short := "Encrypt using the unauthenticated OpenSSL enc format"
	if decrypt {
		use = "decrypt"
		short = "Decrypt the unauthenticated OpenSSL enc format"
	}
	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !allowUnauthenticated {
				return ExitError{Code: 2, Err: fmt.Errorf("--allow-unauthenticated is required for OpenSSL enc compatibility")}
			}
			if err := requireInput(input); err != nil {
				return err
			}
			if output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--out is required")}
			}
			cipher = strings.ToLower(cipher)
			if err := validateAlgorithmName(cipher); err != nil {
				return err
			}
			if isLegacyCipher(cipher) && !g.allowLegacy {
				return ExitError{Code: 2, Err: fmt.Errorf("%s is legacy; also pass --allow-legacy", cipher)}
			}
			passphrase, err := passFlags.read(!decrypt, "Compatibility encryption passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			mode := secureioMode(decrypt)
			err = secureio.AtomicPath(output, mode, force, func(temp string) error {
				args := []string{"enc", "-" + cipher, "-pbkdf2", "-iter", "600000", "-md", "sha256", "-in", input, "-out", temp, "-pass", "fd:3"}
				if decrypt {
					args = append(args, "-d")
				}
				_, runErr := client.RunPassphrase(cmd.Context(), passphrase, args...)
				return runErr
			})
			if err != nil {
				code := 1
				if decrypt {
					code = 4
				}
				return ExitError{Code: code, Err: err}
			}
			if decrypt {
				return printDecryptionResult(cmd, g, output)
			}
			return printEncryptionResult(cmd, g, cipher, output, 0)
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	command.Flags().StringVarP(&output, "out", "o", "", "output file")
	command.Flags().StringVar(&cipher, "cipher", "chacha20", "OpenSSL enc cipher")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	command.Flags().BoolVar(&allowUnauthenticated, "allow-unauthenticated", false, "acknowledge that enc provides no authentication")
	addPassphraseFlags(command, &passFlags, false)
	return command
}

func secureioMode(decrypt bool) os.FileMode {
	if decrypt {
		return 0o600
	}
	return 0o644
}

func isLegacyCipher(name string) bool {
	for _, marker := range []string{"des", "rc2", "rc4", "bf", "blowfish", "cast", "idea"} {
		if name == marker || strings.HasPrefix(name, marker+"-") {
			return true
		}
	}
	return false
}
