// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"fmt"

	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newDeriveCommand(g *globals) *cobra.Command {
	var (
		key       string
		peerKey   string
		output    string
		force     bool
		passFlags passphraseFlags
	)
	command := &cobra.Command{
		Use:   "derive",
		Short: "Derive an (EC)DH shared secret",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if key == "" || peerKey == "" || output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--key, --peer-key, and --out are required")}
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
					"pkeyutl", "-derive", "-inkey", key, "-peerkey", peerKey, "-out", temp,
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
				return ExitError{Code: 1, Err: err}
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK:      true,
					Outputs: map[string]string{"secret": absoluteOutput(output)},
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Derived secret: %s\n", output)
			return nil
		},
	}
	command.Flags().StringVar(&key, "key", "", "private-key path")
	command.Flags().StringVar(&peerKey, "peer-key", "", "peer public-key path")
	command.Flags().StringVarP(&output, "out", "o", "", "derived-secret output path")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	addPassphraseFlags(command, &passFlags, true)
	return command
}
