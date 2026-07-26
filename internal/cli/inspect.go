// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"fmt"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newInspectCommand(g *globals) *cobra.Command {
	var (
		input     string
		kind      string
		passFlags passphraseFlags
	)
	command := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a key, certificate, or CMS file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireInput(input); err != nil {
				return err
			}
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			kind = strings.ToLower(kind)
			var args []string
			var usePassphrase bool
			switch kind {
			case "public-key":
				args = []string{"pkey", "-pubin", "-in", input, "-text", "-noout"}
			case "private-key":
				args = []string{"pkey", "-in", input, "-text", "-noout"}
				usePassphrase = true
			case "certificate":
				args = []string{"x509", "-in", input, "-text", "-noout"}
			case "cms":
				args = []string{"cms", "-cmsout", "-inform", "DER", "-in", input, "-print"}
			default:
				return ExitError{Code: 2, Err: fmt.Errorf("--type must be public-key, private-key, certificate, or cms")}
			}
			var output []byte
			if usePassphrase {
				passphrase, passErr := passFlags.read(false, "Private-key passphrase: ")
				if passErr != nil {
					return ExitError{Code: 2, Err: passErr}
				}
				defer secureio.Zero(passphrase)
				if passphrase != nil {
					args = append(args, "-passin", "fd:3")
					output, err = client.RunPassphrase(cmd.Context(), passphrase, args...)
				} else {
					output, err = client.Run(cmd.Context(), args...)
				}
			} else {
				output, err = client.Run(cmd.Context(), args...)
			}
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK:   true,
					Data: map[string]string{"type": kind, "text": string(output)},
				})
			}
			_, err = cmd.OutOrStdout().Write(output)
			return err
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	command.Flags().StringVar(&kind, "type", "", "public-key, private-key, certificate, or cms")
	addPassphraseFlags(command, &passFlags, true)
	return command
}
