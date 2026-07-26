// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/policy"
	"github.com/spf13/cobra"
)

func newHashCommand(g *globals) *cobra.Command {
	var input string
	command := &cobra.Command{
		Use:   "hash <algorithm>",
		Short: "Hash a file with an OpenSSL digest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.ToLower(args[0])
			if err := validateAlgorithmName(name); err != nil {
				return err
			}
			if policy.IsLegacyDigest(name) && !g.allowLegacy {
				return ExitError{Code: 2, Err: fmt.Errorf("%s is legacy; pass --allow-legacy to use it", name)}
			}
			if err := requireInput(input); err != nil {
				return err
			}
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			digest, err := client.Run(cmd.Context(), "dgst", "-"+name, "-binary", input)
			if err != nil {
				return ExitError{Code: 3, Err: err}
			}
			encoded := hex.EncodeToString(digest)
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK:        true,
					Algorithm: name,
					Data:      map[string]string{"digest": encoded, "input": input},
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", encoded, input)
			return nil
		},
	}
	command.Flags().StringVarP(&input, "in", "i", "", "input file")
	return command
}
