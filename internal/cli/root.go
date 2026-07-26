// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ExitError carries the stable public CLI exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e ExitError) Error() string {
	return e.Err.Error()
}

func (e ExitError) Unwrap() error {
	return e.Err
}

type globals struct {
	opensslPath string
	jsonOutput  bool
	verbose     bool
	allowLegacy bool
	version     string
	commit      string
	date        string
}

// New constructs the CryptoWrapper command tree.
func New(version, commit, date string) *cobra.Command {
	g := &globals{
		version: version,
		commit:  commit,
		date:    date,
	}

	root := &cobra.Command{
		Use:           "cw",
		Short:         "A safer, simpler Go CLI wrapper for OpenSSL",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.SetVersionTemplate(fmt.Sprintf("cw %s (commit %s, built %s)\n", version, commit, date))
	root.PersistentFlags().StringVar(&g.opensslPath, "openssl", "", "path to the openssl executable")
	root.PersistentFlags().BoolVar(&g.jsonOutput, "json", false, "emit stable JSON output")
	root.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "show sanitized OpenSSL commands")
	root.PersistentFlags().BoolVar(&g.allowLegacy, "allow-legacy", false, "allow explicitly requested legacy algorithms")

	root.AddCommand(newVersionCommand(g))
	root.AddCommand(newDoctorCommand(g))
	root.AddCommand(newAlgorithmsCommand(g))
	root.AddCommand(newKeygenCommand(g))
	root.AddCommand(newSymKeyCommand(g))
	root.AddCommand(newCertGenCommand(g))
	root.AddCommand(newCertIssueCommand(g))
	root.AddCommand(newSignCommand(g))
	root.AddCommand(newVerifyCommand(g))
	root.AddCommand(newHashCommand(g))
	root.AddCommand(newDeriveCommand(g))
	root.AddCommand(newInspectCommand(g))
	root.AddCommand(newCompletionCommand(root))

	return root
}

func newVersionCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK: true,
					Data: map[string]string{
						"version": g.version,
						"commit":  g.commit,
						"date":    g.date,
					},
				})
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "cw %s (commit %s, built %s)\n", g.version, g.commit, g.date)
			return err
		},
	}
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish]",
		Short:     "Generate shell completion",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			default:
				return ExitError{Code: 2, Err: fmt.Errorf("unsupported shell %q", args[0])}
			}
		},
	}
}
