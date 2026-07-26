// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/frandustry/CryptoWrapper/internal/cmslib"
	"github.com/frandustry/CryptoWrapper/internal/openssl"
	"github.com/spf13/cobra"
)

func clientFor(ctx context.Context, g *globals) (*openssl.Client, error) {
	client, err := openssl.Resolve(g.opensslPath)
	if err != nil {
		return nil, ExitError{Code: 3, Err: err}
	}
	client.Verbose = g.verbose
	client.Log = os.Stderr
	if _, err := client.RequireSupported(ctx); err != nil {
		return nil, ExitError{Code: 3, Err: err}
	}
	return client, nil
}

func validateLibcryptoVersion(raw string) (openssl.Version, error) {
	version, err := openssl.ParseVersion(raw)
	if err != nil {
		return openssl.Version{}, fmt.Errorf(
			"cannot use linked libcrypto: %w; rebuild CryptoWrapper with OpenSSL 3.6.3+ or 4.0.1+, then run 'cw doctor'",
			err,
		)
	}
	if !version.Supported() {
		return openssl.Version{}, fmt.Errorf(
			"unsupported linked libcrypto %s; rebuild CryptoWrapper with OpenSSL 3.6.3+ or 4.0.1+, then run 'cw doctor'",
			version,
		)
	}
	return version, nil
}

func requireSupportedLibcrypto(command string) error {
	if !cmslib.Available() {
		return ExitError{Code: 3, Err: fmt.Errorf("%s requires a CGO build linked with libcrypto", command)}
	}
	if _, err := validateLibcryptoVersion(cmslib.LibraryVersion()); err != nil {
		return ExitError{Code: 3, Err: err}
	}
	return nil
}

func newDoctorCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check OpenSSL and provider compatibility",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			version, err := client.Version(ctx)
			if err != nil {
				return ExitError{Code: 3, Err: err}
			}
			providers, err := client.Providers(ctx)
			if err != nil {
				return ExitError{Code: 3, Err: err}
			}
			if !version.Supported() {
				return ExitError{Code: 3, Err: fmt.Errorf(
					"unsupported OpenSSL %s; require 3.6.3+ or 4.0.1+", version)}
			}
			libcryptoData := map[string]any{
				"available": cmslib.Available(),
				"version":   cmslib.LibraryVersion(),
			}
			if cmslib.Available() {
				libraryVersion, parseErr := validateLibcryptoVersion(cmslib.LibraryVersion())
				if parseErr != nil {
					return ExitError{Code: 3, Err: parseErr}
				}
				libcryptoData["parsed_version"] = libraryVersion
				if libraryVersion.Major != version.Major || libraryVersion.Minor != version.Minor {
					return ExitError{Code: 3, Err: fmt.Errorf(
						"openssl CLI %s and libcrypto %s must use the same major/minor series",
						version, libraryVersion)}
				}
			}
			data := map[string]any{
				"openssl_path": client.Path,
				"version":      version,
				"providers":    providers,
				"supported":    true,
				"libcrypto":    libcryptoData,
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{OK: true, Data: data})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OpenSSL: %s (%s)\n", version, client.Path)
			fmt.Fprintf(cmd.OutOrStdout(), "Providers: %s\n", strings.Join(providers, ", "))
			fmt.Fprintf(cmd.OutOrStdout(), "libcrypto: %s\n", cmslib.LibraryVersion())
			fmt.Fprintln(cmd.OutOrStdout(), "Status: supported")
			return nil
		},
	}
}

func newAlgorithmsCommand(g *globals) *cobra.Command {
	var all bool
	command := &cobra.Command{
		Use:       "algorithms [keys|ciphers|digests|signatures]",
		Short:     "List algorithms exposed by OpenSSL providers",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"keys", "ciphers", "digests", "signatures"},
		RunE: func(cmd *cobra.Command, args []string) error {
			category := "keys"
			if len(args) == 1 {
				category = strings.ToLower(args[0])
			}
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			names, err := client.ListAlgorithms(cmd.Context(), category)
			if err != nil {
				return ExitError{Code: 3, Err: err}
			}
			if !all {
				names = filterLegacy(names)
			}
			if g.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result{
					OK:   true,
					Data: map[string]any{"category": category, "algorithms": names},
				})
			}
			for _, name := range names {
				fmt.Fprintln(cmd.OutOrStdout(), name)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&all, "all", false, "include legacy algorithms")
	return command
}

func filterLegacy(names []string) []string {
	legacy := []string{"DES", "RC2", "RC4", "BLOWFISH", "CAST", "IDEA", "MD5", "SHA1", "DSA"}
	filtered := make([]string, 0, len(names))
	for _, name := range names {
		upper := strings.ToUpper(name)
		blocked := false
		for _, marker := range legacy {
			if strings.Contains(upper, marker) {
				blocked = true
				break
			}
		}
		if !blocked {
			filtered = append(filtered, name)
		}
	}
	return filtered
}
