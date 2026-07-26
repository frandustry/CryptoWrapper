// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/frandustry/CryptoWrapper/internal/cmslib"
	"github.com/frandustry/CryptoWrapper/internal/rpcapi"
	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newRPCCommand(g *globals) *cobra.Command {
	var (
		stdio    bool
		secretFD int
	)
	command := &cobra.Command{
		Use:   "rpc",
		Short: "Serve the versioned JSON-RPC API for local applications",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !stdio {
				return ExitError{Code: 2, Err: fmt.Errorf("--stdio is required")}
			}
			if g.jsonOutput {
				return ExitError{Code: 2, Err: fmt.Errorf("--json cannot be combined with rpc --stdio")}
			}

			var (
				secretReader io.Reader
				secretFile   *os.File
			)
			if secretFD >= 0 {
				if secretFD <= int(os.Stderr.Fd()) {
					return ExitError{Code: 2, Err: fmt.Errorf("--secret-fd must be greater than 2")}
				}
				secretFile = os.NewFile(uintptr(secretFD), "cw-rpc-secret")
				if secretFile == nil {
					return ExitError{Code: 2, Err: fmt.Errorf("invalid --secret-fd %d", secretFD)}
				}
				defer secretFile.Close()
				secretReader = secretFile
			}

			service, err := rpcapi.New(rpcapi.Config{
				Version:        g.version,
				Commit:         g.commit,
				BuildDate:      g.date,
				OpenSSLPath:    g.opensslPath,
				CMSAvailable:   cmslib.Available(),
				LibraryVersion: cmslib.LibraryVersion(),
				Runner:         rpcCommandRunner(g),
			}, secretReader)
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			if err := service.Serve(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout()); err != nil {
				return ExitError{Code: 1, Err: fmt.Errorf("RPC server: %w", err)}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&stdio, "stdio", false, "use newline-framed JSON-RPC over stdin/stdout")
	command.Flags().IntVar(&secretFD, "secret-fd", -1, "read one-use CWS1 secret frames from this inherited file descriptor")
	return command
}

func rpcCommandRunner(g *globals) rpcapi.Runner {
	return func(ctx context.Context, arguments []string, secret []byte) (json.RawMessage, *rpcapi.CommandError) {
		command := New(g.version, g.commit, g.date)
		command.SetContext(ctx)
		var stdout bytes.Buffer
		command.SetOut(&stdout)
		command.SetErr(io.Discard)

		rootArguments := []string{"--json"}
		if g.opensslPath != "" {
			rootArguments = append(rootArguments, "--openssl", g.opensslPath)
		}
		if g.verbose {
			rootArguments = append(rootArguments, "--verbose")
		}
		rootArguments = append(rootArguments, arguments...)
		command.SetArgs(rootArguments)
		if secret != nil {
			command.SetContext(secureio.WithPassphrase(ctx, secret))
		}

		if err := command.Execute(); err != nil {
			code := 1
			var exitError ExitError
			if errors.As(err, &exitError) {
				code = exitError.Code
			}
			return nil, &rpcapi.CommandError{ExitCode: code, Message: err.Error()}
		}
		payload := bytes.TrimSpace(stdout.Bytes())
		if !json.Valid(payload) {
			return nil, &rpcapi.CommandError{
				ExitCode: 1,
				Message:  "operation returned invalid JSON",
			}
		}
		return append(json.RawMessage(nil), payload...), nil
	}
}
