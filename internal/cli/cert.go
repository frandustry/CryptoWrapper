// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/frandustry/CryptoWrapper/internal/secureio"
	"github.com/spf13/cobra"
)

func newCertGenCommand(g *globals) *cobra.Command {
	var (
		key       string
		output    string
		subject   string
		days      int
		force     bool
		passFlags passphraseFlags
	)
	command := &cobra.Command{
		Use:   "certgen",
		Short: "Generate a self-signed X.509 certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if key == "" || output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--key and --out are required")}
			}
			if subject == "" || subject[0] != '/' {
				return ExitError{Code: 2, Err: fmt.Errorf("--subject must use OpenSSL form such as /CN=Alice")}
			}
			if days < 1 {
				return ExitError{Code: 2, Err: fmt.Errorf("--days must be positive")}
			}
			passphrase, err := passFlags.read(false, "Private-key passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			err = secureio.AtomicPath(output, 0o644, force, func(temp string) error {
				args := []string{
					"req", "-new", "-x509", "-key", key,
					"-subj", subject, "-days", strconv.Itoa(days),
					"-out", temp,
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
			fingerprint, err := fileFingerprint(cmd.Context(), client, "certificate", output)
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return printCertificateResult(cmd, g, output, fingerprint)
		},
	}
	command.Flags().StringVar(&key, "key", "", "private key path")
	command.Flags().StringVarP(&output, "out", "o", "", "certificate output path")
	command.Flags().StringVar(&subject, "subject", "", "X.509 subject, for example /CN=Alice")
	command.Flags().IntVar(&days, "days", 365, "certificate validity in days")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	addPassphraseFlags(command, &passFlags, true)
	return command
}

func newCertIssueCommand(g *globals) *cobra.Command {
	var (
		caCertificate string
		caKey         string
		publicKey     string
		output        string
		subject       string
		days          int
		force         bool
		passFlags     passphraseFlags
	)
	command := &cobra.Command{
		Use:   "certissue",
		Short: "Issue an X.509 certificate for a public key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if caCertificate == "" || caKey == "" || publicKey == "" || output == "" {
				return ExitError{Code: 2, Err: fmt.Errorf("--ca-cert, --ca-key, --public-key, and --out are required")}
			}
			if subject == "" || subject[0] != '/' {
				return ExitError{Code: 2, Err: fmt.Errorf("--subject must use OpenSSL form such as /CN=Recipient")}
			}
			if days < 1 {
				return ExitError{Code: 2, Err: fmt.Errorf("--days must be positive")}
			}
			serialBytes := make([]byte, 20)
			if _, err := rand.Read(serialBytes); err != nil {
				return ExitError{Code: 1, Err: fmt.Errorf("generate certificate serial: %w", err)}
			}
			serialBytes[0] &= 0x7f
			serial := "0x" + hex.EncodeToString(serialBytes)
			secureio.Zero(serialBytes)
			passphrase, err := passFlags.read(false, "CA private-key passphrase: ")
			if err != nil {
				return ExitError{Code: 2, Err: err}
			}
			defer secureio.Zero(passphrase)
			client, err := clientFor(cmd.Context(), g)
			if err != nil {
				return err
			}
			err = secureio.AtomicPath(output, 0o644, force, func(temp string) error {
				args := []string{
					"x509", "-new", "-force_pubkey", publicKey,
					"-subj", subject,
					"-CA", caCertificate, "-CAkey", caKey,
					"-set_serial", serial, "-days", strconv.Itoa(days),
					"-out", temp,
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
			fingerprint, err := fileFingerprint(cmd.Context(), client, "certificate", output)
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return printCertificateResult(cmd, g, output, fingerprint)
		},
	}
	command.Flags().StringVar(&caCertificate, "ca-cert", "", "issuer certificate path")
	command.Flags().StringVar(&caKey, "ca-key", "", "issuer private-key path")
	command.Flags().StringVar(&publicKey, "public-key", "", "subject public-key path")
	command.Flags().StringVarP(&output, "out", "o", "", "issued certificate output path")
	command.Flags().StringVar(&subject, "subject", "", "X.509 subject, for example /CN=Recipient")
	command.Flags().IntVar(&days, "days", 365, "certificate validity in days")
	command.Flags().BoolVarP(&force, "force", "f", false, "replace an existing regular file")
	addPassphraseFlags(command, &passFlags, true)
	return command
}

func printCertificateResult(cmd *cobra.Command, g *globals, output, fingerprint string) error {
	if g.jsonOutput {
		return writeJSON(cmd.OutOrStdout(), result{
			OK:           true,
			Outputs:      map[string]string{"certificate": absoluteOutput(output)},
			Fingerprints: map[string]string{"certificate": fingerprint},
		})
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Certificate: %s\nFingerprint: %s\n", output, fingerprint)
	return nil
}
