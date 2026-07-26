// SPDX-License-Identifier: GPL-3.0-only

package rpcapi

import (
	"context"
	"encoding/json"
	"strconv"
)

func (s *Service) listAlgorithms(ctx context.Context, params AlgorithmsListParams) (json.RawMessage, error) {
	category := params.Category
	if category == "" {
		category = "keys"
	}
	arguments := []string{"algorithms", category}
	if params.All {
		arguments = append(arguments, "--all")
	}
	return s.runOperation(ctx, arguments, OperationParams{}, false)
}

func (s *Service) generateKey(ctx context.Context, params KeyGenerateParams) (json.RawMessage, error) {
	arguments := []string{"keygen", params.Algorithm, "--out", params.Out}
	arguments = stringFlag(arguments, "--public-out", params.PublicOut)
	arguments = intFlag(arguments, "--bits", params.Bits)
	arguments = stringFlag(arguments, "--curve", params.Curve)
	arguments = boolFlag(arguments, "--force", params.Force)
	arguments = stringFlag(arguments, "--openssl-name", params.OpenSSLName)
	for _, option := range params.PKeyOptions {
		arguments = append(arguments, "--pkeyopt", option)
	}
	arguments = legacyFlag(arguments, params.AllowLegacy)
	return s.runOperation(ctx, arguments, params.OperationParams, true)
}

func (s *Service) generateSymmetricKey(
	ctx context.Context,
	params SymmetricKeyGenerateParams,
) (json.RawMessage, error) {
	arguments := []string{"symkey", params.Algorithm, "--out", params.Out}
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, OperationParams{}, false)
}

func (s *Service) generateCertificate(
	ctx context.Context,
	params CertificateGenerateParams,
) (json.RawMessage, error) {
	arguments := []string{
		"certgen",
		"--key", params.Key,
		"--out", params.Out,
		"--subject", params.Subject,
	}
	arguments = intFlag(arguments, "--days", params.Days)
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, params.OperationParams, true)
}

func (s *Service) issueCertificate(
	ctx context.Context,
	params CertificateIssueParams,
) (json.RawMessage, error) {
	arguments := []string{
		"certissue",
		"--ca-cert", params.CACertificate,
		"--ca-key", params.CAKey,
		"--public-key", params.PublicKey,
		"--out", params.Out,
		"--subject", params.Subject,
	}
	arguments = intFlag(arguments, "--days", params.Days)
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, params.OperationParams, true)
}

func (s *Service) encryptFile(ctx context.Context, params FileEncryptParams) (json.RawMessage, error) {
	arguments := []string{"encrypt", "--in", params.In, "--out", params.Out}
	for _, recipient := range params.Recipients {
		arguments = append(arguments, "--recipient", recipient)
	}
	arguments = stringFlag(arguments, "--cipher", params.Cipher)
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, OperationParams{}, false)
}

func (s *Service) decryptFile(ctx context.Context, params FileDecryptParams) (json.RawMessage, error) {
	arguments := []string{
		"decrypt",
		"--in", params.In,
		"--out", params.Out,
		"--cert", params.Certificate,
		"--key", params.Key,
	}
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, params.OperationParams, true)
}

func (s *Service) encryptSymmetric(
	ctx context.Context,
	params SymmetricEncryptParams,
) (json.RawMessage, error) {
	arguments := []string{
		"sym-encrypt",
		"--in", params.In,
		"--out", params.Out,
		"--key", params.Key,
	}
	arguments = stringFlag(arguments, "--cipher", params.Cipher)
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, OperationParams{}, false)
}

func (s *Service) decryptSymmetric(
	ctx context.Context,
	params SymmetricDecryptParams,
) (json.RawMessage, error) {
	arguments := []string{
		"sym-decrypt",
		"--in", params.In,
		"--out", params.Out,
		"--key", params.Key,
	}
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, OperationParams{}, false)
}

func (s *Service) encryptPassword(ctx context.Context, params PasswordFileParams) (json.RawMessage, error) {
	arguments := []string{"pass-encrypt", "--in", params.In, "--out", params.Out}
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, OperationParams{SecretRef: params.SecretRef}, true)
}

func (s *Service) decryptPassword(ctx context.Context, params PasswordFileParams) (json.RawMessage, error) {
	arguments := []string{"pass-decrypt", "--in", params.In, "--out", params.Out}
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, OperationParams{SecretRef: params.SecretRef}, true)
}

func (s *Service) signFile(ctx context.Context, params SignParams) (json.RawMessage, error) {
	arguments := []string{
		"sign",
		"--in", params.In,
		"--key", params.Key,
		"--out", params.Out,
	}
	arguments = stringFlag(arguments, "--key-type", params.KeyType)
	arguments = stringFlag(arguments, "--digest", params.Digest)
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, params.OperationParams, true)
}

func (s *Service) verifyFile(ctx context.Context, params VerifyParams) (json.RawMessage, error) {
	arguments := []string{
		"verify",
		"--in", params.In,
		"--key", params.Key,
		"--signature", params.Signature,
	}
	arguments = stringFlag(arguments, "--key-type", params.KeyType)
	arguments = stringFlag(arguments, "--digest", params.Digest)
	return s.runOperation(ctx, arguments, OperationParams{}, false)
}

func (s *Service) hashFile(ctx context.Context, params HashParams) (json.RawMessage, error) {
	arguments := []string{"hash", params.Algorithm, "--in", params.In}
	arguments = legacyFlag(arguments, params.AllowLegacy)
	return s.runOperation(ctx, arguments, OperationParams{}, false)
}

func (s *Service) deriveKey(ctx context.Context, params DeriveParams) (json.RawMessage, error) {
	arguments := []string{
		"derive",
		"--key", params.Key,
		"--peer-key", params.PeerKey,
		"--out", params.Out,
	}
	arguments = boolFlag(arguments, "--force", params.Force)
	return s.runOperation(ctx, arguments, params.OperationParams, true)
}

func (s *Service) inspectFile(ctx context.Context, params InspectParams) (json.RawMessage, error) {
	arguments := []string{"inspect", "--in", params.In, "--type", params.Type}
	requiresSecretChoice := params.Type == "private-key"
	return s.runOperation(ctx, arguments, params.OperationParams, requiresSecretChoice)
}

func (s *Service) compatEncrypt(ctx context.Context, params CompatParams) (json.RawMessage, error) {
	return s.compat(ctx, params, false)
}

func (s *Service) compatDecrypt(ctx context.Context, params CompatParams) (json.RawMessage, error) {
	return s.compat(ctx, params, true)
}

func (s *Service) compat(ctx context.Context, params CompatParams, decrypt bool) (json.RawMessage, error) {
	operation := "encrypt"
	if decrypt {
		operation = "decrypt"
	}
	arguments := []string{
		"compat", operation,
		"--allow-unauthenticated",
		"--in", params.In,
		"--out", params.Out,
	}
	arguments = stringFlag(arguments, "--cipher", params.Cipher)
	arguments = boolFlag(arguments, "--force", params.Force)
	arguments = legacyFlag(arguments, params.AllowLegacy)
	return s.runOperation(ctx, arguments, OperationParams{SecretRef: params.SecretRef}, true)
}

func stringFlag(arguments []string, name, value string) []string {
	if value != "" {
		return append(arguments, name, value)
	}
	return arguments
}

func intFlag(arguments []string, name string, value int) []string {
	if value != 0 {
		return append(arguments, name, strconv.Itoa(value))
	}
	return arguments
}

func boolFlag(arguments []string, name string, value bool) []string {
	if value {
		return append(arguments, name)
	}
	return arguments
}

func legacyFlag(arguments []string, allow bool) []string {
	if allow {
		return append([]string{"--allow-legacy"}, arguments...)
	}
	return arguments
}
