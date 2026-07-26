// SPDX-License-Identifier: GPL-3.0-only

// Package rpcapi exposes CryptoWrapper operations through a versioned
// JSON-RPC 2.0 protocol. The transport is deliberately separate from the
// cryptographic implementation so desktop applications do not need to
// reconstruct OpenSSL command lines.
package rpcapi

import (
	"context"
	"encoding/json"
)

const (
	ProtocolVersion = "1"
	SchemaVersion   = "1"
)

// Runner executes one already-validated CLI operation in-process. Secret is
// supplied separately from the JSON request and must be cleared by the caller.
type Runner func(ctx context.Context, arguments []string, secret []byte) (json.RawMessage, *CommandError)

// CommandError is the transport-independent form of a stable CLI failure.
type CommandError struct {
	ExitCode int
	Message  string
}

// Config describes one RPC server instance.
type Config struct {
	Version        string
	Commit         string
	BuildDate      string
	OpenSSLPath    string
	CMSAvailable   bool
	LibraryVersion string
	Runner         Runner
}

// HandshakeResult is returned by system.handshake and system.capabilities.
type HandshakeResult struct {
	ProtocolVersion string            `json:"protocol_version"`
	SchemaVersion   string            `json:"schema_version"`
	Product         string            `json:"product"`
	Version         string            `json:"version"`
	Commit          string            `json:"commit"`
	BuildDate       string            `json:"build_date"`
	Transport       string            `json:"transport"`
	Methods         []string          `json:"methods"`
	Features        map[string]bool   `json:"features"`
	SecretChannel   SecretChannelInfo `json:"secret_channel"`
	Runtime         RuntimeInfo       `json:"runtime"`
}

type SecretChannelInfo struct {
	Available bool   `json:"available"`
	Framing   string `json:"framing,omitempty"`
	MaxBytes  int    `json:"max_bytes,omitempty"`
}

type RuntimeInfo struct {
	OpenSSLOverride string `json:"openssl_override,omitempty"`
	CMSAvailable    bool   `json:"cms_available"`
	LibraryVersion  string `json:"library_version"`
}

// OperationParams contains controls shared by operations involving a private
// key or password. SecretRef identifies a frame on the independent secret
// channel; NoPassphrase explicitly selects an unencrypted key.
type OperationParams struct {
	SecretRef    string `json:"secret_ref,omitempty"`
	NoPassphrase bool   `json:"no_passphrase,omitempty"`
}

type AlgorithmsListParams struct {
	Category string `json:"category,omitempty"`
	All      bool   `json:"all,omitempty"`
}

type KeyGenerateParams struct {
	OperationParams
	Algorithm   string   `json:"algorithm"`
	Out         string   `json:"out"`
	PublicOut   string   `json:"public_out,omitempty"`
	Bits        int      `json:"bits,omitempty"`
	Curve       string   `json:"curve,omitempty"`
	Force       bool     `json:"force,omitempty"`
	AllowLegacy bool     `json:"allow_legacy,omitempty"`
	OpenSSLName string   `json:"openssl_name,omitempty"`
	PKeyOptions []string `json:"pkeyopt,omitempty"`
}

type SymmetricKeyGenerateParams struct {
	Algorithm string `json:"algorithm"`
	Out       string `json:"out"`
	Force     bool   `json:"force,omitempty"`
}

type CertificateGenerateParams struct {
	OperationParams
	Key     string `json:"key"`
	Out     string `json:"out"`
	Subject string `json:"subject"`
	Days    int    `json:"days,omitempty"`
	Force   bool   `json:"force,omitempty"`
}

type CertificateIssueParams struct {
	OperationParams
	CACertificate string `json:"ca_certificate"`
	CAKey         string `json:"ca_key"`
	PublicKey     string `json:"public_key"`
	Out           string `json:"out"`
	Subject       string `json:"subject"`
	Days          int    `json:"days,omitempty"`
	Force         bool   `json:"force,omitempty"`
}

type FileEncryptParams struct {
	In         string   `json:"in"`
	Out        string   `json:"out"`
	Recipients []string `json:"recipients"`
	Cipher     string   `json:"cipher,omitempty"`
	Force      bool     `json:"force,omitempty"`
}

type FileDecryptParams struct {
	OperationParams
	In          string `json:"in"`
	Out         string `json:"out"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Force       bool   `json:"force,omitempty"`
}

type SymmetricEncryptParams struct {
	In     string `json:"in"`
	Out    string `json:"out"`
	Key    string `json:"key"`
	Cipher string `json:"cipher,omitempty"`
	Force  bool   `json:"force,omitempty"`
}

type SymmetricDecryptParams struct {
	In    string `json:"in"`
	Out   string `json:"out"`
	Key   string `json:"key"`
	Force bool   `json:"force,omitempty"`
}

type PasswordFileParams struct {
	SecretRef string `json:"secret_ref"`
	In        string `json:"in"`
	Out       string `json:"out"`
	Force     bool   `json:"force,omitempty"`
}

type SignParams struct {
	OperationParams
	In      string `json:"in"`
	Key     string `json:"key"`
	Out     string `json:"out"`
	KeyType string `json:"key_type,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Force   bool   `json:"force,omitempty"`
}

type VerifyParams struct {
	In        string `json:"in"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
	KeyType   string `json:"key_type,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type HashParams struct {
	In          string `json:"in"`
	Algorithm   string `json:"algorithm"`
	AllowLegacy bool   `json:"allow_legacy,omitempty"`
}

type DeriveParams struct {
	OperationParams
	Key     string `json:"key"`
	PeerKey string `json:"peer_key"`
	Out     string `json:"out"`
	Force   bool   `json:"force,omitempty"`
}

type InspectParams struct {
	OperationParams
	In   string `json:"in"`
	Type string `json:"type"`
}

type CompatParams struct {
	SecretRef   string `json:"secret_ref"`
	In          string `json:"in"`
	Out         string `json:"out"`
	Cipher      string `json:"cipher,omitempty"`
	Force       bool   `json:"force,omitempty"`
	AllowLegacy bool   `json:"allow_legacy,omitempty"`
}

type CancelParams struct {
	RequestID json.RawMessage `json:"request_id"`
}

type ProgressNotification struct {
	RequestID json.RawMessage `json:"request_id,omitempty"`
	Method    string          `json:"method"`
	Stage     string          `json:"stage"`
}
