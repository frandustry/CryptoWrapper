// SPDX-License-Identifier: GPL-3.0-only

package rpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/frandustry/CryptoWrapper/api"
)

const (
	errorGeneral      jrpc2.Code = 1001
	errorUsage        jrpc2.Code = 1002
	errorDependency   jrpc2.Code = 1003
	errorVerification jrpc2.Code = 1004
	errorSecret       jrpc2.Code = 1010
)

// Service owns the JSON-RPC method table and optional one-use secret channel.
type Service struct {
	config  Config
	secrets *SecretReader
	methods handler.Map
}

func New(config Config, secretReader io.Reader) (*Service, error) {
	if config.Runner == nil {
		return nil, errors.New("RPC runner is required")
	}
	service := &Service{
		config:  config,
		secrets: NewSecretReader(secretReader),
	}
	service.methods = service.methodHandlers()
	return service, nil
}

// Serve runs a newline-framed JSON-RPC 2.0 server until input closes or ctx is
// cancelled. stdout must be reserved exclusively for protocol messages.
func (s *Service) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	server := jrpc2.NewServer(s.methods, &jrpc2.ServerOptions{
		AllowPush:      true,
		Concurrency:    4,
		DisableBuiltin: true,
		NewContext: func() context.Context {
			return ctx
		},
	})
	server.Start(channel.Line(input, nopWriteCloser{output}))

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			server.Stop()
		case <-stopped:
		}
	}()
	status := server.WaitStatus()
	close(stopped)
	return status.Err
}

func (s *Service) methodNames() []string {
	names := make([]string, 0, len(s.methods))
	for name := range s.methods {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *Service) handshake() HandshakeResult {
	return HandshakeResult{
		ProtocolVersion: ProtocolVersion,
		SchemaVersion:   SchemaVersion,
		Product:         "CryptoWrapper",
		Version:         s.config.Version,
		Commit:          s.config.Commit,
		BuildDate:       s.config.BuildDate,
		Transport:       "json-rpc-2.0/stdio-line",
		Methods:         s.methodNames(),
		Features: map[string]bool{
			"cancellation":           true,
			"progress_notifications": true,
			"strict_parameters":      true,
			"secret_channel":         s.secrets != nil,
		},
		SecretChannel: SecretChannelInfo{
			Available: s.secrets != nil,
			Framing:   secretMagic,
			MaxBytes:  maxSecretBytes,
		},
		Runtime: RuntimeInfo{
			OpenSSLOverride: s.config.OpenSSLPath,
			CMSAvailable:    s.config.CMSAvailable,
			LibraryVersion:  s.config.LibraryVersion,
		},
	}
}

func (s *Service) methodHandlers() handler.Map {
	return handler.Map{
		"algorithms.list":       strict(s.listAlgorithms),
		"certificate.generate":  strict(s.generateCertificate),
		"certificate.issue":     strict(s.issueCertificate),
		"compat.decrypt":        strict(s.compatDecrypt),
		"compat.encrypt":        strict(s.compatEncrypt),
		"file.decrypt":          strict(s.decryptFile),
		"file.decryptPassword":  strict(s.decryptPassword),
		"file.decryptSymmetric": strict(s.decryptSymmetric),
		"file.encrypt":          strict(s.encryptFile),
		"file.encryptPassword":  strict(s.encryptPassword),
		"file.encryptSymmetric": strict(s.encryptSymmetric),
		"file.hash":             strict(s.hashFile),
		"file.inspect":          strict(s.inspectFile),
		"file.sign":             strict(s.signFile),
		"file.verify":           strict(s.verifyFile),
		"key.derive":            strict(s.deriveKey),
		"key.generate":          strict(s.generateKey),
		"key.generateSymmetric": strict(s.generateSymmetricKey),
		"operation.cancel":      strict(s.cancelOperation),
		"rpc.discover":          strict(s.discover),
		"system.capabilities":   strict(s.systemCapabilities),
		"system.doctor":         strict(s.systemDoctor),
		"system.handshake":      strict(s.systemHandshake),
	}
}

func (s *Service) discover(context.Context) json.RawMessage {
	return append(json.RawMessage(nil), api.OpenRPC...)
}

func strict(function any) jrpc2.Handler {
	info, err := handler.Check(function)
	if err != nil {
		panic(err)
	}
	return info.SetStrict(true).AllowArray(false).Wrap()
}

func (s *Service) systemHandshake(context.Context) HandshakeResult {
	return s.handshake()
}

func (s *Service) systemCapabilities(context.Context) HandshakeResult {
	return s.handshake()
}

func (s *Service) systemDoctor(ctx context.Context) (json.RawMessage, error) {
	return s.runOperation(ctx, []string{"doctor"}, OperationParams{}, false)
}

func (s *Service) cancelOperation(ctx context.Context, params CancelParams) (map[string]any, error) {
	if len(params.RequestID) == 0 || string(params.RequestID) == "null" {
		return nil, jrpc2.Errorf(jrpc2.InvalidParams, "request_id is required")
	}
	jrpc2.ServerFromContext(ctx).CancelRequest(string(params.RequestID))
	return map[string]any{
		"schema_version": SchemaVersion,
		"requested":      true,
		"request_id":     params.RequestID,
	}, nil
}

func (s *Service) runOperation(
	ctx context.Context,
	arguments []string,
	secretParams OperationParams,
	requireSecretChoice bool,
) (json.RawMessage, error) {
	if secretParams.SecretRef != "" && secretParams.NoPassphrase {
		return nil, jrpc2.Errorf(jrpc2.InvalidParams, "secret_ref and no_passphrase are mutually exclusive")
	}
	if requireSecretChoice && secretParams.SecretRef == "" && !secretParams.NoPassphrase {
		return nil, jrpc2.Errorf(jrpc2.InvalidParams, "set secret_ref or explicitly set no_passphrase")
	}

	s.notifyProgress(ctx, "started")
	var secret []byte
	if secretParams.SecretRef != "" {
		s.notifyProgress(ctx, "awaiting_secret")
		var err error
		secret, err = s.secrets.Read(secretParams.SecretRef)
		if err != nil {
			s.notifyProgress(ctx, "failed")
			return nil, secretError(err)
		}
		defer zero(secret)
	}
	if secretParams.NoPassphrase {
		arguments = append(arguments, "--no-passphrase")
	}

	s.notifyProgress(ctx, "running")
	result, commandError := s.config.Runner(ctx, arguments, secret)
	if ctx.Err() != nil {
		s.notifyProgress(ctx, "cancelled")
		return nil, ctx.Err()
	}
	if commandError != nil {
		s.notifyProgress(ctx, "failed")
		return nil, commandRPCError(commandError)
	}
	s.notifyProgress(ctx, "completed")
	return result, nil
}

func (s *Service) notifyProgress(ctx context.Context, stage string) {
	request := jrpc2.InboundRequest(ctx)
	if request == nil || request.IsNotification() {
		return
	}
	_ = jrpc2.ServerFromContext(ctx).Notify(ctx, "operation.progress", ProgressNotification{
		RequestID: json.RawMessage(request.ID()),
		Method:    request.Method(),
		Stage:     stage,
	})
}

func commandRPCError(commandError *CommandError) error {
	code := errorGeneral
	switch commandError.ExitCode {
	case 2:
		code = errorUsage
	case 3:
		code = errorDependency
	case 4:
		code = errorVerification
	}
	return (&jrpc2.Error{
		Code:    code,
		Message: commandError.Message,
	}).WithData(map[string]any{
		"schema_version": SchemaVersion,
		"cli_exit_code":  commandError.ExitCode,
	})
}

func secretError(err error) error {
	return (&jrpc2.Error{
		Code:    errorSecret,
		Message: err.Error(),
	}).WithData(map[string]any{"schema_version": SchemaVersion})
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
