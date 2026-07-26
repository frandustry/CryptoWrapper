// SPDX-License-Identifier: GPL-3.0-only

package rpcapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"
)

const (
	secretMagic       = "CWS1"
	maxSecretRefBytes = 256
	maxSecretBytes    = 64 * 1024
	secretHeaderBytes = 10
	maxPendingSecrets = 32
)

// SecretReader consumes binary frames from a channel independent of JSON-RPC.
// A background pump demultiplexes one-use frames by opaque reference, so
// concurrent operations do not depend on handler scheduling order.
type SecretReader struct {
	reader  io.Reader
	closer  io.Closer
	once    sync.Once
	mu      sync.Mutex
	pending map[string][]byte
	update  chan struct{}
	err     error
	closed  bool
}

func NewSecretReader(reader io.Reader) *SecretReader {
	if reader == nil {
		return nil
	}
	secretReader := &SecretReader{
		reader:  reader,
		pending: make(map[string][]byte),
		update:  make(chan struct{}),
	}
	if closer, ok := reader.(io.Closer); ok {
		secretReader.closer = closer
	}
	return secretReader
}

func (s *SecretReader) Read(ctx context.Context, expectedRef string) ([]byte, error) {
	if s == nil || s.reader == nil {
		return nil, errors.New("secret channel is unavailable")
	}
	if expectedRef == "" || len(expectedRef) > maxSecretRefBytes || !utf8.ValidString(expectedRef) {
		return nil, errors.New("secret_ref must contain 1 to 256 bytes")
	}
	s.once.Do(func() { go s.pump() })

	for {
		s.mu.Lock()
		if secret, ok := s.pending[expectedRef]; ok {
			delete(s.pending, expectedRef)
			s.mu.Unlock()
			return secret, nil
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return nil, fmt.Errorf("read secret_ref frame: %w", err)
		}
		update := s.update
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-update:
		}
	}
}

func (s *SecretReader) pump() {
	for {
		reference, secret, err := readSecretFrame(s.reader)
		s.mu.Lock()
		if err != nil {
			s.setErrorLocked(err, false)
			s.mu.Unlock()
			return
		}
		if s.closed {
			zero(secret)
			s.mu.Unlock()
			return
		}
		if _, exists := s.pending[reference]; exists {
			zero(secret)
			s.setErrorLocked(errors.New("duplicate secret frame reference"), true)
			s.mu.Unlock()
			return
		}
		if len(s.pending) >= maxPendingSecrets {
			zero(secret)
			s.setErrorLocked(fmt.Errorf("more than %d unclaimed secret frames", maxPendingSecrets), true)
			s.mu.Unlock()
			return
		}
		s.pending[reference] = secret
		s.signalLocked()
		s.mu.Unlock()
	}
}

func readSecretFrame(reader io.Reader) (string, []byte, error) {
	header := make([]byte, secretHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", nil, fmt.Errorf("read secret frame header: %w", err)
	}
	if string(header[:4]) != secretMagic {
		return "", nil, errors.New("invalid secret frame magic")
	}
	refLength := int(binary.BigEndian.Uint16(header[4:6]))
	secretLength := int(binary.BigEndian.Uint32(header[6:10]))
	if refLength < 1 || refLength > maxSecretRefBytes {
		return "", nil, fmt.Errorf("secret frame reference length %d is invalid", refLength)
	}
	if secretLength > maxSecretBytes {
		return "", nil, fmt.Errorf("secret frame payload exceeds %d bytes", maxSecretBytes)
	}

	reference := make([]byte, refLength)
	if _, err := io.ReadFull(reader, reference); err != nil {
		return "", nil, fmt.Errorf("read secret frame reference: %w", err)
	}
	if !utf8.Valid(reference) {
		zero(reference)
		return "", nil, errors.New("secret frame reference is not valid UTF-8")
	}
	secret := make([]byte, secretLength)
	if _, err := io.ReadFull(reader, secret); err != nil {
		zero(secret)
		zero(reference)
		return "", nil, fmt.Errorf("read secret frame payload: %w", err)
	}
	referenceString := string(reference)
	zero(reference)
	return referenceString, secret, nil
}

func (s *SecretReader) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	closer := s.closer
	s.setErrorLocked(errors.New("secret channel closed"), true)
	s.mu.Unlock()
	if closer != nil {
		_ = closer.Close()
	}
}

func (s *SecretReader) setErrorLocked(err error, clearPending bool) {
	if s.err == nil {
		s.err = err
	}
	if clearPending {
		for reference, secret := range s.pending {
			zero(secret)
			delete(s.pending, reference)
		}
	}
	s.signalLocked()
}

func (s *SecretReader) signalLocked() {
	close(s.update)
	s.update = make(chan struct{})
}

// AppendSecretFrame is exported for client implementations and tests that
// need the canonical framing.
func AppendSecretFrame(dst []byte, reference string, secret []byte) ([]byte, error) {
	if reference == "" || len(reference) > maxSecretRefBytes || !utf8.ValidString(reference) {
		return nil, errors.New("secret reference must contain 1 to 256 bytes")
	}
	if len(secret) > maxSecretBytes {
		return nil, fmt.Errorf("secret payload exceeds %d bytes", maxSecretBytes)
	}
	header := make([]byte, secretHeaderBytes)
	copy(header[:4], secretMagic)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(reference)))
	binary.BigEndian.PutUint32(header[6:10], uint32(len(secret)))
	dst = append(dst, header...)
	dst = append(dst, reference...)
	dst = append(dst, secret...)
	return dst, nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
