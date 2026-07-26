// SPDX-License-Identifier: GPL-3.0-only

package rpcapi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	secretMagic       = "CWS1"
	maxSecretRefBytes = 256
	maxSecretBytes    = 64 * 1024
	secretHeaderBytes = 10
)

// SecretReader consumes binary frames from a channel independent of JSON-RPC.
// Frames are serialized because each secret is one-use and matched to the
// opaque reference carried in the corresponding RPC request.
type SecretReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func NewSecretReader(reader io.Reader) *SecretReader {
	if reader == nil {
		return nil
	}
	return &SecretReader{reader: reader}
}

func (s *SecretReader) Read(expectedRef string) ([]byte, error) {
	if s == nil || s.reader == nil {
		return nil, errors.New("secret channel is unavailable")
	}
	if expectedRef == "" || len(expectedRef) > maxSecretRefBytes {
		return nil, errors.New("secret_ref must contain 1 to 256 bytes")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	header := make([]byte, secretHeaderBytes)
	if _, err := io.ReadFull(s.reader, header); err != nil {
		return nil, fmt.Errorf("read secret frame header: %w", err)
	}
	if string(header[:4]) != secretMagic {
		return nil, errors.New("invalid secret frame magic")
	}
	refLength := int(binary.BigEndian.Uint16(header[4:6]))
	secretLength := int(binary.BigEndian.Uint32(header[6:10]))
	if refLength < 1 || refLength > maxSecretRefBytes {
		return nil, fmt.Errorf("secret frame reference length %d is invalid", refLength)
	}
	if secretLength > maxSecretBytes {
		return nil, fmt.Errorf("secret frame payload exceeds %d bytes", maxSecretBytes)
	}

	reference := make([]byte, refLength)
	if _, err := io.ReadFull(s.reader, reference); err != nil {
		return nil, fmt.Errorf("read secret frame reference: %w", err)
	}
	secret := make([]byte, secretLength)
	if _, err := io.ReadFull(s.reader, secret); err != nil {
		zero(secret)
		return nil, fmt.Errorf("read secret frame payload: %w", err)
	}
	matched := bytes.Equal(reference, []byte(expectedRef))
	zero(reference)
	if !matched {
		zero(secret)
		return nil, errors.New("secret frame reference does not match secret_ref")
	}
	return secret, nil
}

// AppendSecretFrame is exported for client implementations and tests that
// need the canonical framing. It appends a frame without retaining secret.
func AppendSecretFrame(dst []byte, reference string, secret []byte) ([]byte, error) {
	if reference == "" || len(reference) > maxSecretRefBytes {
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
