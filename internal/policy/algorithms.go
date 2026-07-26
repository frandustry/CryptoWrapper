// SPDX-License-Identifier: GPL-3.0-only

package policy

import (
	"fmt"
	"strings"
)

type KeyAlgorithm struct {
	Name         string   `json:"name"`
	OpenSSLName  string   `json:"openssl_name"`
	Category     string   `json:"category"`
	Capabilities []string `json:"capabilities"`
	Legacy       bool     `json:"legacy"`
}

var keyAlgorithms = map[string]KeyAlgorithm{
	"rsa":         {"rsa", "RSA", "classical", []string{"encrypt", "sign"}, false},
	"rsa-pss":     {"rsa-pss", "RSA-PSS", "classical", []string{"sign"}, false},
	"ec":          {"ec", "EC", "classical", []string{"derive", "sign"}, false},
	"ed25519":     {"ed25519", "ED25519", "eddsa", []string{"sign"}, false},
	"ed448":       {"ed448", "ED448", "eddsa", []string{"sign"}, false},
	"x25519":      {"x25519", "X25519", "ecdh", []string{"derive", "encap"}, false},
	"x448":        {"x448", "X448", "ecdh", []string{"derive", "encap"}, false},
	"sm2":         {"sm2", "SM2", "national", []string{"encrypt", "sign", "derive"}, false},
	"ml-kem-512":  {"ml-kem-512", "ML-KEM-512", "post-quantum", []string{"encap"}, false},
	"ml-kem-768":  {"ml-kem-768", "ML-KEM-768", "post-quantum", []string{"encap"}, false},
	"ml-kem-1024": {"ml-kem-1024", "ML-KEM-1024", "post-quantum", []string{"encap"}, false},
	"ml-dsa-44":   {"ml-dsa-44", "ML-DSA-44", "post-quantum", []string{"sign"}, false},
	"ml-dsa-65":   {"ml-dsa-65", "ML-DSA-65", "post-quantum", []string{"sign"}, false},
	"ml-dsa-87":   {"ml-dsa-87", "ML-DSA-87", "post-quantum", []string{"sign"}, false},
	"dsa":         {"dsa", "DSA", "legacy", []string{"sign"}, true},
}

func Key(name string) (KeyAlgorithm, bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(normalized, "slh-dsa-") {
		return KeyAlgorithm{
			Name:         normalized,
			OpenSSLName:  strings.ToUpper(normalized),
			Category:     "post-quantum",
			Capabilities: []string{"sign"},
		}, true
	}
	algorithm, ok := keyAlgorithms[normalized]
	return algorithm, ok
}

func RequireKey(name string, allowLegacy bool) (KeyAlgorithm, error) {
	algorithm, ok := Key(name)
	if !ok {
		return KeyAlgorithm{}, fmt.Errorf("unsupported key algorithm %q; run 'cw algorithms keys'", name)
	}
	if algorithm.Legacy && !allowLegacy {
		return KeyAlgorithm{}, fmt.Errorf("%s is legacy; pass --allow-legacy to use it", name)
	}
	return algorithm, nil
}

var symmetricKeyBits = map[string]int{
	"aes-128":      128,
	"aes-192":      192,
	"aes-256":      256,
	"chacha20":     256,
	"camellia-128": 128,
	"camellia-192": 192,
	"camellia-256": 256,
	"aria-128":     128,
	"aria-192":     192,
	"aria-256":     256,
	"sm4":          128,
}

func SymmetricKeyBits(name string) (int, bool) {
	bits, ok := symmetricKeyBits[strings.ToLower(strings.TrimSpace(name))]
	return bits, ok
}

func IsLegacyDigest(name string) bool {
	switch strings.ToLower(name) {
	case "md5", "sha1", "sha-1":
		return true
	default:
		return false
	}
}
