// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"encoding/json"
	"io"
)

type result struct {
	SchemaVersion string            `json:"schema_version"`
	OK            bool              `json:"ok"`
	Algorithm     string            `json:"algorithm,omitempty"`
	Outputs       map[string]string `json:"outputs,omitempty"`
	Fingerprints  map[string]string `json:"fingerprints,omitempty"`
	Data          any               `json:"data,omitempty"`
	Error         *resultError      `json:"error,omitempty"`
}

type resultError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeJSON(writer io.Writer, value result) error {
	if value.SchemaVersion == "" {
		value.SchemaVersion = "1"
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
