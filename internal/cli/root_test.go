// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionJSON(t *testing.T) {
	cmd := New("1.2.3", "abc123", "2026-07-26")
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--json", "version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := output.String(); !strings.Contains(got, `"schema_version":"1"`) ||
		!strings.Contains(got, `"version":"1.2.3"`) {
		t.Fatalf("unexpected JSON output: %s", got)
	}
}
