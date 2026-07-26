// SPDX-License-Identifier: GPL-3.0-only

package api

import (
	"encoding/json"
	"testing"
)

func TestOpenRPCDocumentIsValidJSON(t *testing.T) {
	var document struct {
		OpenRPC string `json:"openrpc"`
		Info    struct {
			Version string `json:"version"`
		} `json:"info"`
		Methods []struct {
			Name string `json:"name"`
		} `json:"methods"`
	}
	if err := json.Unmarshal(OpenRPC, &document); err != nil {
		t.Fatal(err)
	}
	if document.OpenRPC == "" || document.Info.Version != "1.0.0" {
		t.Fatalf("unexpected document versions: %#v", document)
	}
	if len(document.Methods) == 0 {
		t.Fatal("OpenRPC document contains no methods")
	}
	seen := make(map[string]bool)
	for _, method := range document.Methods {
		if method.Name == "" || seen[method.Name] {
			t.Fatalf("empty or duplicate method name %q", method.Name)
		}
		seen[method.Name] = true
	}
}
