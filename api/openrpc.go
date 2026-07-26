// SPDX-License-Identifier: GPL-3.0-only

// Package api contains the machine-readable public CryptoWrapper RPC contract.
package api

import _ "embed"

// OpenRPC is the canonical CryptoWrapper RPC v1 OpenRPC document.
//
//go:embed openrpc.json
var OpenRPC []byte
