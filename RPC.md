# CryptoWrapper RPC v1

[中文说明](RPC.zh-CN.md)

CryptoWrapper exposes a local application interface through JSON-RPC 2.0.
The interface lets SwiftUI, Wails, Go, Rust, Python, and other applications
reuse the same policy, validation, atomic-output, and OpenSSL execution paths
as the `cw` CLI.

RPC v1 is local-only. It does not open a TCP port or run a persistent daemon.
The application starts a child process and owns its lifetime:

```text
cw rpc --stdio [--secret-fd 3]
```

The machine-readable contract is [`api/openrpc.json`](api/openrpc.json). A
running server returns the same document from `rpc.discover`.

## Transport

- stdin receives one compact JSON-RPC 2.0 object per LF-terminated line.
- stdout contains protocol messages only.
- stderr contains sanitized diagnostics and may be shown to the user.
- Keep stdin open until all expected responses arrive. Closing stdin asks the
  child process to exit.
- Request IDs should be strings or integers. The server returns the same JSON
  value in the response and progress notifications.
- Unknown parameter fields are rejected with JSON-RPC code `-32602`.

Start every session with `system.handshake`:

```json
{"jsonrpc":"2.0","id":"hello","method":"system.handshake"}
```

The result reports `protocol_version`, result `schema_version`, build
information, available methods, secret-channel availability, and CGO/libcrypto
state. Call `system.doctor` when the application needs full OpenSSL and
provider diagnostics.

Use the standard OpenRPC discovery call to retrieve the complete interface:

```json
{"jsonrpc":"2.0","id":"schema","method":"rpc.discover"}
```

## Methods

| Method | Operation |
| --- | --- |
| `rpc.discover` | Return the embedded OpenRPC document |
| `system.handshake` | Negotiate versions and capabilities |
| `system.capabilities` | Repeat the current capability report |
| `system.doctor` | Validate OpenSSL, providers, and libcrypto |
| `algorithms.list` | List provider algorithms |
| `key.generate` | Generate an asymmetric key pair |
| `key.generateSymmetric` | Generate a hexadecimal symmetric key |
| `key.derive` | Derive an ECDH/XDH shared secret |
| `certificate.generate` | Generate a self-signed certificate |
| `certificate.issue` | Issue a certificate for a public key |
| `file.encrypt` / `file.decrypt` | Recipient CMS encryption |
| `file.encryptSymmetric` / `file.decryptSymmetric` | Raw-key CMS |
| `file.encryptPassword` / `file.decryptPassword` | Password CMS |
| `file.sign` / `file.verify` | Detached signatures |
| `file.hash` | File hashing |
| `file.inspect` | Inspect a key, certificate, or CMS file |
| `compat.encrypt` / `compat.decrypt` | Explicit unauthenticated `enc` compatibility |
| `operation.cancel` | Cancel an in-flight request |

Operation results retain the CLI JSON contract:

```json
{
  "schema_version": "1",
  "ok": true,
  "algorithm": "ed25519",
  "outputs": {
    "private_key": "/absolute/alice.key.pem",
    "public_key": "/absolute/alice.pub.pem"
  },
  "fingerprints": {
    "public_key": "SHA256:..."
  }
}
```

Files are passed by path and are never embedded as Base64 in JSON. The same
overwrite protection, symlink rejection, atomic writes, and file modes as the
CLI apply.

## Secrets

Passphrases must never appear in JSON, argv, environment variables, progress
notifications, or logs. Start the child with an inherited read descriptor:

```text
cw rpc --stdio --secret-fd 3
```

The application writes one-use `CWS1` frames to the other end of that pipe.
All integer fields use unsigned big-endian encoding:

| Offset | Size | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII magic `CWS1` |
| 4 | 2 | UTF-8 `secret_ref` byte length, 1–256 |
| 6 | 4 | Secret byte length, 0–65,536 |
| 10 | variable | UTF-8 `secret_ref` |
| following | variable | Secret bytes |

The JSON request contains only the matching opaque reference:

```json
{
  "jsonrpc": "2.0",
  "id": "generate-alice",
  "method": "key.generate",
  "params": {
    "algorithm": "ed25519",
    "out": "/absolute/alice.key.pem",
    "secret_ref": "secret-7bff7b68"
  }
}
```

Frames may arrive before or after their requests and are demultiplexed by
reference. Each reference can be claimed once. At most 32 unclaimed frames are
buffered, and secret operations may run concurrently. Secret buffers are
cleared after the operation. Duplicate references, malformed frames, missing
channels, and payloads over 64 KiB return RPC code `1010`.

For an intentionally unencrypted private key, omit `secret_ref` and explicitly
set `"no_passphrase": true`. Supplying both fields is rejected.

The Go client example demonstrates descriptor inheritance and secret framing:

```sh
go run ./examples/go-rpc-client ./bin/cw /absolute/output.key.pem
```

The Swift example at
[`examples/swift/CryptoWrapperRPC.swift`](examples/swift/CryptoWrapperRPC.swift)
implements request/response and progress handling. A production Swift client
can use `posix_spawn_file_actions_adddup2` to attach its secret pipe as child
descriptor 3.

## Progress and cancellation

Operations produce `operation.progress` notifications:

```json
{
  "jsonrpc": "2.0",
  "method": "operation.progress",
  "params": {
    "request_id": "generate-alice",
    "method": "key.generate",
    "stage": "running"
  }
}
```

Stages are `started`, `awaiting_secret`, `running`, `completed`, `failed`, and
`cancelled`. Notifications have no response.

Cancel with the exact JSON request ID:

```json
{
  "jsonrpc": "2.0",
  "id": "cancel-1",
  "method": "operation.cancel",
  "params": {
    "request_id": "generate-alice"
  }
}
```

Cancellation propagates through Go contexts to the active OpenSSL child
process. Atomic-output operations do not leave partial destination files.

## Errors

Standard JSON-RPC errors retain their negative specification codes. Application
errors use:

| Code | Meaning | CLI equivalent |
| ---: | --- | ---: |
| `1001` | General operation failure | `1` |
| `1002` | Invalid operation parameters | `2` |
| `1003` | Missing or unsupported dependency | `3` |
| `1004` | Verification or authentication failure | `4` |
| `1010` | Secret-channel failure | n/a |

Application error `data` includes `schema_version` and, when applicable,
`cli_exit_code`. Error messages and data must never contain secrets.

## Compatibility policy

- Protocol v1 accepts additive methods and optional result fields.
- Existing method and field meanings will not change incompatibly within v1.
- A breaking request or transport change requires a new protocol version.
- Clients must call `system.handshake` and reject unsupported protocol
  versions before sending cryptographic operations.
- Clients should ignore unknown result fields to permit additive evolution.

This interface has not received an independent cryptographic security audit.
