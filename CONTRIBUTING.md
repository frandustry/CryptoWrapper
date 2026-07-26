# Contributing

CryptoWrapper welcomes focused fixes, documentation improvements, tests, and
carefully justified algorithm support.

## Development setup

Install Go 1.25+, OpenSSL 3.6.3+ development files, and `pkg-config`. Confirm
the environment before making changes:

```sh
make build
./bin/cw doctor
make check
make integration-test
```

## Requirements

- Never route OpenSSL commands through a shell.
- Never log passphrases, private keys, or raw symmetric keys.
- Keep modern authenticated algorithms as the default.
- Add integration coverage for every cryptographic command or format change.
- Preserve stable JSON fields and documented exit codes.
- Add `// SPDX-License-Identifier: GPL-3.0-only` to Go and CGo source files.
- Keep generated binaries, test artifacts, caches, and real keys out of Git.

Use a focused branch and describe the security impact and validation in the
pull request.

## Cutting a release

Release publication is tag-driven. From a clean, fully tested `main` branch,
create and push an annotated semantic version tag:

```sh
git tag -a v0.1.0 -m "CryptoWrapper v0.1.0"
git push origin v0.1.0
```

The Release workflow builds Linux and macOS archives for AMD64 and ARM64,
verifies their checksums, and publishes them with generated release notes.
