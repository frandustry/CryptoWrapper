# CryptoWrapper

[中文说明](README.zh-CN.md)

CryptoWrapper (`cw`) is a safer, simpler Go CLI wrapper around OpenSSL. It
provides short commands for modern classical, Chinese commercial cryptography,
and post-quantum key generation, signatures, key agreement, and standard CMS
file encryption.

> [!WARNING]
> CryptoWrapper has not received an independent cryptographic security audit.
> Do not treat it as a substitute for a reviewed key-management system.

## Requirements

- Go 1.25 or newer.
- OpenSSL 3.6.3+ or 4.0.1+.
- OpenSSL headers, libraries, and `pkg-config` for the default CGO build.
- macOS or Linux.

OpenSSL 3.6.0 through 3.6.2 are rejected because 3.6.3 contains security fixes
relevant to CMS processing. The `openssl` executable and linked `libcrypto`
must use the same major/minor series. Every OpenSSL-backed command checks the
CLI version before operating; direct CGO CMS commands also check the linked
library version. Run `cw doctor` for the full path, provider, and linkage
diagnostics. `cw version`, `cw completion`, and the pure-Go `cw symkey` command
do not need an OpenSSL executable.

macOS with Homebrew:

```sh
brew install go openssl@3 pkg-config
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
```

Linux distributions must provide OpenSSL 3.6.3+ development files. If the
distribution package is older, build a supported OpenSSL release and point
`PATH`, `PKG_CONFIG_PATH`, and the platform library path at that installation.

## Build and install

```sh
git clone https://github.com/frandustry/CryptoWrapper.git
cd CryptoWrapper
make check
make build
./bin/cw doctor
```

Install to your Go binary directory:

```sh
make install
```

Generate shell completions:

```sh
make completions
```

Applications can use the versioned, local JSON-RPC interface without
reconstructing CLI arguments. See [CryptoWrapper RPC v1](RPC.md), the embedded
[OpenRPC contract](api/openrpc.json), and the Go and Swift examples under
`examples/`.

`CGO_ENABLED=0 go build ./cmd/cw` is supported. That build can perform
key, certificate, signature, recipient-CMS, hashing, and compatibility
operations, but intentionally refuses password and raw-symmetric-key CMS
commands.

## Prebuilt releases

Pushing a semantic version tag such as `v0.1.0` automatically builds and
publishes release archives for Linux and macOS on both AMD64 and ARM64.
Every release includes individual SHA-256 checksum files and a consolidated
`SHA256SUMS` file.

The binaries still require a compatible OpenSSL installation as described
above. Release assets are retained by GitHub Releases rather than as
long-lived GitHub Actions artifacts.

The macOS archives are not Developer ID-signed or notarized. The ARM64 binary
may carry an ad-hoc signature added by the Go linker, while the AMD64 binary
may be unsigned; neither establishes a trusted developer identity. The
recommended macOS path is to build from source using the Homebrew setup above.
Advanced users who choose a prebuilt archive should verify its SHA-256
checksum first and may apply or replace a local ad-hoc signature:

```sh
codesign --force --sign - ./cw
codesign --verify --verbose=2 ./cw
```

An ad-hoc signature does not identify a Developer ID and is not Apple
notarization; Gatekeeper may still require the user to explicitly approve the
binary in System Settings.

## Quick start

[![Watch the CryptoWrapper CLI demo](https://static.frank-ruan.com/project_specific/CryptoWrapper/CryptoWrapper-demo-poster.png)](https://static.frank-ruan.com/project_specific/CryptoWrapper/CryptoWrapper-demo.mp4)

[Watch the browser-friendly MP4 demo](https://static.frank-ruan.com/project_specific/CryptoWrapper/CryptoWrapper-demo.mp4).
It uses a disposable unencrypted key so the recording can run unattended.
Real private keys should use CryptoWrapper's default hidden passphrase prompt
or a mode-`0600` passphrase file.

Generate an encrypted RSA key pair:

```sh
cw keygen rsa \
  --out alice.key.pem \
  --public-out alice.pub.pem
```

For scripts, store the passphrase in a mode-`0600` file:

```sh
cw keygen ed25519 \
  --passphrase-file private-passphrase.txt \
  --out signing.key.pem \
  --public-out signing.pub.pem
```

Generate a self-signed certificate:

```sh
cw certgen \
  --key alice.key.pem \
  --subject /CN=Alice \
  --days 365 \
  --out alice.crt.pem
```

Encrypt a file for one or more certificate recipients:

```sh
cw encrypt \
  --in document.pdf \
  --recipient alice.crt.pem \
  --recipient bob.crt.pem \
  --out document.pdf.cms

cw decrypt \
  --in document.pdf.cms \
  --cert alice.crt.pem \
  --key alice.key.pem \
  --out document.pdf
```

Generate a symmetric key and use authenticated CMS encryption:

```sh
cw symkey aes-256 --out vault.key
cw sym-encrypt --key vault.key --in archive.tar --out archive.tar.cms
cw sym-decrypt --key vault.key --in archive.tar.cms --out archive.tar
```

Password-based authenticated CMS:

```sh
cw pass-encrypt \
  --passphrase-file vault-passphrase.txt \
  --in notes.txt \
  --out notes.txt.cms

cw pass-decrypt \
  --passphrase-file vault-passphrase.txt \
  --in notes.txt.cms \
  --out notes.txt
```

Sign and verify:

```sh
cw sign --key signing.key.pem --in release.tar.gz --out release.tar.gz.sig
cw verify --key signing.pub.pem --in release.tar.gz --signature release.tar.gz.sig
```

Hash and derive:

```sh
cw hash sha3-256 --in release.tar.gz
cw derive --key alice-x25519.key.pem --peer-key bob-x25519.pub.pem --out shared.secret
```

## Post-quantum CMS recipients

ML-KEM recipient certificates need an issuing key capable of signing. The
following creates an ML-DSA CA and issues an ML-KEM certificate:

```sh
cw keygen ml-dsa-65 --out pq-ca.key.pem --public-out pq-ca.pub.pem
cw certgen --key pq-ca.key.pem --subject /CN=PQ-CA --out pq-ca.crt.pem

cw keygen ml-kem-768 --out recipient.key.pem --public-out recipient.pub.pem
cw certissue \
  --ca-cert pq-ca.crt.pem \
  --ca-key pq-ca.key.pem \
  --public-key recipient.pub.pem \
  --subject /CN=PQ-Recipient \
  --out recipient.crt.pem
```

The resulting certificate can be passed to `cw encrypt --recipient`.

## Algorithms and policy

`cw algorithms keys|ciphers|digests|signatures` reports what the active
OpenSSL providers actually expose. `--json` produces the stable schema-v1
machine interface.

Curated key support includes:

- RSA, RSA-PSS, P-256/P-384/P-521/secp256k1 EC.
- Ed25519, Ed448, X25519, X448.
- SM2, SM3, and SM4.
- ML-KEM-512/768/1024 and ML-DSA-44/65/87.
- Provider-exposed SLH-DSA variants.
- AES, ChaCha20, Camellia, ARIA, and SM4 symmetric key sizes.

DES, 3DES, RC2, RC4, Blowfish, CAST, IDEA, DSA, MD5, and SHA-1 require
`--allow-legacy`. Unauthenticated OpenSSL `enc` files additionally require
`cw compat ... --allow-unauthenticated`.

## Secret handling

- Private keys are encrypted by default. `--no-passphrase` is explicit.
- Passphrases are read from a hidden terminal, `--passphrase-file`, or
  `--passphrase-env`; there is no literal passphrase flag.
- Password and raw-key CMS operations use `libcrypto` directly, keeping
  secrets out of process arguments.
- Private and symmetric keys are mode `0600`.
- Outputs are written to same-directory temporary files and atomically
  installed. Existing files and symlinks are rejected unless a regular file is
  explicitly replaced with `--force`.
- Failed authentication does not install a partial plaintext output.

## Stable exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | General operational or I/O failure |
| 2 | Invalid usage or unsafe policy request |
| 3 | Missing/unsupported dependency or algorithm |
| 4 | Signature verification or decryption authentication failure |

## License

CryptoWrapper is licensed under `GPL-3.0-only`. See [LICENSE](LICENSE) and
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
