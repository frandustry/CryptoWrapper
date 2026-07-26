# Security policy

## Supported versions

Until the first stable release, security fixes are applied to the latest
commit on `main`.

CryptoWrapper requires OpenSSL 3.6.3+ or 4.0.1+. It refuses OpenSSL 3.6.0
through 3.6.2 because those releases predate CMS-related security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
[private GitHub security advisory](https://github.com/frandustry/CryptoWrapper/security/advisories/new).
Include the affected command, version, OpenSSL version, platform, and a minimal
reproducer that contains no real keys or private data.

## Security boundaries

- This project is an OpenSSL wrapper, not a new cryptographic implementation.
- The small CGO layer handles CMS password and raw symmetric-key workflows so
  those secrets do not enter process arguments.
- Private-key passphrases are passed to OpenSSL through an anonymous file
  descriptor.
- Legacy and unauthenticated formats require explicit opt-in.
- This project has not received an independent cryptographic audit.
