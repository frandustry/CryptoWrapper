# CryptoWrapper repository guidance

- Keep the CLI compatible with macOS and Linux.
- Cryptographic operations must never be assembled through a shell.
- Never place passphrases, raw symmetric keys, or private-key material in logs.
- Modern authenticated algorithms are the default. Legacy or unauthenticated
  algorithms require an explicit opt-in.
- Write outputs atomically, reject accidental overwrites, and keep secret files
  at mode `0600`.
- Run the smallest relevant test before each substantial commit.
- Commit with `git commit --no-gpg-sign` and push each validated phase to
  `origin/main` once the remote exists.
- User-facing documentation belongs in the repository root.

