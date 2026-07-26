#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cw="${CW_BINARY:-$repo_root/bin/cw}"
demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/cryptowrapper-demo.XXXXXX")"

cleanup() {
  rm -rf -- "$demo_dir"
}
trap cleanup EXIT

if [[ ! -x "$cw" ]]; then
  printf 'CryptoWrapper binary not found at %s\n' "$cw" >&2
  printf 'Run "make build" first, or set CW_BINARY.\n' >&2
  exit 1
fi

run() {
  local display=("$@")
  if [[ "${display[0]}" == "$cw" ]]; then
    display[0]="cw"
  fi
  printf '\033[1;36m$'
  printf ' %q' "${display[@]}"
  printf '\033[0m\n'
  "$@"
  printf '\n'
  sleep 0.8
}

if [[ -t 1 && -n "${TERM:-}" && "${TERM:-}" != "dumb" ]] &&
  command -v clear >/dev/null 2>&1; then
  clear
fi
printf '\033[1;35mCryptoWrapper: key generation, signing, verification, and hashing\033[0m\n\n'
sleep 1

cd "$demo_dir"

run "$cw" doctor

printf '\033[0;33mThis demo uses an unencrypted disposable key to stay non-interactive.\033[0m\n'
printf '\033[0;33mFor real keys, omit --no-passphrase and enter a hidden passphrase.\033[0m\n\n'
sleep 1

run "$cw" keygen ed25519 \
  --no-passphrase \
  --out signing.key.pem \
  --public-out signing.pub.pem

printf '\033[1;36m$ printf %s > message.txt\033[0m\n' "'Hello from CryptoWrapper\\n'"
printf 'Hello from CryptoWrapper\n' > message.txt
printf '\n'
sleep 0.8

run "$cw" sign \
  --no-passphrase \
  --key signing.key.pem \
  --in message.txt \
  --out message.txt.sig

run "$cw" verify \
  --key signing.pub.pem \
  --in message.txt \
  --signature message.txt.sig

run "$cw" hash sha256 --in message.txt
run "$cw" inspect --type public-key --in signing.pub.pem

printf '\033[1;32mDone. The signature is valid and all files were written safely.\033[0m\n'
