#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-$(git -C "$repo_root" describe --tags --always)}"
platform="$(go env GOOS)-$(go env GOARCH)"
archive_name="cryptowrapper-${version}-${platform}"
staging_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$staging_dir"
}
trap cleanup EXIT

make -C "$repo_root" clean build completions VERSION="$version"
mkdir -p "$repo_root/dist" "$staging_dir/$archive_name"
cp "$repo_root/bin/cw" "$repo_root/LICENSE" "$repo_root/README.md" \
  "$repo_root/README.zh-CN.md" "$repo_root/RPC.md" \
  "$repo_root/RPC.zh-CN.md" "$repo_root/SECURITY.md" \
  "$repo_root/THIRD_PARTY_LICENSES.md" \
  "$staging_dir/$archive_name/"
cp -R "$repo_root/bin/completions" "$staging_dir/$archive_name/"
mkdir -p "$staging_dir/$archive_name/api" "$staging_dir/$archive_name/examples"
cp "$repo_root/api/openrpc.json" "$staging_dir/$archive_name/api/"
cp -R "$repo_root/examples/go-rpc-client" "$repo_root/examples/swift" \
  "$staging_dir/$archive_name/examples/"
mkdir -p "$staging_dir/$archive_name/demo"
cp "$repo_root/demo/cryptowrapper.cast" "$staging_dir/$archive_name/demo/"

tar -C "$staging_dir" -czf "$repo_root/dist/$archive_name.tar.gz" "$archive_name"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$repo_root/dist" && sha256sum "$archive_name.tar.gz" > "$archive_name.tar.gz.sha256")
else
  (cd "$repo_root/dist" && shasum -a 256 "$archive_name.tar.gz" > "$archive_name.tar.gz.sha256")
fi

printf 'Built %s\n' "$repo_root/dist/$archive_name.tar.gz"
