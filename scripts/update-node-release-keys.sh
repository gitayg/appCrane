#!/usr/bin/env bash
#
# Refresh infra/node-release-keys.gpg, the keyring self-update uses to check
# the GPG signature on a Node release it downloads (server/services/bundledNode.js).
#
# Source: https://github.com/nodejs/release-keys — keys.list is the set of
# people currently allowed to sign Node releases. When a new releaser signs a
# Node 22 build, a host downloading it refuses until this keyring includes
# their key, so run this and ship the result in an AppCrane release.
#
# Needs gpg (for --dearmor) and curl. Review the diff of the .list file before
# committing: it is the list of keys AppCrane will trust.

set -euo pipefail
cd "$(dirname "$0")/.."
BASE="https://raw.githubusercontent.com/nodejs/release-keys/HEAD"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$BASE/keys.list" -o "$tmp/keys.list"
: > "$tmp/node-release-keys.gpg"
while read -r fpr; do
  [ -n "$fpr" ] || continue
  [[ "$fpr" =~ ^[0-9A-F]{40}$ ]] || { echo "unexpected line in keys.list: $fpr" >&2; exit 1; }
  curl -fsSL "$BASE/keys/$fpr.asc" | gpg --dearmor >> "$tmp/node-release-keys.gpg"
done < "$tmp/keys.list"

cp "$tmp/keys.list" infra/node-release-keys.list
cp "$tmp/node-release-keys.gpg" infra/node-release-keys.gpg
echo "infra/node-release-keys.gpg: $(wc -l < infra/node-release-keys.list | tr -d ' ') keys"
