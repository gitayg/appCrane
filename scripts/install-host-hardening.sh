#!/usr/bin/env bash
#
# Let a non-root AppCrane apply scripts/host-hardening.sh from
# Settings > Job Health > Host limits.
#
#   sudo bash scripts/install-host-hardening.sh [run-user]
#
# Called by install.sh; re-run it after an update changes host-hardening.sh
# (the settings page says when the installed copy is stale).
#
# It installs a root-owned copy at /usr/local/lib/appcrane/host-hardening.sh and
# a sudoers rule letting the run user execute exactly that file, with no
# arguments. The repo copy is never sudoed: self-update rewrites it as the run
# user, so a rule for it would hand root to anyone who controls the app. The
# copy has the repo path baked in, because sudo's env_reset strips the
# environment and the script needs the repo to find .env / DATA_DIR.
#
# It also installs scripts/appcrane-publish-chain.sh, root-owned, at
# /usr/local/lib/appcrane/appcrane-publish-chain.sh, with a second sudoers rule
# letting the run user run exactly that path with arguments (it validates them
# itself): AppCrane keeps the APPCRANE-PUBLISH chain in step with the ports it
# publishes through it. host-hardening.sh closes the public interface in
# DOCKER-USER only when AppCrane runs as root or this rule is in place.
#
# Likewise scripts/appcrane-db-chain.sh goes to
# /usr/local/lib/appcrane/appcrane-db-chain.sh with a third sudoers rule for
# exactly that path: AppCrane keeps the APPCRANE-DB chain (which app containers
# may reach which managed database port) in step with the databases it hands out.
#
# run-user defaults to the User= of appcrane.service, then $SUDO_USER, then root.
# A root run user needs no sudoers rule, so none is written.

set -euo pipefail

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_DIR/scripts/host-hardening.sh"
DEST_DIR=/usr/local/lib/appcrane
DEST="$DEST_DIR/host-hardening.sh"
SUDOERS_FILE=/etc/sudoers.d/appcrane-host-hardening
PUB_SRC="$REPO_DIR/scripts/appcrane-publish-chain.sh"
PUB_DEST="$DEST_DIR/appcrane-publish-chain.sh"
PUB_SUDOERS_FILE=/etc/sudoers.d/appcrane-publish-chain
DB_SRC="$REPO_DIR/scripts/appcrane-db-chain.sh"
DB_DEST="$DEST_DIR/appcrane-db-chain.sh"
DB_SUDOERS_FILE=/etc/sudoers.d/appcrane-db-chain

RUN_USER="${1:-}"
if [[ -z "$RUN_USER" ]] && [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
  RUN_USER="$(systemctl show -p User --value appcrane 2>/dev/null || true)"
fi
RUN_USER="${RUN_USER:-${SUDO_USER:-root}}"

[[ -f "$SRC" ]] || die "$SRC not found"
[[ -f "$PUB_SRC" ]] || die "$PUB_SRC not found"
[[ -f "$DB_SRC" ]] || die "$DB_SRC not found"
[[ "$REPO_DIR" != *"'"* ]] || die "Repo path contains a single quote: $REPO_DIR"
[[ "$RUN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Not a valid user name: $RUN_USER"
id -u "$RUN_USER" >/dev/null 2>&1 || die "User does not exist: $RUN_USER"

# install -d also resets the owner and mode of a directory that already exists.
install -d -o root -g root -m 0755 "$DEST_DIR"
# A temp file left by an aborted run (set -e) is removed on exit.
_src=""; _tmp=""
trap 'rm -f -- ${_src:+"$_src"} ${_tmp:+"$_tmp"}' EXIT
# The source is read once, into a root-owned file, so the stamp below names
# exactly the bytes the installed copy was made from.
_src="$(mktemp "$DEST_DIR/.host-hardening-src.XXXXXX")"
cat "$SRC" > "$_src"
_tmp="$(mktemp "$DEST_DIR/.host-hardening.XXXXXX")"
REPO="$REPO_DIR" awk '!done && /^REPO_DIR=/ { print "REPO_DIR='\''" ENVIRON["REPO"] "'\''"; done = 1; next } { print }' "$_src" > "$_tmp"
if ! grep -qxF "REPO_DIR='$REPO_DIR'" "$_tmp"; then
  rm -f "$_tmp" "$_src"; die "No REPO_DIR= line in $SRC"
fi
chown root:root "$_tmp"
chmod 0755 "$_tmp"
mv -f "$_tmp" "$DEST"
log "host-hardening: installed $DEST (root:root 0755, repo $REPO_DIR)"

_tmp="$(mktemp "$DEST_DIR/.appcrane-publish-chain.XXXXXX")"
cat "$PUB_SRC" > "$_tmp"
chown root:root "$_tmp"
chmod 0755 "$_tmp"
mv -f "$_tmp" "$PUB_DEST"
log "host-hardening: installed $PUB_DEST (root:root 0755)"
_tmp="$(mktemp "$DEST_DIR/.appcrane-db-chain.XXXXXX")"
cat "$DB_SRC" > "$_tmp"
chown root:root "$_tmp"
chmod 0755 "$_tmp"
mv -f "$_tmp" "$DB_DEST"
log "host-hardening: installed $DB_DEST (root:root 0755)"

# Version stamp, written last: AppCrane runs the installed copy by itself after
# an upgrade only when source_sha256 equals the sha256 of the checkout's script
# and publish_chain_sha256 / db_chain_sha256 those of its two helpers (copied
# byte for byte), so a release that changes only a helper is flagged stale too.
STAMP="$DEST_DIR/host-hardening.version"
_ver="$(grep -m1 -oE '"version"[[:space:]]*:[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"' "$REPO_DIR/package.json" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
_tmp="$(mktemp "$DEST_DIR/.host-hardening-version.XXXXXX")"
printf 'version=%s\nsource_sha256=%s\ninstalled_sha256=%s\npublish_chain_sha256=%s\ndb_chain_sha256=%s\n' \
  "${_ver:-unknown}" "$(sha256sum "$_src" | cut -d' ' -f1)" "$(sha256sum "$DEST" | cut -d' ' -f1)" \
  "$(sha256sum "$PUB_DEST" | cut -d' ' -f1)" "$(sha256sum "$DB_DEST" | cut -d' ' -f1)" > "$_tmp"
rm -f "$_src"
chown root:root "$_tmp"
chmod 0644 "$_tmp"
mv -f "$_tmp" "$STAMP"
log "host-hardening: stamped $STAMP (AppCrane ${_ver:-unknown})"

if [[ "$RUN_USER" == root ]]; then
  log "host-hardening: AppCrane runs as root — no sudoers rule needed"
  exit 0
fi
command -v visudo >/dev/null 2>&1 || die "visudo not found — install sudo, then re-run this script"
mkdir -p /etc/sudoers.d
# A name with a dot is ignored by sudo's #includedir until it is renamed.
_tmp="$(mktemp /etc/sudoers.d/.appcrane-host-hardening.XXXXXX)"
cat > "$_tmp" <<SUDOERS
# Written by AppCrane scripts/install-host-hardening.sh
# Lets ${RUN_USER} apply Settings > Job Health > Host limits. "" forbids arguments.
${RUN_USER} ALL=(root) NOPASSWD: ${DEST} ""
SUDOERS
chown root:root "$_tmp"
chmod 0440 "$_tmp"
if ! visudo -cf "$_tmp" >/dev/null; then
  rm -f "$_tmp"; die "Generated sudoers rule is invalid — $SUDOERS_FILE not written"
fi
mv -f "$_tmp" "$SUDOERS_FILE"
log "host-hardening: sudoers written: $SUDOERS_FILE ($RUN_USER may run $DEST)"

_tmp="$(mktemp /etc/sudoers.d/.appcrane-publish-chain.XXXXXX)"
cat > "$_tmp" <<SUDOERS
# Written by AppCrane scripts/install-host-hardening.sh
# Lets ${RUN_USER} set the APPCRANE-PUBLISH chain; the script accepts only <tcp|udp>:<port> arguments.
${RUN_USER} ALL=(root) NOPASSWD: ${PUB_DEST}
SUDOERS
chown root:root "$_tmp"
chmod 0440 "$_tmp"
if ! visudo -cf "$_tmp" >/dev/null; then
  rm -f "$_tmp"; die "Generated sudoers rule is invalid — $PUB_SUDOERS_FILE not written"
fi
mv -f "$_tmp" "$PUB_SUDOERS_FILE"
log "host-hardening: sudoers written: $PUB_SUDOERS_FILE ($RUN_USER may run $PUB_DEST)"

_tmp="$(mktemp /etc/sudoers.d/.appcrane-db-chain.XXXXXX)"
cat > "$_tmp" <<SUDOERS
# Written by AppCrane scripts/install-host-hardening.sh
# Lets ${RUN_USER} set the APPCRANE-DB chain; the script accepts only allow:<port>:<address> and close:<port> arguments.
${RUN_USER} ALL=(root) NOPASSWD: ${DB_DEST}
SUDOERS
chown root:root "$_tmp"
chmod 0440 "$_tmp"
if ! visudo -cf "$_tmp" >/dev/null; then
  rm -f "$_tmp"; die "Generated sudoers rule is invalid — $DB_SUDOERS_FILE not written"
fi
mv -f "$_tmp" "$DB_SUDOERS_FILE"
log "host-hardening: sudoers written: $DB_SUDOERS_FILE ($RUN_USER may run $DB_DEST)"
