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

RUN_USER="${1:-}"
if [[ -z "$RUN_USER" ]] && [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
  RUN_USER="$(systemctl show -p User --value appcrane 2>/dev/null || true)"
fi
RUN_USER="${RUN_USER:-${SUDO_USER:-root}}"

[[ -f "$SRC" ]] || die "$SRC not found"
[[ "$REPO_DIR" != *"'"* ]] || die "Repo path contains a single quote: $REPO_DIR"
[[ "$RUN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Not a valid user name: $RUN_USER"
id -u "$RUN_USER" >/dev/null 2>&1 || die "User does not exist: $RUN_USER"

# install -d also resets the owner and mode of a directory that already exists.
install -d -o root -g root -m 0755 "$DEST_DIR"
_tmp="$(mktemp "$DEST_DIR/.host-hardening.XXXXXX")"
REPO="$REPO_DIR" awk '!done && /^REPO_DIR=/ { print "REPO_DIR='\''" ENVIRON["REPO"] "'\''"; done = 1; next } { print }' "$SRC" > "$_tmp"
if ! grep -qxF "REPO_DIR='$REPO_DIR'" "$_tmp"; then
  rm -f "$_tmp"; die "No REPO_DIR= line in $SRC"
fi
chown root:root "$_tmp"
chmod 0755 "$_tmp"
mv -f "$_tmp" "$DEST"
log "host-hardening: installed $DEST (root:root 0755, repo $REPO_DIR)"

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
