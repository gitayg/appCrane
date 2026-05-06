#!/usr/bin/env bash
#
# safe-boot.sh — out-of-process AppCrane boot wrapper with auto-rollback.
#
# Why this exists: v2.1.8 added an in-process auto-rollback in
# server/index.js, but a migration crash kills the node process before
# the recovery handler can run. Recovery has to happen OUTSIDE the node
# process. This script wraps `node server/index.js` and rolls the working
# tree back to the previous SHA if the child crashes during boot.
#
# Usage in systemd unit:
#   ExecStart=/root/appCrane/scripts/safe-boot.sh
# (Replaces the previous `ExecStart=/usr/bin/node /root/appCrane/server/index.js`)
#
# Behavior:
#   1. Spawn `node server/index.js`. Forward SIGTERM/SIGINT to the child.
#   2. If child exits cleanly (0): we exit 0 too.
#   3. If child exits non-zero AND uptime >= BOOT_GRACE_SECONDS: treat as
#      a runtime crash, not a boot crash. Exit with the child's code; let
#      systemd's Restart= policy handle it.
#   4. If child exits non-zero AND uptime < BOOT_GRACE_SECONDS: it's a
#      boot crash. Check the pending self-update file:
#        - exists, not completed, has previous_sha, attempts < MAX
#          → git reset --hard <previous_sha> + npm install + retry
#        - else: bail with the child's exit code
#   5. Hard cap of MAX_ROLLBACK_ATTEMPTS (persisted across loop iterations
#      to the pending file) prevents infinite loop if both versions
#      are broken.
#
# Dependencies:
#   - jq (for parsing the pending file). `apt install jq` if missing.
#
# Required environment:
#   - APPCRANE_DIR (default: directory this script lives in / ..)
#   - DATA_DIR (default: $APPCRANE_DIR/data)
#
# Exit codes:
#   0   clean shutdown (child exited 0 or got SIGTERM)
#   1+  child crashed and either no rollback was possible or
#       rollback budget was exhausted

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
APPCRANE_DIR="${APPCRANE_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
DATA_DIR="${DATA_DIR:-${APPCRANE_DIR}/data}"
PENDING_FILE="${DATA_DIR}/.self-update/self-update-pending.json"
BOOT_GRACE_SECONDS="${BOOT_GRACE_SECONDS:-30}"
MAX_ROLLBACK_ATTEMPTS="${MAX_ROLLBACK_ATTEMPTS:-3}"

log() {
  echo "[safe-boot] $*" >&2
}

cd "$APPCRANE_DIR"

# Forward SIGTERM/SIGINT from systemd to the child so a clean shutdown
# stays clean.
got_signal=0
child_pid=0
on_signal() {
  got_signal=1
  if [ "$child_pid" -ne 0 ]; then
    log "received signal, forwarding to node (pid=$child_pid)"
    kill -TERM "$child_pid" 2>/dev/null || true
  fi
}
trap on_signal TERM INT

read_pending_field() {
  local field="$1"
  if ! command -v jq >/dev/null 2>&1; then
    return 1
  fi
  if [ ! -f "$PENDING_FILE" ]; then
    return 1
  fi
  jq -r ".${field} // empty" "$PENDING_FILE" 2>/dev/null
}

attempt_rollback() {
  if ! command -v jq >/dev/null 2>&1; then
    log "jq not installed — cannot parse pending file. Install jq."
    return 1
  fi
  if [ ! -f "$PENDING_FILE" ]; then
    log "no pending self-update found at $PENDING_FILE — nothing to roll back to"
    return 1
  fi

  local prev_sha prev_version attempts completed
  prev_sha="$(read_pending_field 'previous_sha')"
  prev_version="$(read_pending_field 'previous_version')"
  attempts="$(read_pending_field 'rollback_attempts')"
  completed="$(read_pending_field 'completed_at')"
  attempts="${attempts:-0}"

  if [ -n "$completed" ]; then
    log "pending update already completed — boot crash unrelated to last update"
    return 1
  fi
  if [ -z "$prev_sha" ]; then
    log "pending update has no previous_sha (legacy format pre-v2.1.8) — cannot auto-rollback. Manual recovery: git reset --hard <sha-before-${prev_version}> in $APPCRANE_DIR"
    return 1
  fi
  if [ "$attempts" -ge "$MAX_ROLLBACK_ATTEMPTS" ]; then
    log "auto-rollback budget exhausted ($attempts attempts). Both versions broken — manual intervention required."
    return 1
  fi

  log "rolling back to ${prev_version:-?} @ ${prev_sha:0:7} (attempt $((attempts + 1))/$MAX_ROLLBACK_ATTEMPTS)"

  # Persist attempt counter BEFORE destructive ops so a crash mid-rollback
  # doesn't burn an attempt without recording it.
  local tmp
  tmp="$(mktemp)"
  jq --arg n "$((attempts + 1))" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     '.rollback_attempts = ($n | tonumber) | .last_rollback_at = $t' \
     "$PENDING_FILE" > "$tmp" && mv "$tmp" "$PENDING_FILE"

  git config --global --add safe.directory "$APPCRANE_DIR" 2>/dev/null || true

  if ! git fetch origin 2>&1 | sed 's/^/[safe-boot] git fetch: /' >&2; then
    log "git fetch failed — cannot roll back"
    return 1
  fi
  if ! git reset --hard "$prev_sha" 2>&1 | sed 's/^/[safe-boot] git reset: /' >&2; then
    log "git reset --hard $prev_sha failed"
    return 1
  fi
  if ! npm install --omit=dev --prefer-offline 2>&1 | sed 's/^/[safe-boot] npm: /' >&2; then
    log "npm install failed after rollback"
    return 1
  fi

  log "rollback to ${prev_version:-?} complete; re-spawning node"
  return 0
}

while true; do
  start_time=$(date +%s)
  log "spawning node server/index.js"
  node server/index.js &
  child_pid=$!
  wait "$child_pid"
  exit_code=$?
  child_pid=0
  end_time=$(date +%s)
  uptime=$((end_time - start_time))

  if [ "$got_signal" -eq 1 ]; then
    log "exiting cleanly after signal forward (uptime=${uptime}s, child_exit=$exit_code)"
    exit 0
  fi

  if [ "$exit_code" -eq 0 ]; then
    log "node exited 0 (uptime=${uptime}s) — clean shutdown"
    exit 0
  fi

  if [ "$uptime" -ge "$BOOT_GRACE_SECONDS" ]; then
    log "node ran ${uptime}s before crash (exit=$exit_code) — runtime failure, not boot. Letting systemd handle."
    exit "$exit_code"
  fi

  log "node crashed at boot (uptime=${uptime}s, exit=$exit_code) — checking for pending self-update"
  if attempt_rollback; then
    # Loop continues: next iteration re-spawns node on the rolled-back code.
    continue
  fi

  log "no rollback possible — bailing with exit=$exit_code"
  exit "$exit_code"
done
