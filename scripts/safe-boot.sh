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

# ---------------------------------------------------------------------------
# Runtime reconciliation (v2.55.1)
# ---------------------------------------------------------------------------
#
# THIS IS THE ONLY NEW CODE A STUCK HOST WILL RUN.
#
# The self-update endpoint lives inside server/index.js, so the updater that
# executes is always the version being upgraded FROM. A host provisioned below
# the current Node floor runs an updater with no Node step: it does `git reset
# --hard origin/main` (which succeeds), then `npm install`, which .npmrc's
# engine-strict correctly refuses — leaving the working tree ahead of
# node_modules and the update dead. Measured: npm enforces engine-strict BEFORE
# any lifecycle script, so a preinstall hook cannot rescue it either.
#
# But the reset DID land, and systemd's ExecStart is this file, from that tree.
# So the next restart runs the NEW wrapper even though the node process was old.
# That makes this the one place a fix can reach a host that is already stuck.
#
# Everything here fails open. A boot wrapper that refuses to boot is worse than
# the problem it is solving, so every branch ends by spawning node anyway.

node_major() { node -p "process.versions.node.split('.')[0]" 2>/dev/null || echo ""; }

required_node_major() {
  node -p "((((require('${APPCRANE_DIR}/package.json').engines)||{}).node)||'').match(/(\\d+)/)?.[1]||''" 2>/dev/null || echo ""
}

# apt + nodesource, as root directly or via passwordless sudo. Anything else
# (no apt, no root, sudo wants a password) is not an error here — it is a host
# this script cannot fix, and it gets told exactly what to run.
upgrade_node() {
  local want="$1" sudo_cmd=""
  if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true 2>/dev/null; then sudo_cmd="sudo -n"; else return 1; fi
  fi
  command -v apt-get >/dev/null 2>&1 || return 1
  log "upgrading Node to ${want}.x via nodesource"
  # shellcheck disable=SC2086
  curl -fsSL "https://deb.nodesource.com/setup_${want}.x" | $sudo_cmd bash - >&2 || return 1
  # shellcheck disable=SC2086
  $sudo_cmd apt-get install -y nodejs >&2 || return 1
  return 0
}

reconcile_runtime() {
  local have want
  have="$(node_major)"; want="$(required_node_major)"
  if [ -z "$have" ] || [ -z "$want" ]; then
    log "runtime check skipped (node=${have:-?}, required=${want:-?})"
    return 0
  fi
  if [ "$have" -ge "$want" ]; then
    # Still install if a previous update reset the tree but never got to npm.
    if [ ! -d "$APPCRANE_DIR/node_modules" ]; then
      log "node_modules missing — installing"
      npm install --omit=dev --prefer-offline 2>&1 | sed 's/^/[safe-boot] npm: /' >&2 || true
    fi
    return 0
  fi

  log "Node v${have} is below this release's floor of v${want} — a self-update cannot install dependencies until this is fixed"
  if upgrade_node "$want"; then
    log "Node is now $(node -v 2>/dev/null) — installing dependencies the blocked update could not"
    if npm install --omit=dev --prefer-offline 2>&1 | sed 's/^/[safe-boot] npm: /' >&2; then
      log "runtime reconciled; the stalled update is complete"
    else
      log "npm install still failed after the Node upgrade — booting anyway on the existing node_modules"
    fi
  else
    log "cannot upgrade Node automatically (needs root or passwordless sudo, and apt-get). Run on this host:"
    log "    curl -fsSL https://deb.nodesource.com/setup_${want}.x | sudo -E bash -"
    log "    sudo apt-get install -y nodejs && sudo systemctl restart appcrane"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Native addon ABI (v2.58.0)
# ---------------------------------------------------------------------------
#
# better-sqlite3 is a V8-ABI addon, not N-API: a binary built for Node 20
# declares MODULE_VERSION 115 and Node 22 demands 127. So ANY Node major change
# breaks it instantly — and the break is not at startup, it is at the first
# `new Database()`, which is why a bare `require()` succeeds and tells you
# nothing.
#
# This does not need an AppCrane update to happen. unattended-upgrades moving
# Node 20 -> 22 on its own is enough, and did it: the addon stopped loading, the
# process died on every boot, and with `Restart=always RestartSec=3` and no
# start limit systemd restarted it 10,394 times before anyone noticed.
#
# Measured on the real dependency tree (node:20 build, node:22 runtime):
#   npm install --omit=dev --prefer-offline  -> STILL BROKEN
#   npm rebuild better-sqlite3               -> FIXED
# The install is not enough because npm sees node_modules as satisfied and skips
# the addon entirely; only an explicit rebuild recompiles against the new ABI.
#
# Probed rather than inferred from a version stamp: the probe is the same
# operation the app performs on its first query, so it cannot disagree with
# reality the way a stamp can after a manual npm install or a restored backup.

NATIVE_PROBE='const D=require("better-sqlite3"); new D(":memory:").prepare("select 1").get();'

native_ok() { node -e "$NATIVE_PROBE" >/dev/null 2>&1; }

reconcile_native() {
  if native_ok; then return 0; fi
  log "better-sqlite3 does not load under $(node -v 2>/dev/null) — its ABI does not match this runtime. Rebuilding."
  if npm rebuild better-sqlite3 2>&1 | sed 's/^/[safe-boot] rebuild: /' >&2 && native_ok; then
    log "native addon rebuilt against $(node -v 2>/dev/null) and loading"
  else
    log "rebuild did not fix better-sqlite3 — the app will crash on its first query."
    log "    build tools may be missing: apt-get install -y python3 make g++"
  fi
}

# --check-runtime prints the decision and exits, so the logic is testable
# without booting AppCrane or touching apt.
if [ "${1:-}" = "--check-runtime" ]; then
  have="$(node_major)"; want="$(required_node_major)"
  echo "have=${have:-?} want=${want:-?}"
  if [ -n "$have" ] && [ -n "$want" ] && [ "$have" -lt "$want" ]; then
    echo "decision=upgrade"
  else
    echo "decision=ok"
  fi
  if native_ok; then echo "native=ok"; else echo "native=broken"; fi
  exit 0
fi

reconcile_runtime
reconcile_native

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
