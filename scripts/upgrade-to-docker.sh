#!/usr/bin/env bash
#
# Idempotent upgrade to v1.4.0 runtime (Docker + systemd). Two phases:
#
#   prepare  — safe to run under PM2 (never kills self)
#               install docker.io, write appcrane.service, systemctl enable (no start)
#
#   cutover  — must run detached from the old process
#               systemctl start appcrane.service (will wait on busy port),
#               pm2 kill (frees port), then verify health
#
#   full     — prepare + cutover (used by install.sh on fresh hosts where no PM2 is running)
#
# Called by /api/self-update (phases 'prepare' inline, 'cutover' detached) and by install.sh ('full').

set -euo pipefail

PHASE="${1:?Usage: upgrade-to-docker.sh <prepare|cutover|cleanup|full> <repo-dir> <run-user>}"
REPO_DIR="${2:?repo-dir required}"
RUN_USER="${3:?run-user required}"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }

[[ $EUID -eq 0 ]] || { warn "upgrade-to-docker.sh must run as root"; exit 1; }

do_prepare() {
  # 1. Docker
  if ! command -v docker >/dev/null 2>&1; then
    log "Installing docker.io"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y docker.io
    systemctl enable --now docker
  else
    log "Docker already present: $(docker --version | head -n1)"
  fi

  # 2. Docker group
  if ! id -nG "$RUN_USER" | tr ' ' '\n' | grep -qx docker; then
    log "Adding $RUN_USER to docker group"
    usermod -aG docker "$RUN_USER"
  fi

  # 3. systemd unit (write + enable, do NOT start — port may still be held by PM2)
  NODE_BIN="$(command -v node)"
  SERVICE_FILE="/etc/systemd/system/appcrane.service"
  log "Writing $SERVICE_FILE"
  cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=AppCrane — self-hosted deployment manager
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${REPO_DIR}
ExecStart=${NODE_BIN} server/index.js
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
KillSignal=SIGTERM
TimeoutStopSec=20
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl enable appcrane.service
  log "prepare complete — systemd unit written and enabled (not started)"
}

kill_pm2_if_running() {
  # Hunt down EVERY way PM2 can come back, then kill the daemon.
  # Returns 0 if any PM2 artifact was removed/killed, 1 if host was already clean.
  #
  # Steps in order (each step prevents the next-fastest respawn vector):
  #   1. Disable + remove every systemd unit with 'pm2' in the name
  #   2. Strip pm2 lines from root's crontab
  #   3. Comment out pm2 invocations in shell rc files
  #   4. Delete ~/.pm2/dump.pm2 so a stray pm2 invocation can't resurrect apps
  #   5. Kill the daemon (via pm2 kill if a binary exists, else direct kill)
  #   6. Remove ~/.pm2 entirely so PM2_HOME is gone
  local did_work=1
  local run_home; run_home="$(getent passwd "$RUN_USER" | cut -d: -f6)"

  # 1. systemd units — any unit whose name contains 'pm2'
  local units; units="$(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^pm2' || true)"
  for u in $units; do
    log "Disabling systemd unit: $u"
    systemctl disable "$u" 2>/dev/null || true
    systemctl stop    "$u" 2>/dev/null || true
    local unit_file
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
      [[ -f "$d/$u" ]] && rm -f "$d/$u" && log "  removed $d/$u"
    done
    did_work=0
  done
  # Clean any leftover symlinks in *.wants/
  find /etc/systemd/system -name 'pm2*' 2>/dev/null | while read -r f; do
    rm -f "$f"; log "  removed leftover $f"
  done
  systemctl daemon-reload

  # 2. cron — any pm2 line in root's crontab
  if crontab -l -u "$RUN_USER" 2>/dev/null | grep -qi pm2; then
    log "Stripping pm2 lines from $RUN_USER crontab"
    crontab -l -u "$RUN_USER" 2>/dev/null | grep -vi pm2 | crontab -u "$RUN_USER" -
    did_work=0
  fi

  # 3. shell rc files — comment out anything that runs pm2 on shell init
  for rc in "$run_home/.bashrc" "$run_home/.bash_profile" "$run_home/.profile" "$run_home/.zshrc"; do
    if [[ -f "$rc" ]] && grep -qE '^[^#]*pm2' "$rc" 2>/dev/null; then
      log "Commenting pm2 lines in $rc"
      sed -i.appcrane-bak -E 's|^([^#]*pm2)|# [appcrane] disabled: \1|' "$rc"
      did_work=0
    fi
  done

  # 4. dump.pm2 — saved process list that PM2 resurrects from on next invocation
  if [[ -f "$run_home/.pm2/dump.pm2" ]]; then
    log "Removing $run_home/.pm2/dump.pm2 (PM2 resurrection list)"
    rm -f "$run_home/.pm2/dump.pm2" "$run_home/.pm2/dump.pm2.bak" 2>/dev/null || true
    did_work=0
  fi

  # 5. Kill the daemon
  local pids="$(pgrep -f 'PM2.*God Daemon' 2>/dev/null || true)"
  local sock="$run_home/.pm2/rpc.sock"
  if [[ -n "$pids" ]] || [[ -S "$sock" ]]; then
    log "PM2 daemon detected (pids: ${pids:-none}, sock: $sock)"
    local pm2_bin="$(command -v pm2 2>/dev/null || true)"
    [[ -z "$pm2_bin" && -x "$REPO_DIR/node_modules/pm2/bin/pm2" ]] && pm2_bin="$REPO_DIR/node_modules/pm2/bin/pm2"
    if [[ -n "$pm2_bin" ]]; then
      log "Killing PM2 via $pm2_bin"
      sudo -u "$RUN_USER" -H "$pm2_bin" kill >/dev/null 2>&1 || true
    fi
    pids="$(pgrep -f 'PM2.*God Daemon' 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      log "Killing PM2 daemon PIDs directly: $pids"
      kill $pids 2>/dev/null || true
      sleep 1
      pids="$(pgrep -f 'PM2.*God Daemon' 2>/dev/null || true)"
      [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null || true
    fi
    did_work=0
  fi

  # 6. Remove PM2_HOME entirely — last-line defense against any future invocation
  if [[ -d "$run_home/.pm2" ]]; then
    log "Removing $run_home/.pm2 (PM2_HOME)"
    rm -rf "$run_home/.pm2"
    did_work=0
  fi

  return $did_work
}

bulk_redeploy_all_apps() {
  # Write a sentinel file; AppCrane's startup hook reads it, queues deploys
  # in-process, then deletes it. Avoids the jq + config.json + API-key chain.
  local data_dir sentinel
  data_dir="${REPO_DIR}/data"
  mkdir -p "$data_dir" 2>/dev/null || true
  sentinel="$data_dir/needs-bulk-redeploy"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$sentinel"
  chown "$RUN_USER":"$RUN_USER" "$sentinel" 2>/dev/null || true
  log "Bulk-redeploy sentinel written: $sentinel"
  log "  AppCrane will queue deploys on its next startup"
}

do_cleanup() {
  # Idempotent post-upgrade hygiene — runs on every self-update once AppCrane
  # is under systemd. Safe because killing PM2 cannot kill *us* (we're now a
  # systemd-managed process, independent of the PM2 daemon).
  # If PM2 was actually killed, those apps are offline → trigger bulk redeploy.
  if kill_pm2_if_running; then
    log "cleanup: PM2 artifacts removed — apps were offline, rebuilding as containers"
    # Wait for appcrane to be responsive before hitting its API
    for i in $(seq 1 20); do
      curl -fsS http://localhost:5001/api/info >/dev/null 2>&1 && break
      sleep 1
    done
    bulk_redeploy_all_apps
  else
    log "cleanup: nothing to do"
  fi
}

do_cutover() {
  # Helpers might run before systemd knows about the unit — reload to be safe.
  systemctl daemon-reload

  # Queue the start first. systemd will keep trying (Restart=always) once pm2 releases :5001.
  log "Starting appcrane.service (may fail once while PM2 still holds port)"
  systemctl start appcrane.service || true

  # Give the HTTP response a moment to flush before killing pm2.
  sleep 2

  if ! kill_pm2_if_running; then
    log "No PM2 daemon detected — skipping PM2 cutover"
  fi

  # Nudge the service — first attempt likely failed while PM2 held the port.
  systemctl reset-failed appcrane.service 2>/dev/null || true
  systemctl restart appcrane.service || true

  # Verify health — systemd will also auto-restart, so we retry for 20s.
  log "Waiting for appcrane to respond on :5001"
  HEALTHY=0
  for i in $(seq 1 20); do
    if curl -fsS http://localhost:5001/api/info >/dev/null 2>&1; then
      log "appcrane is up (attempt $i)"
      HEALTHY=1
      break
    fi
    sleep 1
  done
  if [[ "$HEALTHY" != "1" ]]; then
    warn "appcrane did not respond within 20s — check: journalctl -u appcrane -n 80"
    exit 2
  fi

  bulk_redeploy_all_apps
}

case "$PHASE" in
  prepare) do_prepare ;;
  cutover) do_cutover ;;
  cleanup) do_cleanup ;;
  full)    do_prepare; do_cutover ;;
  *)       warn "Unknown phase: $PHASE"; exit 1 ;;
esac
