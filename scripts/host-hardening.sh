#!/usr/bin/env bash
#
# Cap host logs, keep disk headroom and turn on unattended security upgrades
# on an AppCrane box.
#
# Called by install.sh; also safe to run on an existing install:
#   sudo bash scripts/host-hardening.sh
#
# A production box once filled its disk to 100%: a 4 GB journal (a size limit
# had been written but journald was never restarted, so it never applied) plus
# ~1.2 GB of syslog that only rotated weekly. This script sets the limits AND
# applies them now. Re-running is safe: files are rewritten only when they differ.
#
# It never restarts Docker — that would stop every app container.
#
# Knob (for tests / small disks): APPCRANE_RESERVE_MIN_FREE_GB, the free space
# that must remain after the reserve file is created (default 10).

set -euo pipefail

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# systemctl exists in containers and chroots too, but only talks to a running
# systemd; check for one so the script still completes without it.
have_systemd() { [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; }

# write_if_changed <path> <content>: prints "changed" or "unchanged".
write_if_changed() {
  local path="$1" content="$2"
  if [[ -f "$path" ]] && [[ "$(cat "$path")" == "$content" ]]; then
    echo unchanged; return
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
  echo changed
}

# ---------- journald -------------------------------------------------------
# SystemMaxUse caps the persistent journal; SystemKeepFree makes journald stop
# growing (and trim) before the disk itself runs low, whichever bites first.
# 500M holds weeks of an AppCrane box's journal at the measured rate; 2G of
# keep-free leaves room for a deploy's image pull and build. A drop-in, not an
# edit to journald.conf, so package upgrades never conflict; an operator who
# wants other values adds a later-sorting file (e.g. 60-local.conf).
JOURNALD_DROPIN=/etc/systemd/journald.conf.d/50-appcrane.conf
JOURNALD_CONF="# Written by AppCrane scripts/host-hardening.sh
[Journal]
SystemMaxUse=500M
SystemKeepFree=2G
MaxRetentionSec=1month"
log "journald: $JOURNALD_DROPIN $(write_if_changed "$JOURNALD_DROPIN" "$JOURNALD_CONF")"

# Writing the limit is not enough — journald reads it only at start, and the
# space already used is released only by a vacuum. Do both, every run.
if have_systemd; then
  systemctl restart systemd-journald || warn "journald restart failed — limit applies at next boot"
else
  warn "journald: no running systemd — limit applies when journald next starts"
fi
if command -v journalctl >/dev/null 2>&1; then
  journalctl --vacuum-size=500M || warn "journalctl --vacuum-size failed"
fi

# ---------- syslog rotation ------------------------------------------------
# Ubuntu rotates rsyslog's files weekly (syslog daily on 20.04), with no size
# limit, so one noisy day can fill the disk. Add `maxsize 200M` to each stanza
# of the packaged /etc/logrotate.d/rsyslog: a second stanza naming the same
# files would make logrotate fail with "duplicate log entry". The edit is
# validated on a copy before it replaces the original.
RSYSLOG_LR=/etc/logrotate.d/rsyslog
if [[ ! -f "$RSYSLOG_LR" ]]; then
  log "logrotate: $RSYSLOG_LR not present (rsyslog not installed) — skipped"
elif grep -qE '^[[:space:]]*maxsize[[:space:]]' "$RSYSLOG_LR"; then
  log "logrotate: $RSYSLOG_LR already has maxsize — unchanged"
elif ! command -v logrotate >/dev/null 2>&1; then
  warn "logrotate: not installed — $RSYSLOG_LR left as is"
else
  # Validate the whole configuration as logrotate will read it — the edited
  # file alone fails, since the global `su` directive lives in logrotate.conf —
  # using a copy of /etc/logrotate.d with the edited file swapped in.
  _lr_dir="$(mktemp -d)"; _lr_state="$(mktemp)"
  _lr_tmp="$_lr_dir/d/rsyslog"
  cp -a /etc/logrotate.d "$_lr_dir/d"
  awk '{ print } /^[[:space:]]*\{[[:space:]]*$/ { print "\tmaxsize 200M" }' "$RSYSLOG_LR" > "$_lr_tmp"
  sed "s#^\([[:space:]]*include[[:space:]]\+\)/etc/logrotate\.d#\1$_lr_dir/d#" /etc/logrotate.conf > "$_lr_dir/logrotate.conf"
  if ! grep -q 'maxsize 200M' "$_lr_tmp"; then
    warn "logrotate: no stanza found in $RSYSLOG_LR — layout differs from Ubuntu's; left as is"
  elif _lr_err="$(logrotate -d -s "$_lr_state" "$_lr_dir/logrotate.conf" 2>&1)"; then
    # Back up outside /etc/logrotate.d: logrotate reads every file there whose
    # extension it does not ignore (".bak" is not ignored), so a copy there
    # would itself cause "duplicate log entry".
    mkdir -p /var/backups
    cp -p "$RSYSLOG_LR" "/var/backups/logrotate-rsyslog.appcrane-bak.$(date +%s)"
    cat "$_lr_tmp" > "$RSYSLOG_LR"
    log "logrotate: added maxsize 200M to $RSYSLOG_LR (original in /var/backups)"
  else
    warn "logrotate: edited $RSYSLOG_LR fails logrotate -d — left as is:"
    grep -i 'error' <<<"$_lr_err" | head -5 >&2 || true
  fi
  rm -rf "$_lr_dir" "$_lr_state"
fi

# maxsize is checked only when logrotate runs, and Ubuntu's timer runs it daily.
# Run it hourly; daily/weekly rotation still follows the state file, so only the
# size check gets more frequent.
LR_TIMER_DROPIN=/etc/systemd/system/logrotate.timer.d/50-appcrane.conf
LR_TIMER_CONF="# Written by AppCrane scripts/host-hardening.sh
[Timer]
OnCalendar=
OnCalendar=hourly
AccuracySec=5min"
_timer_state="$(write_if_changed "$LR_TIMER_DROPIN" "$LR_TIMER_CONF")"
log "logrotate: $LR_TIMER_DROPIN $_timer_state"
if have_systemd; then
  systemctl daemon-reload || true
  systemctl restart logrotate.timer 2>/dev/null || warn "logrotate.timer restart failed"
fi

# ---------- Docker default log limits -------------------------------------
# AppCrane already passes --log-opt max-size to the containers it starts; this
# covers everything else (builds, helpers, containers run by hand). Merged into
# daemon.json only when the operator chose no logging settings of their own.
DJSON=/etc/docker/daemon.json
DOCKER_LOG_OPTS='{"max-size":"10m","max-file":"3"}'
if [[ ! -f "$DJSON" ]]; then
  mkdir -p /etc/docker
  jq -n --argjson o "$DOCKER_LOG_OPTS" '{"log-opts": $o}' > "$DJSON"
  log "docker: wrote $DJSON with default log-opts — applies at the next Docker restart"
elif ! jq empty "$DJSON" >/dev/null 2>&1; then
  warn "docker: $DJSON is not valid JSON — log-opts not added, file left untouched"
elif jq -e 'has("log-opts") or has("log-driver")' "$DJSON" >/dev/null 2>&1; then
  log "docker: $DJSON already sets log-opts/log-driver — unchanged"
else
  cp "$DJSON" "${DJSON}.appcrane-bak.$(date +%s)"
  _tmp="$(mktemp)"
  jq --argjson o "$DOCKER_LOG_OPTS" '. + {"log-opts": $o}' "$DJSON" > "$_tmp" && mv "$_tmp" "$DJSON"
  chmod 644 "$DJSON"
  log "docker: added default log-opts to $DJSON — applies at the next Docker restart"
fi

# ---------- gVisor (runsc) container runtime -------------------------------
# Lets AppCrane start app containers with --runtime=runsc (services/
# containerRuntime.js): a user-space kernel between the app and the host, for
# apps whose owners do not trust each other. Installing it changes nothing on
# its own; apps stay on runc until a platform admin picks runsc.
#
# A pinned release, checked against the SHA-512 recorded here (not only the
# .sha512 file served next to it), installed where gVisor's install guide puts
# it: /usr/local/bin, with gvisor-bin/ beside runsc. Registered by merging one
# key into daemon.json (every other key kept, the old file backed up, the new
# one checked with `dockerd --validate` first), then applied with a RELOAD:
# Docker's docs say "After changing the runtimes configuration in the
# configuration file, you must reload or restart the daemon", and a reload
# (SIGHUP) leaves running containers alone. If dockerd does not list runsc
# after the reload, the backup is put back and reloaded.
#
# platform systrap: runsc's default ("systrap (default), ptrace, kvm, auto",
# `runsc flags`), and the one that needs no /dev/kvm, so it works on EC2
# instances that are not bare metal. Written explicitly so a later runsc
# default change does not move it.
GVISOR_RELEASE=20261116
GVISOR_PATH=/usr/local/bin/runsc
case "$(uname -m)" in
  x86_64)  GVISOR_ARCH=x86_64;  GVISOR_SHA512=c87d792d5842efb70c38ee822124cfe0821a547715e7abcf3f2b14997cd02784edaa0b91e238ec5c27a25a1b9e00bf98113398eb62a0778d8d20d4e222f8b0e0 ;;
  aarch64) GVISOR_ARCH=aarch64; GVISOR_SHA512=a64ce2d5ba6825a0a6459ee6a9ce40164749c2d276a945b885673988c4e545e66b2f4ef3a08e068a26cca676061c8c5e8ba982156feb786f0eab995f5b8b854d ;;
  *)       GVISOR_ARCH="" ;;
esac
GVISOR_RUNTIME="{\"path\":\"$GVISOR_PATH\",\"runtimeArgs\":[\"--platform=systrap\"]}"
DJSON=/etc/docker/daemon.json

docker_reload() {
  if have_systemd && systemctl is-active --quiet docker 2>/dev/null; then
    systemctl reload docker
  elif pidof dockerd >/dev/null 2>&1; then
    kill -HUP "$(pidof dockerd)"
  else
    return 2
  fi
}
docker_has_runsc() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    docker info --format '{{json .Runtimes}}' 2>/dev/null | jq -e 'has("runsc")' >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

if [[ -z "$GVISOR_ARCH" ]]; then
  warn "gvisor: no gVisor release for $(uname -m) — skipped"
elif [[ "$(uname -s)" != Linux ]]; then
  warn "gvisor: not Linux — skipped"
else
  _gv_have="$("$GVISOR_PATH" --version 2>/dev/null | sed -n 's/^runsc version release-\([0-9]*\).*/\1/p' || true)"
  if [[ "$_gv_have" == "$GVISOR_RELEASE" ]]; then
    log "gvisor: runsc release-$GVISOR_RELEASE already installed"
  else
    _gv_tmp="$(mktemp -d)"
    _gv_url="https://storage.googleapis.com/gvisor/releases/release/$GVISOR_RELEASE/$GVISOR_ARCH/gvisor.tar.bz2"
    command -v bzip2 >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bzip2 >/dev/null 2>&1 \
      || { apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bzip2 >/dev/null 2>&1; } || true
    if ! curl -fsSL --retry 3 -o "$_gv_tmp/gvisor.tar.bz2" "$_gv_url"; then
      warn "gvisor: download of $_gv_url failed — runsc not installed"
    elif ! (cd "$_gv_tmp" && echo "$GVISOR_SHA512  gvisor.tar.bz2" | sha512sum -c --quiet -); then
      warn "gvisor: $_gv_url does not match the pinned SHA-512 — runsc not installed"
    elif ! mkdir -p "$_gv_tmp/x" || ! tar -xjf "$_gv_tmp/gvisor.tar.bz2" -C "$_gv_tmp/x" \
      || [[ ! -f "$_gv_tmp/x/runsc" || ! -f "$_gv_tmp/x/containerd-shim-runsc-v1" ]]; then
      warn "gvisor: could not unpack gvisor.tar.bz2 (bzip2 missing?) — runsc not installed"
    else
      install -o root -g root -m 0755 "$_gv_tmp/x/runsc" "$_gv_tmp/x/containerd-shim-runsc-v1" /usr/local/bin/
      rm -rf /usr/local/bin/gvisor-bin
      cp -r "$_gv_tmp/x/gvisor-bin" /usr/local/bin/gvisor-bin
      chown -R root:root /usr/local/bin/gvisor-bin
      chmod -R a+rX,go-w /usr/local/bin/gvisor-bin
      log "gvisor: installed $("$GVISOR_PATH" --version | head -1) at $GVISOR_PATH"
    fi
    rm -rf "$_gv_tmp"
  fi

  if [[ ! -x "$GVISOR_PATH" ]]; then
    :
  elif [[ -f "$DJSON" ]] && ! jq empty "$DJSON" >/dev/null 2>&1; then
    warn "gvisor: $DJSON is not valid JSON — runsc not registered, file left untouched"
  elif [[ -f "$DJSON" ]] && jq -e --argjson r "$GVISOR_RUNTIME" '.runtimes.runsc == $r' "$DJSON" >/dev/null 2>&1; then
    log "gvisor: runsc already registered in $DJSON"
    if docker info >/dev/null 2>&1 && ! docker_has_runsc; then
      if docker_reload; then docker_has_runsc && log "gvisor: dockerd reloaded, runsc available" || warn "gvisor: dockerd still lists no runsc after a reload"; fi
    fi
  else
    mkdir -p /etc/docker
    _gv_new="$(mktemp /etc/docker/.daemon.json.XXXXXX)"
    if [[ -f "$DJSON" ]]; then jq --argjson r "$GVISOR_RUNTIME" '.runtimes = ((.runtimes // {}) + {runsc: $r})' "$DJSON" > "$_gv_new"
    else jq -n --argjson r "$GVISOR_RUNTIME" '{runtimes: {runsc: $r}}' > "$_gv_new"; fi
    _gv_valid=yes
    if command -v dockerd >/dev/null 2>&1 && dockerd --help 2>&1 | grep -q -- '--validate'; then
      _gv_err="$(dockerd --validate --config-file "$_gv_new" 2>&1)" || _gv_valid="$_gv_err"
    fi
    if [[ "$_gv_valid" != yes ]]; then
      rm -f "$_gv_new"
      warn "gvisor: dockerd --validate refused the merged daemon.json — left as is: $_gv_valid"
    else
      _gv_bak=""
      if [[ -f "$DJSON" ]]; then _gv_bak="${DJSON}.appcrane-bak.$(date +%s)"; cp -p "$DJSON" "$_gv_bak"; fi
      chmod 644 "$_gv_new"
      mv -f "$_gv_new" "$DJSON"
      log "gvisor: registered runsc (platform systrap) in $DJSON${_gv_bak:+ (previous file: $_gv_bak)}"
      if ! docker info >/dev/null 2>&1; then
        log "gvisor: dockerd is not running — runsc is available from its next start"
      elif ! docker_reload; then
        warn "gvisor: could not reload dockerd — runsc is available after the next Docker reload"
      elif docker_has_runsc; then
        log "gvisor: dockerd reloaded (running containers untouched); runsc is available"
      else
        warn "gvisor: dockerd lists no runsc after the reload — restoring the previous $DJSON"
        if [[ -n "$_gv_bak" ]]; then cp -p "$_gv_bak" "$DJSON"; else rm -f "$DJSON"; fi
        docker_reload || true
      fi
    fi
  fi
fi

# ---------- Ubuntu Pro apt news --------------------------------------------
# apt_news runs hourly and, under AppArmor, logs a denial each time: journal
# noise with no value on a server.
if command -v pro >/dev/null 2>&1; then
  if pro config set apt_news=false >/dev/null 2>&1; then
    log "ubuntu pro: apt_news disabled"
  else
    warn "ubuntu pro: could not disable apt_news (ignored)"
  fi
fi

# ---------- unattended security upgrades -----------------------------------
# AppCrane mails admins about pending security updates (hostVulns.js); this is
# the half that installs them without waiting for someone to read that mail.
# Ubuntu's 50unattended-upgrades already limits it to the -security pocket (and
# ESM when attached) and leaves Automatic-Reboot off; that file is not touched,
# so no reboot is ever scheduled from here. 20auto-upgrades is written only
# when it does not exist: an existing one is the operator's (or debconf's)
# choice, including a deliberate "0".
AUTO_UPGRADES=/etc/apt/apt.conf.d/20auto-upgrades
AUTO_UPGRADES_CONF='// Written by AppCrane scripts/host-hardening.sh
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
if ! command -v apt-get >/dev/null 2>&1; then
  log "unattended-upgrades: not an apt system — skipped"
else
  if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
    log "unattended-upgrades: already installed"
  # A box whose package lists were cleaned (images, fresh containers) cannot
  # install anything until they are fetched again.
  elif DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null 2>&1 \
    || { apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null 2>&1; }; then
    log "unattended-upgrades: installed"
  else
    warn "unattended-upgrades: apt-get install failed — security updates stay manual"
  fi
  if [[ -f "$AUTO_UPGRADES" ]]; then
    log "unattended-upgrades: $AUTO_UPGRADES exists — left as is"
  else
    write_if_changed "$AUTO_UPGRADES" "$AUTO_UPGRADES_CONF" >/dev/null
    log "unattended-upgrades: wrote $AUTO_UPGRADES (daily list update + security upgrades)"
  fi
  if [[ "$(apt-config shell V APT::Periodic::Unattended-Upgrade 2>/dev/null)" != *"V='1'"* ]]; then
    warn "unattended-upgrades: APT::Periodic::Unattended-Upgrade is not \"1\" — security updates are not applied automatically"
  fi
fi

# ---------- Caddy access-log directory ------------------------------------
# AppCrane points Caddy's redacted access log at /var/log/caddy/access.log only
# when that directory exists (caddy.js). It must belong to the user Caddy runs
# as: a root-owned directory makes Caddy fail to open the log and the reload
# that added it fails with it.
CADDY_LOG_DIR=/var/log/caddy
_caddy_user=""
if have_systemd; then
  _caddy_user="$(systemctl show -p User --value caddy 2>/dev/null || true)"
fi
_caddy_user="${_caddy_user:-caddy}"
if ! id -u "$_caddy_user" >/dev/null 2>&1; then
  warn "caddy log dir: user '$_caddy_user' does not exist — $CADDY_LOG_DIR not created"
else
  _caddy_group="$(id -gn "$_caddy_user")"
  _before="$(stat -c '%U:%G %a' "$CADDY_LOG_DIR" 2>/dev/null || echo missing)"
  mkdir -p "$CADDY_LOG_DIR"
  chown "$_caddy_user:$_caddy_group" "$CADDY_LOG_DIR"
  chmod 0750 "$CADDY_LOG_DIR"
  if [[ "$_before" == "$_caddy_user:$_caddy_group 750" ]]; then
    log "caddy log dir: $CADDY_LOG_DIR already $_caddy_user:$_caddy_group 0750"
  else
    log "caddy log dir: $CADDY_LOG_DIR set to $_caddy_user:$_caddy_group 0750 (was: $_before)"
  fi
fi

# ---------- disk reserve file ---------------------------------------------
# A 1 GiB placeholder on the filesystem holding DATA_DIR. When that disk fills,
# deleting it frees enough room to log in, run a vacuum and restart services.
# It lives at the filesystem's mount point, outside DATA_DIR, so backups of the
# data never copy it.
DATA_DIR="$REPO_DIR/data"
if [[ -f "$REPO_DIR/.env" ]]; then
  _dd="$(sed -n 's/^DATA_DIR=//p' "$REPO_DIR/.env" | tail -n1 | tr -d '"'"'"'')"
  if [[ -n "$_dd" ]]; then
    [[ "$_dd" == /* ]] && DATA_DIR="$_dd" || DATA_DIR="$REPO_DIR/$_dd"
  fi
fi
_probe="$DATA_DIR"
while [[ ! -e "$_probe" ]]; do _probe="$(dirname "$_probe")"; done
_mount="$(df -P "$_probe" | awk 'NR==2 {print $6}')"
RESERVE="${_mount%/}/appcrane-disk-reserve"
RESERVE_BYTES=$((1024 * 1024 * 1024))
MIN_FREE_GB="${APPCRANE_RESERVE_MIN_FREE_GB:-10}"

# Root writes here, and DATA_DIR comes from .env, which the run user can edit.
# So only a root-owned mount point that nobody else can write to is used, and
# never through a symlink: otherwise a planted link would point fallocate and
# chmod at a system file.
_mstat="$(stat -c '%u %a' "$_mount")"
if [[ "${_mstat%% *}" != 0 ]] || (( 8#${_mstat##* } & 8#022 )); then
  warn "reserve: $_mount is not root-owned or is writable by others — skipped"
elif [[ -L "$RESERVE" ]] || { [[ -e "$RESERVE" ]] && [[ ! -f "$RESERVE" ]]; }; then
  warn "reserve: $RESERVE is a symlink or not a regular file — left alone, skipped"
elif [[ -f "$RESERVE" ]] && [[ "$(stat -c %s "$RESERVE")" -ge "$RESERVE_BYTES" ]]; then
  log "reserve: $RESERVE already present"
else
  _avail_kb="$(df -Pk "$_mount" | awk 'NR==2 {print $4}')"
  _need_kb=$(( (MIN_FREE_GB * 1024 * 1024) + (RESERVE_BYTES / 1024) ))
  if (( _avail_kb < _need_kb )); then
    warn "reserve: only $((_avail_kb / 1024 / 1024)) GiB free on $_mount — need ${MIN_FREE_GB} GiB left after 1 GiB; skipped"
  else
    rm -f "$RESERVE"
    if ! fallocate -l "$RESERVE_BYTES" "$RESERVE" 2>/dev/null; then
      dd if=/dev/zero of="$RESERVE" bs=1M count=1024 status=none
    fi
    chmod 600 "$RESERVE"
    log "reserve: created 1 GiB $RESERVE"
  fi
fi
[[ -f "$RESERVE" ]] && log "reserve: if this disk fills, free 1 GiB with:  sudo rm $RESERVE"

log "Host hardening done"
