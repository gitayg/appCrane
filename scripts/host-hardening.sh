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

# Sections that failed. Every other section still runs; the script exits
# non-zero at the end when this is not empty.
HH_FAILED=()

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

# djson_merge <jq filter> [jq args...]: applies the filter to daemon.json (an
# empty object when there is none), checks the result with `dockerd --validate`
# when this dockerd has it, backs the old file up and moves the new one in.
# 0 written (DJSON_BAK = the backup, or "" when there was no file), 1 refused
# by dockerd --validate (DJSON_ERR = why), 2 the current file is not JSON.
djson_merge() {
  local filter="$1" new; shift
  if [[ -f "$DJSON" ]] && ! jq empty "$DJSON" >/dev/null 2>&1; then return 2; fi
  mkdir -p /etc/docker
  new="$(mktemp /etc/docker/.daemon.json.XXXXXX)"
  if [[ -f "$DJSON" ]]; then jq "$@" "$filter" "$DJSON" > "$new"; else jq -n "$@" "$filter" > "$new"; fi
  DJSON_ERR=""
  if command -v dockerd >/dev/null 2>&1 && dockerd --help 2>&1 | grep -q -- '--validate'; then
    if ! DJSON_ERR="$(dockerd --validate --config-file "$new" 2>&1)"; then rm -f "$new"; return 1; fi
  fi
  DJSON_BAK=""
  if [[ -f "$DJSON" ]]; then
    DJSON_BAK="${DJSON}.appcrane-bak.$(date +%s)"
    [[ -e "$DJSON_BAK" ]] && DJSON_BAK="$DJSON_BAK.$$.$RANDOM"
    cp -p "$DJSON" "$DJSON_BAK"
  fi
  chmod 644 "$new"
  mv -f "$new" "$DJSON"
}

docker_reload_raw() {
  if have_systemd && systemctl is-active --quiet docker 2>/dev/null; then
    systemctl reload docker
  elif pidof dockerd >/dev/null 2>&1; then
    kill -HUP "$(pidof dockerd)"
  else
    return 2
  fi
}

# ---- host-gateway and Docker reloads ----
# A reload (SIGHUP) on some Docker releases empties host-gateway: dockerd logs
# "host-gateway-ips":[""] and every container created afterwards gets
# "invalid IP" for host.docker.internal (or `docker run --add-host` fails), so
# app containers lose AppCrane and their databases until dockerd restarts.
# Measured with a SIGHUP in privileged docker:<version>-dind, probing with
# --add-host probe.test:host-gateway before and after:
#   27.5.1 ok | 28.0.4, 28.5.2, 29.0.0, 29.1.3, 29.2.0 broken | 29.3.0, 29.4.0, 29.5.0, 29.10.1 ok
# Pinning "host-gateway-ips" in daemon.json does not survive the reload either
# (29.1.3: pinned before dockerd started, still "invalid IP" after a SIGHUP), so
# nothing short of a restart repairs it. So on 28.x and 29.0-29.2 the script
# does not reload at all (the change waits for the next Docker restart), and
# after every reload it does do, a throwaway container checks host-gateway and
# the run fails loudly when it is broken.
docker_reload_breaks_host_gateway() {
  local v major minor
  v="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
  [[ "$v" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
  major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"
  DOCKER_SERVER_VERSION="$v"
  (( major == 28 || (major == 29 && minor < 3) ))
}
hg_probe_image() {
  local img
  for img in busybox:latest alpine:latest; do
    docker image inspect "$img" >/dev/null 2>&1 && { echo "$img"; return 0; }
  done
  docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
    | grep -E '^([^/]+/)*(busybox|alpine|ubuntu|debian):' | grep -v ':<none>$' | head -n1 | grep .
}
# Sets HG_IP to what the probe container's /etc/hosts maps probe.test to: an
# address, "invalid" (the broken reload writes "invalid IP"), or "" when docker
# run itself fails (HG_ERR then holds docker's last line).
hg_resolve() {
  local out i
  HG_IP=""; HG_ERR=""
  for i in 1 2 3; do
    if out="$(docker run --rm --network bridge --add-host probe.test:host-gateway --entrypoint cat "$1" /etc/hosts 2>&1)"; then
      HG_IP="$(awk '$NF == "probe.test" { print ($1 == "probe.test" ? "" : $1); exit }' <<<"$out")"
      return 0
    fi
    HG_ERR="$(tail -n1 <<<"$out")"
    sleep 1
  done
}
docker_wait_up() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do docker info >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
verify_host_gateway() {
  local img ip
  if ! img="$(hg_probe_image)"; then
    warn "host-gateway: no local busybox/alpine/ubuntu/debian image to probe with — not verified after the Docker reload"
    return 0
  fi
  hg_resolve "$img"
  ip="$HG_IP"
  if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then log "host-gateway: a new container resolves host-gateway to $ip"; return 0; fi
  printf '\033[1;31mxx\033[0m  %s\n' "host-gateway: BROKEN after the Docker reload — a new container got '${ip:-no address}' for host-gateway${HG_ERR:+ ($HG_ERR)}. New app containers cannot reach AppCrane or their databases. Only restarting the Docker daemon repairs it, in a maintenance window (Docker 29.3.0 and later reload without this bug)" >&2
  return 1
}

# Every reload goes through here, so none can leave host-gateway broken unseen.
# 3: skipped because this Docker's reload would break host-gateway.
docker_reload() {
  if docker_reload_breaks_host_gateway; then
    warn "docker: not reloading Docker $DOCKER_SERVER_VERSION — a reload on 28.x and 29.0-29.2 empties host-gateway for every new container; the change applies at the next Docker restart"
    return 3
  fi
  docker_reload_raw || return $?
  docker_wait_up || true
  sleep 1
  verify_host_gateway || HH_FAILED+=("host-gateway")
  return 0
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
    _gv_rc=0
    djson_merge '.runtimes = ((.runtimes // {}) + {runsc: $r})' --argjson r "$GVISOR_RUNTIME" || _gv_rc=$?
    if (( _gv_rc != 0 )); then
      warn "gvisor: dockerd --validate refused the merged daemon.json — left as is: $DJSON_ERR"
    else
      _gv_bak="$DJSON_BAK"
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

# ---------- network: DOCKER-USER, INPUT baseline, boot unit ---------------
# Measured on a production box (Docker 29.1.3): FORWARD is policy DROP, then
# -j DOCKER-USER, -j DOCKER-FORWARD, then ufw's chains, so a ufw deny never
# sees a port Docker publishes, and DOCKER-USER was empty: two UDP ports
# published on 0.0.0.0 answered the internet with no ufw rule for them.
#
# DOCKER-USER (iptables and ip6tables) is owned by this section and rewritten
# as a whole, atomically (iptables-restore --noflush replaces that one chain):
#   1. replies to connections already allowed
#   2. containers to the instance metadata service: dropped
#   3. from the public interface (<EXT>, the default route's): APPCRANE-PUBLISH
#   4. from <EXT>: dropped
#   5. everything else (container to container, container egress): RETURN
# APPCRANE-PUBLISH is owned by the AppCrane server: one ACCEPT per host port it
# publishes on 0.0.0.0, matched on conntrack's original destination port
# (Docker's DNAT has already rewritten --dport in FORWARD). It is created here
# empty when missing and never flushed; the server refills it within seconds.
# Rule 4 is installed only when the server can keep that chain filled (it runs
# as root, or install-host-hardening.sh put in appcrane-publish-chain.sh and its
# sudoers rule) and the chain already accepts every port docker-proxy listens
# on for 0.0.0.0/::. Otherwise the skeleton goes in without it, or, while the
# interim hand-installed appcrane-docker-user unit is present, DOCKER-USER is
# left to that unit; both are recorded in the state file.
#
# INPUT: with ufw active, rules are only added (22, 80, 443/tcp unless a rule
# for the port exists; AppCrane's own port denied on <EXT>, prepended), never
# deleted or reordered. Without ufw, an APPCRANE-INPUT chain jumped from INPUT
# accepts loopback, replies, ICMP essentials, DHCP, the container bridges
# (apps reach AppCrane at host.docker.internal:<PORT> and their databases on
# the bridge gateway), 22/tcp, 80/tcp, 443/tcp+udp and APPCRANE_INPUT_ALLOW,
# drops AppCrane's own port on <EXT> (it stays reachable on every other
# interface: tailscale, VPN, private NICs), and only then is the INPUT
# policy set to DROP — unless a socket listens on a non-loopback address no
# rule covers, which would be cut off; then the policy is left as it was
# (APPCRANE_INPUT_FORCE=1 overrides). iptables-persistent / netfilter-persistent
# save are never used: they would also save Docker's own chains and restore
# stale copies of them at boot. appcrane-host-network.service re-applies only
# AppCrane's chains, after Docker starts and whenever it restarts.
#
# Knobs (environment, or the same NAME=value lines in /etc/appcrane/
# host-network.conf, which must be root-owned and writable by root only;
# Apply runs through sudo, which drops the environment):
#   APPCRANE_INPUT_ALLOW="8443/tcp 51820/udp"  more INPUT ports to accept
#   APPCRANE_INPUT_FORCE=1                     set DROP despite uncovered listeners
HN_STATE=/var/lib/appcrane/host-network.state
HN_CONF=/etc/appcrane/host-network.conf
HN_BOOT_SCRIPT=/usr/local/sbin/appcrane-host-network.sh
HN_UNIT=appcrane-host-network.service
HN_UNIT_FILE=/etc/systemd/system/appcrane-host-network.service
HN_INTERIM_UNIT=appcrane-docker-user.service
HN_INTERIM_UNIT_FILE=/etc/systemd/system/appcrane-docker-user.service
HN_INTERIM_SCRIPT=/usr/local/sbin/appcrane-docker-user.sh
HN_BASE_ALLOW="22/tcp 80/tcp 443/tcp 443/udp"
HN_PUB_HELPER=/usr/local/lib/appcrane/appcrane-publish-chain.sh
HN_PUB_SUDOERS=/etc/sudoers.d/appcrane-publish-chain

# The interface of the default route (lowest metric), IPv4 first, then IPv6.
hn_ext_if() {
  local dev
  dev="$(awk 'NR > 1 && $2 == "00000000" && $8 == "00000000" && $1 != "lo" { print $7, $1 }' /proc/net/route 2>/dev/null | sort -n | awk 'NR == 1 { print $2 }')"
  [[ -n "$dev" ]] || dev="$(awk '$1 == "00000000000000000000000000000000" && $2 == "00" && $10 != "lo" { print $6, $10 }' /proc/net/ipv6_route 2>/dev/null | sort | awk 'NR == 1 { print $2 }')"
  [[ "$dev" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || return 1
  printf '%s\n' "$dev"
}

hn_publish_chain() { "$1" -w -n -L APPCRANE-PUBLISH >/dev/null 2>&1 || "$1" -w -N APPCRANE-PUBLISH; }

# hn_docker_user <iptables|ip6tables> <metadata address> <ext> <drop: yes|no>
hn_docker_user() {
  local ipt="$1" imds="$2" ext="$3" drop=""
  [[ "$4" == yes ]] && drop="-A DOCKER-USER -i $ext -j DROP"
  hn_publish_chain "$ipt" || return 1
  "${ipt}-restore" -w --noflush <<EOF
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -i docker0 -d $imds -j DROP
-A DOCKER-USER -i br-+ -d $imds -j DROP
-A DOCKER-USER -i $ext -j APPCRANE-PUBLISH
$drop
-A DOCKER-USER -j RETURN
COMMIT
EOF
}

# hn_docker_user_mode <ipt> <imds> <ext> <docker_user: skeleton|interim> <drop>
hn_docker_user_mode() {
  if [[ "$4" == interim ]]; then hn_publish_chain "$1"; else hn_docker_user "$1" "$2" "$3" "$5"; fi
}

# AppCrane's own port: 1024-65535 and none of the base allow list, because it
# comes from .env, which the app user can write, and root DROPs it.
hn_app_port_ok() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 >= 1024 && $1 <= 65535 )) && [[ " $HN_BASE_ALLOW " != *" $1/tcp "* ]]
}

# hn_input_chain <iptables|ip6tables> <allow list> <app port> <ext>
hn_input_chain() {
  local ipt="$1" allow="$2" appport="$3" ext="$4" p rules
  if [[ "$ipt" == iptables ]]; then
    rules="-A APPCRANE-INPUT -p icmp --icmp-type echo-request -j ACCEPT
-A APPCRANE-INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
-A APPCRANE-INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
-A APPCRANE-INPUT -p icmp --icmp-type parameter-problem -j ACCEPT
-A APPCRANE-INPUT -p udp --sport 67 --dport 68 -j ACCEPT"
  else
    rules=""
    for p in 1 2 3 4 128 133 134 135 136; do rules+="-A APPCRANE-INPUT -p ipv6-icmp --icmpv6-type $p -j ACCEPT"$'\n'; done
    rules+="-A APPCRANE-INPUT -s fe80::/10 -p udp --sport 547 --dport 546 -j ACCEPT"
  fi
  for p in $allow; do rules+=$'\n'"-A APPCRANE-INPUT -p ${p#*/} --dport ${p%/*} -j ACCEPT"; done
  "${ipt}-restore" -w --noflush <<EOF || return 1
*filter
:APPCRANE-INPUT - [0:0]
-A APPCRANE-INPUT -i lo -j ACCEPT
-A APPCRANE-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A APPCRANE-INPUT -i docker0 -j ACCEPT
-A APPCRANE-INPUT -i br-+ -j ACCEPT
-A APPCRANE-INPUT -i $ext -p tcp --dport $appport -j DROP
-A APPCRANE-INPUT -p tcp --dport $appport -j ACCEPT
$rules
-A APPCRANE-INPUT -j RETURN
COMMIT
EOF
  "$ipt" -w -C INPUT -j APPCRANE-INPUT 2>/dev/null || "$ipt" -w -I INPUT 1 -j APPCRANE-INPUT
}

hn_input_chain_remove() {
  local ipt="$1"
  "$ipt" -w -n -L APPCRANE-INPUT >/dev/null 2>&1 || return 0
  while "$ipt" -w -D INPUT -j APPCRANE-INPUT 2>/dev/null; do :; done
  "$ipt" -w -F APPCRANE-INPUT && "$ipt" -w -X APPCRANE-INPUT
}

hn_have6() { command -v ip6tables >/dev/null 2>&1 && ip6tables -w -n -L INPUT >/dev/null 2>&1; }

hn_state_get() { [[ -f "$HN_STATE" ]] && sed -n "s/^$1=//p" "$HN_STATE" | tail -n1; }

# Re-applies what the last host-hardening run decided. Run by
# appcrane-host-network.service; it never widens or narrows anything itself.
hn_boot() {
  local ext="" i mode allow appport du drop
  if [[ ! -f "$HN_STATE" ]]; then warn "network: $HN_STATE missing — run scripts/host-hardening.sh"; return 1; fi
  mode="$(hn_state_get input_mode)"; allow="$(hn_state_get allow)"; appport="$(hn_state_get app_port)"
  du="$(hn_state_get docker_user)"; drop="$(hn_state_get publish_drop)"
  if ! hn_app_port_ok "$appport"; then warn "network: app_port '$appport' in $HN_STATE is not usable — INPUT not applied"; mode=none; fi
  for i in $(seq 1 30); do ext="$(hn_ext_if)" && break; sleep 1; done
  if [[ -z "$ext" ]]; then warn "network: no default route after 30 s — DOCKER-USER not applied"; return 1; fi
  hn_docker_user_mode iptables 169.254.169.254 "$ext" "$du" "$drop" || return 1
  if hn_have6; then hn_docker_user_mode ip6tables fd00:ec2::254 "$ext" "$du" "$drop" || return 1; fi
  case "$mode" in
    appcrane-input|refused)
      hn_input_chain iptables "$allow" "$appport" "$ext" || return 1
      if hn_have6; then hn_input_chain ip6tables "$allow" "$appport" "$ext" || return 1; fi
      if [[ "$(hn_state_get input_policy)" == DROP ]]; then
        iptables -w -P INPUT DROP || return 1
        if hn_have6; then ip6tables -w -P INPUT DROP || return 1; fi
      fi ;;
  esac
  log "network: DOCKER-USER (${du:-skeleton}, public interface $ext, DROP ${drop:-no}) and INPUT ($mode) re-applied"
}

# Listening sockets on non-loopback addresses that no INPUT rule here accepts,
# one "port/proto@address(process)" per line. Covered: loopback, addresses of
# docker0/br-*, docker-proxy (published ports go through DOCKER-USER, not
# INPUT), AppCrane's own TCP port (deliberately dropped; Caddy reaches it on
# loopback), DHCP client ports and the allow list.
hn_uncovered() {
  local allow=" $1 68/udp 546/udp " appport="$2" listeners="$3" bridges proto local proc port addr iface
  bridges=" $(ip -o addr show 2>/dev/null | awk '$2 == "docker0" || $2 ~ /^br-/ { split($4, a, "/"); printf "%s ", a[1] }') "
  while read -r proto _ _ _ local _ proc; do
    port="${local##*:}"; addr="${local%:*}"; addr="${addr#[}"; addr="${addr%]}"; iface=""
    if [[ "$addr" == *%* ]]; then iface="${addr#*%}"; addr="${addr%%\%*}"; fi
    case "$addr" in 127.*|::1|::ffff:127.*) continue ;; esac
    [[ "$iface" == lo || "$iface" == docker0 || "$iface" == br-* ]] && continue
    [[ "$bridges" == *" $addr "* ]] && continue
    [[ "$proto" == tcp && "$port" == "$appport" ]] && continue
    [[ "$proc" == *'"docker-proxy"'* ]] && continue
    [[ "$allow" == *" $port/$proto "* ]] && continue
    proc="$(sed -n 's/^users:(("\([^"]*\)".*/\1/p' <<<"$proc")"
    printf '%s/%s@%s%s\n' "$port" "$proto" "$addr" "${proc:+($proc)}"
  done <<<"$listeners" | sort -u | tr -cd 'A-Za-z0-9._:/@%()*\n-'
}

# Ports docker-proxy listens on for 0.0.0.0, :: or * (one "proto:port" per
# line) that APPCRANE-PUBLISH does not accept yet, in that family's table; a
# dual-stack * socket is checked in both.
hn_unsynced_publishes() {
  local listeners="$1" have6="$2" proto local proc port addr ipt ipts
  while read -r proto _ _ _ local _ proc; do
    [[ "$proc" == *'"docker-proxy"'* ]] || continue
    port="${local##*:}"; addr="${local%:*}"
    case "$addr" in
      0.0.0.0) ipts=iptables ;;
      '[::]') [[ "$have6" == yes ]] || continue; ipts=ip6tables ;;
      '*') ipts=iptables; [[ "$have6" == yes ]] && ipts+=" ip6tables" ;;
      *) continue ;;
    esac
    [[ "$proto" == tcp || "$proto" == udp ]] || continue
    for ipt in $ipts; do
      "$ipt" -w -S APPCRANE-PUBLISH 2>/dev/null | grep -Eq -- "^-A APPCRANE-PUBLISH -p $proto( .*)? --ctorigdstport $port( .*)? -j ACCEPT$" \
        || { printf '%s:%s\n' "$proto" "$port"; break; }
    done
  done <<<"$listeners" | sort -u
}

# The user AppCrane runs as: User= of appcrane.service when systemd has it
# (empty means root), else the owner of the repo's .env (install.sh chowns it
# to the run user).
hn_run_user() {
  local u
  if have_systemd && [[ "$(systemctl show -p LoadState --value appcrane 2>/dev/null)" == loaded ]]; then
    u="$(systemctl show -p User --value appcrane)"
    printf '%s\n' "${u:-root}"
    return 0
  fi
  stat -c %U "$REPO_DIR/.env" 2>/dev/null || stat -c %U "$REPO_DIR"
}

# Whether AppCrane can keep APPCRANE-PUBLISH filled: as root, or through the
# helper install-host-hardening.sh installs. Prints why not.
hn_publish_maintainer() {
  local user="$1" st
  [[ "$user" == root || "$user" == 0 ]] && return 0
  if [[ ! "$user" =~ ^[a-z_][a-z0-9_-]*$ ]]; then echo "cannot tell which user AppCrane runs as ($user)"; return 1; fi
  if [[ ! -f "$HN_PUB_HELPER" ]]; then echo "AppCrane runs as $user and $HN_PUB_HELPER is not installed (run sudo bash $REPO_DIR/scripts/install-host-hardening.sh)"; return 1; fi
  st="$(stat -c '%u %a' "$HN_PUB_HELPER")"
  if [[ "${st%% *}" != 0 ]] || (( 8#${st##* } & 8#022 )); then echo "$HN_PUB_HELPER is not root-owned or is writable by others"; return 1; fi
  if [[ ! -f "$HN_PUB_SUDOERS" ]] || ! command -v visudo >/dev/null 2>&1 || ! visudo -cf "$HN_PUB_SUDOERS" >/dev/null; then
    echo "$HN_PUB_SUDOERS is missing or does not validate (run sudo bash $REPO_DIR/scripts/install-host-hardening.sh)"; return 1
  fi
  if ! sudo -n -l -U "$user" "$HN_PUB_HELPER" >/dev/null; then echo "sudoers does not let $user run $HN_PUB_HELPER"; return 1; fi
}

hn_conf_get() {
  local name="$1" st
  [[ -f "$HN_CONF" ]] || return 0
  st="$(stat -c '%u %a' "$HN_CONF")"
  if [[ "${st%% *}" != 0 ]] || (( 8#${st##* } & 8#022 )); then
    warn "network: $HN_CONF is not root-owned or is writable by others — ignored"
    return 0
  fi
  sed -n "s/^$name=//p" "$HN_CONF" | tail -n1 | tr -d '"'"'"''
}

hn_write_state() {
  mkdir -p "$(dirname "$HN_STATE")"
  local tmp; tmp="$(mktemp "$(dirname "$HN_STATE")/.host-network.XXXXXX")"
  printf '%s\n' "# Written by AppCrane scripts/host-hardening.sh; read by Settings > Host limits and $HN_BOOT_SCRIPT" "applied_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$@" > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$HN_STATE"
}

# A failed run keeps the last decision, so the boot unit goes on applying it.
hn_fail() {
  local keep=()
  [[ -f "$HN_STATE" ]] && mapfile -t keep < <(grep -E '^(input_mode|input_policy|allow|app_port|docker_user|publish_drop|publish_drop_reason|run_user)=' "$HN_STATE")
  hn_write_state ${keep[@]+"${keep[@]}"} "result=failed" "error=$1" "ext=${2:-}"
}

hn_policy() { "$1" -w -S INPUT 2>/dev/null | awk '$1 == "-P" { print $3; exit }'; }

# The persisted re-apply script: this section's own functions, so boot and
# Apply cannot drift apart.
hn_boot_script() {
  printf '%s\n' '#!/usr/bin/env bash' \
    '# Written by AppCrane scripts/host-hardening.sh — re-applies AppCrane'"'"'s chains only' \
    '# (DOCKER-USER skeleton, APPCRANE-PUBLISH created empty if missing, APPCRANE-INPUT).' \
    'set -uo pipefail'
  declare -p HN_STATE HN_BASE_ALLOW | sed 's/^declare -- //'
  declare -f log warn hn_ext_if hn_publish_chain hn_docker_user hn_docker_user_mode hn_app_port_ok hn_input_chain hn_have6 hn_state_get hn_boot
  printf '%s\n' 'hn_boot'
}

HN_UNIT_CONF="# Written by AppCrane scripts/host-hardening.sh
[Unit]
Description=AppCrane host network policy (DOCKER-USER, APPCRANE-INPUT)
After=docker.service network-online.target
Wants=network-online.target
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$HN_BOOT_SCRIPT

[Install]
WantedBy=docker.service multi-user.target"

hn_main() {
  local ext appport allow="" force p bad="" fam="IPv4" mode policy uncovered="" interim=no added n
  local listeners="" ss_ok=yes runuser drop=yes why="" unsynced du=skeleton have6=no
  if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-restore >/dev/null 2>&1; then
    log "network: iptables not installed — skipped"
    return 0
  fi
  if ! ext="$(hn_ext_if)"; then
    warn "network: no default route, so the public interface is unknown — DOCKER-USER and INPUT left as they are"
    hn_fail "no default route: public interface unknown"
    return 1
  fi
  appport="$(sed -n 's/^PORT=//p' "$REPO_DIR/.env" 2>/dev/null | tail -n1 | tr -d '"'"'"'')"
  appport="${appport:-5001}"
  if ! hn_app_port_ok "$appport"; then
    warn "network: PORT=$appport in $REPO_DIR/.env is below 1024 or a port the baseline accepts ($HN_BASE_ALLOW); AppCrane's port is dropped on $ext, so DOCKER-USER and INPUT are left as they are"
    hn_fail "app port $appport refused: below 1024 or in $HN_BASE_ALLOW" "$ext"
    return 1
  fi

  for p in ${APPCRANE_INPUT_ALLOW-$(hn_conf_get APPCRANE_INPUT_ALLOW)}; do
    n="${p%/*}"
    if [[ ! "$p" =~ ^[1-9][0-9]{0,4}/(tcp|udp)$ ]] || (( n > 65535 )); then bad+=" $p"
    elif [[ "$n" == "$appport" ]]; then warn "network: APPCRANE_INPUT_ALLOW names AppCrane's own port $p — never accepted from outside; ignored"
    else allow+=" $p"; fi
  done
  [[ -n "$bad" ]] && warn "network: APPCRANE_INPUT_ALLOW entries ignored (want port/tcp or port/udp):$bad"
  allow="$(tr ' ' '\n' <<<"$HN_BASE_ALLOW$allow" | awk 'NF && !seen[$0]++' | paste -sd' ' -)"
  force="${APPCRANE_INPUT_FORCE-$(hn_conf_get APPCRANE_INPUT_FORCE)}"
  hn_have6 && have6=yes

  if ! command -v ss >/dev/null 2>&1; then
    ss_ok=ss-not-installed
  elif ! listeners="$(ss -H -ltnup)"; then
    ss_ok=ss-failed
    warn "network: ss failed, so the listening sockets cannot be checked"
  fi

  # The DROP on <EXT> only when the server can keep APPCRANE-PUBLISH filled
  # and already has: otherwise every published port would go dark.
  runuser="$(hn_run_user)"
  if ! why="$(hn_publish_maintainer "$runuser")"; then
    drop=no
    warn "network: DOCKER-USER installed WITHOUT the DROP on $ext: $why. Published ports stay open to the internet until that is fixed and Apply runs again"
  elif [[ "$ss_ok" != yes ]]; then
    drop=no; why="cannot check which ports docker-proxy listens on ($ss_ok)"
    warn "network: DOCKER-USER installed WITHOUT the DROP on $ext: $why"
  else
    unsynced="$(hn_unsynced_publishes "$listeners" "$have6" | paste -sd' ' -)"
    if [[ -n "$unsynced" ]]; then
      drop=no; why="AppCrane has not synced published ports yet: APPCRANE-PUBLISH lacks $unsynced"
      warn "network: AppCrane has not synced published ports yet; Apply again after the server is on v2.145.0 (APPCRANE-PUBLISH lacks $unsynced, which docker-proxy listens on). DOCKER-USER installed WITHOUT the DROP on $ext"
    fi
  fi
  if [[ "$drop" == no ]] && [[ -e "$HN_INTERIM_UNIT_FILE" || -e "$HN_INTERIM_SCRIPT" ]]; then
    du=interim
    warn "network: the interim $HN_INTERIM_UNIT_FILE is kept and DOCKER-USER is left to it (only APPCRANE-PUBLISH is created), so its per-port allows and DROP stay in force"
  fi

  if ! hn_docker_user_mode iptables 169.254.169.254 "$ext" "$du" "$drop"; then
    warn "network: could not write DOCKER-USER (iptables)"
    hn_fail "iptables refused the DOCKER-USER chain" "$ext"
    return 1
  fi
  if [[ "$have6" == yes ]]; then
    fam="IPv4+IPv6"
    if ! hn_docker_user_mode ip6tables fd00:ec2::254 "$ext" "$du" "$drop"; then
      warn "network: could not write DOCKER-USER (ip6tables)"
      hn_fail "ip6tables refused the DOCKER-USER chain" "$ext"
      return 1
    fi
  else
    log "network: ip6tables not available — IPv6 chains skipped"
  fi
  if [[ "$du" == interim ]]; then
    log "network: APPCRANE-PUBLISH ($fam) present; DOCKER-USER left to the interim unit"
  elif [[ "$drop" == yes ]]; then
    log "network: DOCKER-USER ($fam) set: replies, metadata service blocked for containers, public interface $ext limited to APPCRANE-PUBLISH, then DROP"
  else
    log "network: DOCKER-USER ($fam) set: replies, metadata service blocked for containers, public interface $ext through APPCRANE-PUBLISH, no DROP"
  fi

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -n1 | grep -qx 'Status: active'; then
    mode=ufw
    hn_input_chain_remove iptables
    hn_have6 && hn_input_chain_remove ip6tables
    added="$(ufw show added 2>/dev/null | grep '^ufw ' || true)"
    for p in 22/tcp 80/tcp 443/tcp; do
      n="${p%/*}"
      if grep -Eq "(^| )(port )?$n(/(tcp|udp))?( |$)" <<<"$added" || { [[ "$n" == 22 ]] && grep -q 'OpenSSH' <<<"$added"; }; then
        log "network: ufw already has a rule for port $n — left as is"
      else
        ufw allow "$p" >/dev/null && log "network: ufw allow $p added"
      fi
    done
    if ufw prepend deny in on "$ext" to any port "$appport" >/dev/null 2>&1 \
      || ufw deny in on "$ext" to any port "$appport" >/dev/null; then
      log "network: ufw denies AppCrane's port $appport on $ext (first rule; existing rules untouched)"
    else
      warn "network: ufw would not add the deny for port $appport on $ext"
    fi
    policy="$(hn_policy iptables)"
  else
    if ! hn_input_chain iptables "$allow" "$appport" "$ext" || { hn_have6 && ! hn_input_chain ip6tables "$allow" "$appport" "$ext"; }; then
      warn "network: could not write APPCRANE-INPUT"
      hn_fail "iptables refused the APPCRANE-INPUT chain" "$ext"
      return 1
    fi
    if [[ "$ss_ok" != yes ]]; then
      uncovered="$ss_ok"
    else
      uncovered="$(hn_uncovered "$allow" "$appport" "$listeners" | paste -sd' ' -)"
    fi
    if [[ -n "$uncovered" && "$force" != 1 ]]; then
      mode=refused
      warn "network: INPUT policy NOT set to DROP — these listen on non-loopback addresses with no accept rule, and would be cut off: $uncovered"
      warn "network: add them to APPCRANE_INPUT_ALLOW in $HN_CONF (e.g. APPCRANE_INPUT_ALLOW=\"8443/tcp\"), or set APPCRANE_INPUT_FORCE=1 there, and apply again"
    else
      mode=appcrane-input
      [[ -n "$uncovered" ]] && warn "network: APPCRANE_INPUT_FORCE=1 — setting DROP although these listen uncovered: $uncovered"
      iptables -w -P INPUT DROP
      hn_have6 && ip6tables -w -P INPUT DROP
      log "network: INPUT policy DROP; accepted: loopback, replies, ICMP, DHCP, container bridges, $allow; AppCrane's port $appport on every interface but $ext"
    fi
    policy="$(hn_policy iptables)"
  fi

  hn_write_state "result=$([[ $mode == refused ]] && echo refused || echo ok)" "ext=$ext" "families=$fam" \
    "input_mode=$mode" "input_policy=$policy" "allow=$allow" "app_port=$appport" "uncovered=$uncovered" \
    "run_user=$runuser" "docker_user=$du" "publish_drop=$drop" "publish_drop_reason=$why"

  # Persistence: the boot script and its unit, both root-owned.
  log "network: $HN_BOOT_SCRIPT $(write_if_changed "$HN_BOOT_SCRIPT" "$(hn_boot_script)")"
  chown root:root "$HN_BOOT_SCRIPT"; chmod 0755 "$HN_BOOT_SCRIPT"
  log "network: $HN_UNIT_FILE $(write_if_changed "$HN_UNIT_FILE" "$HN_UNIT_CONF")"
  chmod 0644 "$HN_UNIT_FILE"
  if have_systemd; then
    systemctl daemon-reload
    systemctl enable "$HN_UNIT" >/dev/null 2>&1 || warn "network: systemctl enable $HN_UNIT failed"
    systemctl restart "$HN_UNIT" || warn "network: $HN_UNIT failed to start — see journalctl -u $HN_UNIT"
  else
    warn "network: no running systemd — $HN_UNIT is written but not enabled; the chains last until reboot"
  fi

  # The interim hand-installed policy: removed once the unit replacing it is
  # active (without systemd nothing can be running it).
  if [[ -e "$HN_INTERIM_UNIT_FILE" || -e "$HN_INTERIM_SCRIPT" ]]; then
    if [[ "$du" == interim ]]; then
      :
    elif ! have_systemd || systemctl is-active --quiet "$HN_UNIT"; then
      if have_systemd; then
        systemctl disable "$HN_INTERIM_UNIT" >/dev/null 2>&1 || true
        systemctl stop "$HN_INTERIM_UNIT" >/dev/null 2>&1 || true
      fi
      rm -f "$HN_INTERIM_UNIT_FILE" "$HN_INTERIM_SCRIPT"
      if have_systemd; then
        systemctl daemon-reload
        systemctl restart "$HN_UNIT" || warn "network: $HN_UNIT failed to re-apply after the interim unit was removed"
      else
        hn_docker_user iptables 169.254.169.254 "$ext" "$drop"
        hn_have6 && hn_docker_user ip6tables fd00:ec2::254 "$ext" "$drop"
      fi
      interim=yes
      log "network: removed the interim $HN_INTERIM_UNIT_FILE and $HN_INTERIM_SCRIPT; its per-port allows are not carried over — APPCRANE-PUBLISH starts from what is in it (empty on first run) and AppCrane refills it with the ports it publishes within seconds"
    else
      warn "network: $HN_UNIT is not active — the interim $HN_INTERIM_UNIT_FILE is kept"
    fi
    echo "interim_removed=$interim" >> "$HN_STATE"
  fi
  [[ "$mode" == refused ]] && return 1
  return 0
}

hn_main || HH_FAILED+=("network")

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

# ---------- Caddy restart policy -------------------------------------------
# The packaged caddy.service has Restart=no and systemd's default start limit
# (5 starts in 10 s). One burst of restarts while an app was deleted hit that
# limit and left every site on the box down, with nothing starting Caddy
# again. This drop-in restarts Caddy when it dies and never gives up. Applied
# with daemon-reload only: Restart= and the start limit are read from the unit
# when the next start is due, so the running Caddy is not touched. An operator
# file that differs is backed up before it is replaced; a later-sorting
# drop-in (e.g. 60-local.conf) still overrides it.
CADDY_DROPIN=/etc/systemd/system/caddy.service.d/appcrane.conf
CADDY_DROPIN_CONF="# Written by AppCrane scripts/host-hardening.sh
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=2"
if [[ -f "$CADDY_DROPIN" ]] && [[ "$(cat "$CADDY_DROPIN")" != "$CADDY_DROPIN_CONF" ]]; then
  mkdir -p /var/backups
  cp -p "$CADDY_DROPIN" "/var/backups/caddy-dropin.appcrane-bak.$(date +%s)"
fi
_caddy_dropin_state="$(write_if_changed "$CADDY_DROPIN" "$CADDY_DROPIN_CONF")"
chmod 0644 "$CADDY_DROPIN"
log "caddy restart policy: $CADDY_DROPIN $_caddy_dropin_state"
if have_systemd; then
  [[ "$_caddy_dropin_state" == changed ]] && { systemctl daemon-reload || warn "daemon-reload failed — the Caddy restart policy applies at next boot"; }
  # A Caddy already given up on (start limit hit) stays down until reset.
  if [[ "$(systemctl is-active caddy 2>/dev/null || true)" == failed ]]; then
    systemctl reset-failed caddy || true
    systemctl start caddy && log "caddy restart policy: started a failed Caddy" || warn "caddy restart policy: Caddy is failed and would not start — check 'journalctl -u caddy'"
  fi
else
  warn "caddy restart policy: no running systemd — applies when systemd next loads units"
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

if (( ${#HH_FAILED[@]} )); then
  warn "Host hardening done, with failed sections: ${HH_FAILED[*]}"
  exit 3
fi
log "Host hardening done"
