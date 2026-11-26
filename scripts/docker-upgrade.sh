#!/usr/bin/env bash
# Move this host's Docker to Docker CE >= 29.3 from Docker's official apt
# repository, replacing Ubuntu's docker.io (29.1.3 on 24.04 and 25.10, which has
# the reload bug described in scripts/lib/docker-ce.sh) in one apt transaction.
#
#   sudo bash scripts/docker-upgrade.sh            # newest docker-ce >= 29.3
#   sudo DOCKER_VERSION=29.10.1 bash scripts/docker-upgrade.sh
#   bash scripts/docker-upgrade.sh --dry-run       # print the plan, change nothing
#
# Docker restarts during the upgrade, so EVERY container stops and starts again:
# run it in a maintenance window. /etc/docker/daemon.json is backed up first and
# kept. Units that systemd stops together with docker.service (appcrane.service
# has Requires=docker.service) are started again, and AppCrane must answer
# /api/info afterwards. If the new dockerd does not come up, reports a version
# below 29.3, lost the runsc runtime or fails the host-gateway probe, the
# previous packages are reinstalled, daemon.json restored, and the script exits
# non-zero. A failure it cannot roll back prints the commands that would.
# Idempotent: on Docker CE >= 29.3 with no docker.io left it changes nothing.
# Ubuntu only.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/docker-ce.sh
. "$HERE/lib/docker-ce.sh"

DJSON="${DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"
MIN_FREE_MB="${DOCKER_UPGRADE_MIN_FREE_MB:-1024}"
WAIT_S="${DOCKER_UPGRADE_WAIT_S:-300}"
DOCKERD_WAIT_S="${DOCKER_UPGRADE_DOCKERD_WAIT_S:-90}"   # for the new dockerd; a rollback always waits 90 s
CRANE_WAIT_S="${APPCRANE_HEALTH_WAIT_S:-180}"

log()  { printf '==> %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }
die()  { printf 'xx  %s\n' "$*" >&2; exit "${2:-1}"; }

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/docker-upgrade.sh [--dry-run]

Replaces docker.io with Docker CE (>= 29.3) from download.docker.com.
Docker restarts, so every container restarts: use a maintenance window.

  --dry-run          print the plan and change nothing
  -h, --help         this help

Environment:
  DOCKER_VERSION=X.Y.Z   install this docker-ce version (must be >= 29.3)
EOF
}

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $arg" 2 ;;
  esac
done

WANT="${DOCKER_VERSION:-}"
if [[ -n "$WANT" ]]; then
  [[ "$WANT" =~ ^([0-9]+:)?[0-9]+\.[0-9]+\.[0-9]+([-~+][A-Za-z0-9.~+-]*)?$ ]] \
    || die "DOCKER_VERSION '$WANT' is not a version (expected e.g. 29.10.1)" 2
  dce_ver_ge "$WANT" "$DCE_MIN_FIXED" \
    || die "DOCKER_VERSION $WANT is below $DCE_MIN_FIXED: a dockerd reload on it breaks host.docker.internal" 2
fi

(( DRY_RUN )) || [[ $EUID -eq 0 ]] || die "run as root: sudo bash $0" 2

# ---------- preflight ----------
dce_is_ubuntu || die "this script supports Ubuntu only (ID=$(dce_os_field ID) in $DCE_OS_RELEASE)"
CODENAME="$(dce_codename)"
[[ -n "$CODENAME" ]] || die "no Ubuntu codename in $DCE_OS_RELEASE"
dce_codename_supported "$CODENAME" \
  || die "Docker's repository has no Ubuntu '$CODENAME' ($DCE_REPO_URL/dists/$CODENAME/Release not found). Stay on docker.io until Docker publishes it, and do not reload dockerd (restart it instead)."

FREE_MB="$(df -Pm /var | awk 'NR==2 {print $4}')"
[[ "$FREE_MB" =~ ^[0-9]+$ ]] || die "could not read free space on /var"
(( FREE_MB >= MIN_FREE_MB )) || die "only ${FREE_MB} MB free on /var; need ${MIN_FREE_MB} MB for the packages"

HAVE="$(dce_installed_docker_pkgs)"
SERVER_VER="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
RUNNING_NAMES="$(docker ps --format '{{.Names}}' 2>/dev/null || true)"
RUNNING_BEFORE="$(grep -c . <<<"$RUNNING_NAMES" || true)"
RUNTIMES_BEFORE="$(docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}' 2>/dev/null || true)"
HAD_RUNSC=0; [[ " $RUNTIMES_BEFORE " == *" runsc "* ]] && HAD_RUNSC=1
if [[ -d /run/systemd/system ]]; then INIT=systemd; else INIT=none; fi

# Units systemd stops with docker.service and does not start again with it
# (Requires=, BindsTo=, PartOf=): the active reverse dependencies, without targets.
DEPENDENTS=()
if [[ "$INIT" == systemd ]]; then
  while IFS= read -r u; do
    [[ -n "$u" ]] && systemctl is-active --quiet "$u" && DEPENDENTS+=("$u")
  done < <(systemctl list-dependencies --reverse --plain --all --no-legend docker.service \
             | awk 'NR > 1 { print $1 }' | grep -vE '\.target$|^docker\.(service|socket)$' | sort -u)
fi

# AppCrane's own unauthenticated endpoint (the self-update health gate uses it).
crane_env_file() {
  local wd
  [[ -n "${APPCRANE_ENV_FILE:-}" ]] && { echo "$APPCRANE_ENV_FILE"; return; }
  if [[ "$INIT" == systemd ]]; then
    wd="$(systemctl show -p WorkingDirectory --value appcrane.service 2>/dev/null || true)"
    [[ -n "$wd" && -f "$wd/.env" ]] && { echo "$wd/.env"; return; }
  fi
  echo "$HERE/../.env"
}
env_value() { [[ -f "$2" ]] && sed -n "s/^$1=//p" "$2" | tail -n1 | tr -d "\"' \r"; }
CRANE_ENV="$(crane_env_file)"
CRANE_PORT="$(env_value PORT "$CRANE_ENV" || true)"
[[ "$CRANE_PORT" =~ ^[0-9]{1,5}$ ]] || CRANE_PORT=5001
CRANE_HOST="$(env_value HOST "$CRANE_ENV" || true)"
[[ "$CRANE_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$CRANE_HOST" != 0.0.0.0 ]] || CRANE_HOST=127.0.0.1
CRANE_URL="http://$CRANE_HOST:$CRANE_PORT/api/info"
crane_up() { curl -fsS -o /dev/null --max-time 5 "$CRANE_URL" 2>/dev/null; }
CRANE_BEFORE=0; crane_up && CRANE_BEFORE=1

ce_now="$(grep '^docker-ce=' <<<"$HAVE" | cut -d= -f2- || true)"
if [[ -n "$ce_now" ]] && ! grep -q '^docker\.io=' <<<"$HAVE" \
   && [[ -n "$SERVER_VER" ]] && dce_ver_ge "$SERVER_VER" "$DCE_MIN_FIXED" \
   && { [[ -z "$WANT" ]] || [[ "$ce_now" == "$WANT" || "$(dce_upstream "$ce_now")" == "$WANT" ]]; }; then
  log "Already on Docker CE $SERVER_VER ($ce_now) from Docker's repository, no docker.io installed. Nothing to do."
  exit 0
fi

TARGET=""
if [[ -f "$DCE_SOURCES" ]]; then
  TARGET="$(apt-cache madison docker-ce 2>/dev/null | dce_pick_version "$WANT")"
  [[ -n "$TARGET" ]] || die "no docker-ce ${WANT:-at or above $DCE_MIN_FIXED} in Docker's repository for '$CODENAME' (apt-cache madison docker-ce)"
fi

# ---------- plan ----------
echo "Docker upgrade plan"
echo "  host:           Ubuntu $CODENAME ($(dpkg --print-architecture)), ${FREE_MB} MB free on /var, init: $INIT"
echo "  dockerd now:    ${SERVER_VER:-not running}"
echo "  packages now:   $(paste -sd' ' - <<<"${HAVE:-none}")"
target_note="newest ${WANT:-at or above $DCE_MIN_FIXED} (Docker's repository is not configured yet; chosen after adding it)"
echo "  target:         docker-ce ${TARGET:-$target_note}"
echo "  repository:     $DCE_SOURCES (key $DCE_KEYRING)"
echo "  daemon.json:    $( [[ -f "$DJSON" ]] && echo "$DJSON backed up and kept" || echo "none" )"
echo "  runsc runtime:  $( (( HAD_RUNSC )) && echo "registered, must still be after" || echo "not registered" )"
echo "  running now:    $RUNNING_BEFORE container(s)"
[[ -n "$RUNNING_NAMES" ]] && sed 's/^/                    /' <<<"$RUNNING_NAMES"
if [[ -n "$TARGET" ]]; then
  echo "  apt-get install: ${DCE_APT_INSTALL[*]:2} $(dce_install_args "$TARGET" "$HAVE" | paste -sd' ' -)"
fi
mapfile -t _plan < <(dce_install_args "${TARGET:-new}" "$HAVE")
adds=(); removes=()
for a in "${_plan[@]}"; do
  if [[ "$a" == *- ]]; then removes+=("${a%-}"); else grep -q "^${a%%=*}=" <<<"$HAVE" || adds+=("${a%%=*}"); fi
done
echo "  adds:           ${adds[*]:-nothing}"
echo "  removes:        ${removes[*]:-nothing}"
if grep -qE '^docker-buildx(-plugin)?=' <<<"$HAVE"; then
  echo "  BuildKit:       unchanged, on (buildx was installed before and is kept)"
else
  echo "  BuildKit:       unchanged, off (buildx was not installed before; Recommends are not installed)"
fi
if grep -qE '^docker-compose-(v2|plugin)=' <<<"$HAVE"; then echo "  compose:        kept"; else echo "  compose:        not installed (it was not before)"; fi
echo "  started again:  ${DEPENDENTS[*]:-no units (none depend on docker.service)}"
if (( CRANE_BEFORE )); then
  echo "  AppCrane:       answering on $CRANE_URL; must answer again within ${CRANE_WAIT_S}s"
else
  echo "  AppCrane:       not answering on $CRANE_URL now; not checked after"
fi
echo "  Docker restarts: every running container stops and starts again."
if (( DRY_RUN )); then
  echo "Dry run: nothing changed."
  exit 0
fi

LOCK=/run/lock/appcrane-docker-upgrade.lock
[[ -d /run/lock ]] || LOCK=/tmp/appcrane-docker-upgrade.lock
exec 9>"$LOCK"
flock -n 9 || die "another docker-upgrade.sh is running"

export DEBIAN_FRONTEND=noninteractive
STAMP="$(date +%Y%m%d%H%M%S)"
DJSON_BAK=""
if [[ -f "$DJSON" ]]; then
  DJSON_BAK="${DJSON}.appcrane-upgrade-bak.$STAMP"
  cp -p "$DJSON" "$DJSON_BAK"
  log "daemon.json backed up to $DJSON_BAK"
fi

if [[ -z "$TARGET" || ! -f "$DCE_KEYRING" ]]; then
  log "Adding Docker's apt repository for $CODENAME"
  dce_add_repo "$CODENAME"
else
  apt-get update -y
fi
TARGET="$(apt-cache madison docker-ce | dce_pick_version "$WANT")"
[[ -n "$TARGET" ]] || die "no docker-ce ${WANT:-at or above $DCE_MIN_FIXED} in Docker's repository for '$CODENAME'"
mapfile -t INSTALL_ARGS < <(dce_install_args "$TARGET" "$HAVE")

stop_docker() {
  local pid _
  if [[ "$INIT" == systemd ]]; then
    # Stopped before apt swaps the unit files: a docker.socket still listening
    # while docker.io's unit is replaced by docker-ce's keeps no socket fd, and
    # the new docker.service then fails "no sockets found via socket
    # activation" until it hits its start limit (measured on 24.04).
    systemctl stop docker.socket docker.service || true
    return 0
  fi
  pid="$(pidof dockerd || true)"
  [[ -n "$pid" ]] || return 0
  kill "$pid"
  for _ in $(seq 1 60); do pidof dockerd >/dev/null || return 0; sleep 1; done
  kill -9 "$pid" 2>/dev/null || true
}
start_dockerd() {
  if [[ "$INIT" == systemd ]]; then
    systemctl daemon-reload || true
    systemctl reset-failed docker.socket docker.service 2>/dev/null || true
    systemctl start docker.socket docker.service || true
  else
    pidof dockerd >/dev/null || { nohup dockerd >>/var/log/dockerd-appcrane-upgrade.log 2>&1 & }
  fi
}
wait_dockerd() {
  local _
  for _ in $(seq 1 "$DOCKERD_WAIT_S"); do
    docker version --format '{{.Server.Version}}' >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
start_dependents() {
  local u
  for u in "${DEPENDENTS[@]}"; do
    systemctl is-active --quiet "$u" && continue
    systemctl reset-failed "$u" 2>/dev/null || true
    systemctl start "$u" || warn "systemctl start $u failed: systemctl status $u"
  done
}
CRANE_OK=""
wait_crane() {
  local _
  (( CRANE_BEFORE )) || { CRANE_OK="not answering before the upgrade; not checked"; return 0; }
  for _ in $(seq 0 2 "$CRANE_WAIT_S"); do
    crane_up && { CRANE_OK="ok ($CRANE_URL)"; return 0; }
    sleep 2
  done
  CRANE_OK="FAILED: no answer on $CRANE_URL within ${CRANE_WAIT_S}s (systemctl status appcrane; journalctl -u appcrane -n 50)"
  return 1
}
restore_daemon_json() {
  [[ -n "$DJSON_BAK" ]] || return 0
  cmp -s "$DJSON" "$DJSON_BAK" 2>/dev/null || { cp -p "$DJSON_BAK" "$DJSON"; return 1; }
}
CHANGED=0; ROLLED_BACK=0
print_manual_rollback() {
  local back
  back="$(dce_rollback_args "$HAVE" "$(dce_installed_docker_pkgs)" | paste -sd' ' -)"
  warn "Docker was not rolled back. To return to the previous packages by hand:"
  if [[ "$INIT" == systemd ]]; then
    printf '      sudo systemctl stop docker.socket docker.service\n' >&2
  else
    printf '      sudo kill $(pidof dockerd)\n' >&2
  fi
  printf '      sudo dpkg --configure -a\n' >&2
  printf '      sudo %s --allow-downgrades %s\n' "${DCE_APT_INSTALL[*]}" "$back" >&2
  [[ -n "$DJSON_BAK" ]] && printf '      sudo cp -p %s %s\n' "$DJSON_BAK" "$DJSON" >&2
  if [[ "$INIT" == systemd ]]; then
    printf '      sudo systemctl start docker.socket docker.service %s\n' "${DEPENDENTS[*]}" >&2
  else
    printf '      sudo dockerd &\n' >&2
  fi
}
on_exit() {
  local rc=$?
  (( rc != 0 && CHANGED && ! ROLLED_BACK )) && print_manual_rollback
  return 0
}
trap on_exit EXIT
rollback() {
  local back=()
  warn "$1. Rolling back to the previous packages."
  mapfile -t back < <(dce_rollback_args "$HAVE" "$(dce_installed_docker_pkgs)")
  stop_docker
  dpkg --configure -a || warn "dpkg --configure -a failed"
  "${DCE_APT_INSTALL[@]}" --allow-downgrades "${back[@]}" || die "rollback failed too"
  ROLLED_BACK=1
  restore_daemon_json || true
  start_dockerd
  DOCKERD_WAIT_S=90
  if wait_dockerd; then
    warn "previous Docker $(docker version --format '{{.Server.Version}}') is running again"
  else
    warn "previous Docker did not start either: systemctl status docker; journalctl -u docker -n 50"
  fi
  start_dependents
  wait_crane || true
  warn "AppCrane: $CRANE_OK"
  exit 1
}

log "Installing docker-ce $TARGET (one apt transaction: ${INSTALL_ARGS[*]})"
stop_docker
CHANGED=1
"${DCE_APT_INSTALL[@]}" "${INSTALL_ARGS[@]}" || rollback "apt-get install failed"

if ! restore_daemon_json; then
  log "daemon.json had changed during the install; restored it from $DJSON_BAK"
  [[ "$INIT" == systemd ]] && systemctl restart docker.service || true
fi
start_dockerd
wait_dockerd || rollback "dockerd did not answer within ${DOCKERD_WAIT_S}s after the install"

# ---------- verify ----------
NEW_VER="$(docker version --format '{{.Server.Version}}')"
dce_ver_ge "$NEW_VER" "$DCE_MIN_FIXED" || rollback "the running dockerd is $NEW_VER, below $DCE_MIN_FIXED"
if (( HAD_RUNSC )); then
  [[ " $(docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}') " == *" runsc "* ]] \
    || rollback "the runsc runtime is no longer registered (check $DJSON); gVisor apps would not start"
  r_ok="runsc registered"
else
  r_ok="runsc was not registered before"
fi

# The probe uses AppCrane's pinned helper image, pulled only when it is not on
# the host, and removed afterwards only when this script pulled it.
fail=0
PULLED=0
if ! docker image inspect "$DCE_PROBE_IMAGE" >/dev/null 2>&1; then
  if docker pull -q "$DCE_PROBE_IMAGE" >/dev/null; then PULLED=1; fi
fi
if (( PULLED )) || docker image inspect "$DCE_PROBE_IMAGE" >/dev/null 2>&1; then
  HG_IP="$(docker run --rm --network bridge --add-host probe.test:host-gateway --entrypoint cat "$DCE_PROBE_IMAGE" /etc/hosts 2>/dev/null \
    | awk '$NF == "probe.test" { print $1; exit }' || true)"
  (( PULLED )) && { docker rmi "$DCE_PROBE_IMAGE" >/dev/null || warn "could not remove $DCE_PROBE_IMAGE"; }
  [[ "$HG_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || rollback "the host-gateway probe got '${HG_IP:-nothing}' instead of an IPv4"
  hg_ok="ok ($HG_IP)"
else
  hg_ok="NOT CHECKED: $DCE_PROBE_IMAGE is not on the host and could not be pulled"
  fail=1
fi

start_dependents
wait_crane || fail=1

RUNNING_AFTER=0
for _ in $(seq 0 5 "$WAIT_S"); do
  RUNNING_AFTER="$(docker ps -q | grep -c . || true)"
  (( RUNNING_AFTER >= RUNNING_BEFORE )) && break
  sleep 5
done

echo
echo "Docker upgrade summary"
echo "  Docker:           ${SERVER_VER:-not running} -> $NEW_VER (ok), docker-ce $TARGET"
echo "  runtimes:         $r_ok"
echo "  host-gateway:     $hg_ok"
echo "  units started:    ${DEPENDENTS[*]:-none needed}"
echo "  AppCrane:         $CRANE_OK"
echo "  running:          $RUNNING_AFTER of $RUNNING_BEFORE container(s) back$( (( RUNNING_AFTER < RUNNING_BEFORE )) && echo " after ${WAIT_S}s; start the rest from their app pages" )"
if [[ -n "$DJSON_BAK" ]]; then echo "  daemon.json:      kept (backup $DJSON_BAK)"; else echo "  daemon.json:      none"; fi
exit "$fail"
