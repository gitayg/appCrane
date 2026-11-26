# shellcheck shell=bash
# Shared by install.sh (fresh installs) and scripts/docker-upgrade.sh: Docker
# versions with the reload bug, and Docker's official apt repository.
#
# A dockerd reload (SIGHUP) on some releases empties host-gateway, and every
# container created afterwards gets "invalid IP" for host.docker.internal.
# Measured in privileged docker:<version>-dind (2026-11-25):
#   27.5.1 ok | 28.0.4, 28.5.2, 29.0.0, 29.1.3, 29.2.0 broken | 29.3.0, 29.4.0, 29.5.0, 29.10.1 ok
# 28.0.0-28.0.3 and 29.2.1 were not measured and count as broken. Ubuntu's own
# docker.io is 29.1.3 on 24.04 and 25.10, so the fix is Docker CE from
# download.docker.com, installed the way docs.docker.com/engine/install/ubuntu
# documents: key in /etc/apt/keyrings/docker.asc, /etc/apt/sources.list.d/docker.sources.
#
# Source this file; it defines functions only.

DCE_REPO_URL="${DCE_REPO_URL:-https://download.docker.com/linux/ubuntu}"
DCE_KEYRING="${DCE_KEYRING:-/etc/apt/keyrings/docker.asc}"
DCE_SOURCES="${DCE_SOURCES:-/etc/apt/sources.list.d/docker.sources}"
DCE_MIN_FIXED=29.3.0
DCE_OS_RELEASE="${DCE_OS_RELEASE:-/etc/os-release}"
# Recommends stay out: docker-ce-cli recommends docker-buildx-plugin and
# docker-compose-plugin, and server/services/docker.js turns BuildKit on when
# buildx is present, which would change every app's build. dce_install_args adds
# the plugins only where their Ubuntu counterparts were installed.
DCE_APT_INSTALL=(apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold)
# The same pinned image as HELPER_IMAGE in server/services/volumeHelper.js.
# shellcheck disable=SC2034
DCE_PROBE_IMAGE='busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'

# "5:29.10.1-1~ubuntu.24.04~noble" or "29.1.3-0ubuntu3~24.04.2" -> "29.10.1"
dce_upstream() {
  local v="${1#*:}"
  v="${v%%[-~+]*}"
  printf '%s\n' "$v"
}

# 0 when $1 >= $2 (both X.Y[.Z]).
dce_ver_ge() {
  local a b i
  IFS=. read -r -a a <<<"$(dce_upstream "$1")"
  IFS=. read -r -a b <<<"$(dce_upstream "$2")"
  for i in 0 1 2; do
    (( 10#${a[i]:-0} > 10#${b[i]:-0} )) && return 0
    (( 10#${a[i]:-0} < 10#${b[i]:-0} )) && return 1
  done
  return 0
}

dce_valid_version() {
  [[ "$(dce_upstream "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]
}

# 0 when a reload on this version breaks host-gateway (28.x, 29.0-29.2).
dce_reload_bug() {
  dce_valid_version "$1" || return 1
  dce_ver_ge "$1" 28.0.0 && ! dce_ver_ge "$1" "$DCE_MIN_FIXED"
}

# 0 when install.sh should not take this distro docker.io: the reload bug, or older than 27.
dce_distro_unfit() {
  dce_valid_version "$1" || return 0
  dce_reload_bug "$1" || ! dce_ver_ge "$1" 27.0.0
}

dce_os_field() {
  [[ "$1" =~ ^[A-Z_]+$ ]] || return 1
  # shellcheck disable=SC1090
  ( . "$DCE_OS_RELEASE" 2>/dev/null; printf '%s\n' "${!1:-}" )
}

dce_codename() {
  local c
  c="$(dce_os_field UBUNTU_CODENAME)"
  [[ -n "$c" ]] || c="$(dce_os_field VERSION_CODENAME)"
  printf '%s\n' "$c"
}

dce_is_ubuntu() {
  [[ "$(dce_os_field ID)" == ubuntu ]]
}

# 0 when Docker's repository publishes this Ubuntu codename (checked live).
dce_codename_supported() {
  [[ "$1" =~ ^[a-z]+$ ]] || return 1
  curl -fsS -o /dev/null --max-time 30 "$DCE_REPO_URL/dists/$1/Release"
}

# The documented repository setup. Idempotent: rewrites the same two files.
dce_add_repo() {
  local codename="$1" arch
  arch="$(dpkg --print-architecture)"
  install -m 0755 -d "$(dirname "$DCE_KEYRING")"
  curl -fsSL "$DCE_REPO_URL/gpg" -o "$DCE_KEYRING"
  chmod a+r "$DCE_KEYRING"
  printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: %s\n' \
    "$DCE_REPO_URL" "$codename" "$arch" "$DCE_KEYRING" > "$DCE_SOURCES"
  apt-get update -y
}

# Reads `apt-cache madison docker-ce` on stdin and prints the full apt version
# to install: the newest at or above DCE_MIN_FIXED, or the one whose upstream
# version (or full string) equals $1. Prints nothing when there is none.
dce_pick_version() {
  local want="${1:-}" line ver
  while IFS= read -r line; do
    [[ "$line" == *"|"* ]] || continue
    ver="$(cut -d'|' -f2 <<<"$line" | tr -d '[:space:]')"
    dce_valid_version "$ver" || continue
    dce_ver_ge "$ver" "$DCE_MIN_FIXED" || continue
    [[ -z "$want" || "$ver" == "$want" || "$(dce_upstream "$ver")" == "$want" ]] || continue
    printf '%s\t%s\n' "${ver#*:}" "$ver"
  done | sort -V -k1,1 | tail -n1 | cut -f2
}

# Installed (state ii) packages among the Docker-related set, as "name=version" lines.
dce_installed_docker_pkgs() {
  dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Version}\n' 2>/dev/null \
    | awk -F'\t' '$1 ~ /^ii/ && $2 ~ /^(docker\.io|docker-ce|docker-ce-cli|docker-ce-rootless-extras|containerd|containerd\.io|runc|docker-buildx|docker-buildx-plugin|docker-compose-v2|docker-compose-plugin|docker-doc|podman-docker)$/ { print $2 "=" $3 }'
}

# The apt-get install arguments that replace whatever Docker is installed with
# Docker CE $1 in one transaction. $2 is the dce_installed_docker_pkgs output.
# The Ubuntu buildx/compose packages get their Docker CE counterparts, so a
# box that built with BuildKit before still does after.
dce_install_args() {
  local ver="$1" have="$2" p
  local args=("docker-ce=$ver" "docker-ce-cli=$ver" containerd.io)
  grep -q '^docker-buildx=' <<<"$have" && args+=(docker-buildx-plugin docker-buildx-)
  grep -q '^docker-compose-v2=' <<<"$have" && args+=(docker-compose-plugin docker-compose-v2-)
  for p in docker.io containerd runc docker-doc podman-docker; do
    grep -q "^${p//./\\.}=" <<<"$have" && args+=("$p-")
  done
  printf '%s\n' "${args[@]}"
}

# Fresh install (install.sh): Docker CE from the official repository.
# Returns non-zero when the codename is unsupported or no fixed version exists.
dce_fresh_install() {
  local codename ver
  codename="$(dce_codename)"
  dce_codename_supported "$codename" || { echo "Docker's repository has no Ubuntu '$codename' ($DCE_REPO_URL/dists/$codename)" >&2; return 1; }
  dce_add_repo "$codename" || return 1
  ver="$(apt-cache madison docker-ce | dce_pick_version "${DOCKER_VERSION:-}")"
  [[ -n "$ver" ]] || { echo "no docker-ce ${DOCKER_VERSION:-at or above $DCE_MIN_FIXED} in Docker's repository for '$codename'" >&2; return 1; }
  mapfile -t _dce_args < <(dce_install_args "$ver" "$(dce_installed_docker_pkgs)")
  "${DCE_APT_INSTALL[@]}" "${_dce_args[@]}"
}

# The apt-get install arguments that return to the packages in $1 (the
# dce_installed_docker_pkgs output before the upgrade) from those in $2 (now):
# every old package at its old version, and every package added since removed.
dce_rollback_args() {
  local have="$1" now="$2" p
  while IFS= read -r p; do [[ -n "$p" ]] && printf '%s\n' "$p"; done <<<"$have"
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    grep -q "^${p%%=*}=" <<<"$have" || printf '%s-\n' "${p%%=*}"
  done <<<"$now"
}
