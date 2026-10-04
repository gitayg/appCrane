#!/usr/bin/env bash
# Nesher VPN agent — keeps the local WireGuard interface's peer list in sync with
# the passes issued on AppCrane. Outbound HTTPS only: it polls, nothing polls it.
#
# Config (/etc/nesher-vpn/agent.env):
#   CRANE_URL    https://nesher-vpn.crane.glick.run   (no trailing slash)
#   AGENT_TOKEN  same value as the app's AGENT_TOKEN env var
#   WG_IF        wg0 (default)
#   INTERVAL     seconds between syncs, default 15
set -uo pipefail

: "${CRANE_URL:?CRANE_URL is required}"
: "${AGENT_TOKEN:?AGENT_TOKEN is required}"
WG_IF="${WG_IF:-wg0}"
INTERVAL="${INTERVAL:-15}"
CACHE_DIR="${CACHE_DIR:-/var/lib/nesher-vpn}"
CACHE="$CACHE_DIR/peers.json"
mkdir -p "$CACHE_DIR" && chmod 700 "$CACHE_DIR"

log() { echo "[nesher-vpn-agent] $*"; }

# Token goes via a 0600 header file, never on the command line (visible in ps).
AUTH_HDR="$CACHE_DIR/auth.hdr"
( umask 077; printf 'Authorization: Bearer %s\n' "$AGENT_TOKEN" >"$AUTH_HDR" )
curl_crane() { curl -fsS --max-time 10 -H "@$AUTH_HDR" "$@"; }

fetch_peers() {
  local tmp; tmp="$(mktemp "$CACHE_DIR/peers.XXXXXX")"
  if curl_crane "$CRANE_URL/agent/peers" -o "$tmp" && jq -e '.peers | type == "array"' "$tmp" >/dev/null; then
    mv "$tmp" "$CACHE"; chmod 600 "$CACHE"
  else
    rm -f "$tmp"
    log "crane unreachable — using cached peer list (expiry still enforced locally)"
  fi
}

reconcile() {
  [[ -f "$CACHE" ]] || return 0
  local now desired current pk psk ips pskfile
  now="$(date +%s)"
  # Expiry is enforced here too, so a pass dies on time even if crane is down.
  desired="$(jq -r --argjson now "$now" '.peers[] | select(.expiresAt > $now) | [.publicKey, .presharedKey, .allowedIps] | @tsv' "$CACHE")"
  current="$(wg show "$WG_IF" peers)"

  while IFS=$'\t' read -r pk psk ips; do
    [[ -n "$pk" ]] || continue
    pskfile="$(mktemp)"; chmod 600 "$pskfile"; printf '%s' "$psk" >"$pskfile"
    wg set "$WG_IF" peer "$pk" preshared-key "$pskfile" allowed-ips "$ips" || log "failed to set peer $pk"
    rm -f "$pskfile"
  done <<<"$desired"

  while read -r pk; do
    [[ -n "$pk" ]] || continue
    if ! grep -qF "$pk" <<<"$desired"; then
      wg set "$WG_IF" peer "$pk" remove && log "removed peer $pk"
    fi
  done <<<"$current"
}

report_status() {
  # wg dump: line 1 = interface (privkey pubkey port fwmark); then per peer:
  # pubkey psk endpoint allowed-ips latest-handshake rx tx keepalive. Keys we send: public only.
  wg show "$WG_IF" dump | awk -F'\t' '
    NR == 1 { printf "{\"publicKey\":\"%s\",\"listenPort\":%s,\"peers\":[", $2, $3; next }
    { printf "%s{\"publicKey\":\"%s\",\"latestHandshake\":%s,\"rx\":%s,\"tx\":%s}", (n++ ? "," : ""), $1, $5, $6, $7 }
    END { print "]}" }' |
  curl_crane -X POST -H 'Content-Type: application/json' --data-binary @- "$CRANE_URL/agent/status" -o /dev/null ||
    log "status report failed"
}

log "syncing $WG_IF with $CRANE_URL every ${INTERVAL}s"
while true; do
  fetch_peers
  reconcile
  report_status
  sleep "$INTERVAL"
done
