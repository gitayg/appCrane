#!/usr/bin/env bash
#
# Replaces the contents of the APPCRANE-DB chain (iptables and ip6tables): for
# each managed database host port named, one RETURN per app container address
# allowed to reach it, then a DROP for every other source (or, for a port
# being observed, a rate-limited LOG). DOCKER-USER jumps
# here for connections Docker DNATs to the default bridge (where the managed
# database servers run); a RETURN lets DOCKER-USER carry on, so this chain can
# only narrow what is allowed. scripts/install-host-hardening.sh installs a
# root-owned copy at /usr/local/lib/appcrane/appcrane-db-chain.sh and a sudoers
# rule for it, so a non-root AppCrane can keep the chain in step:
#
#   sudo -n /usr/local/lib/appcrane/appcrane-db-chain.sh allow:45432:172.20.0.5 close:43306
#
# Arguments (at most 2048):
#   allow:<port>:<IPv4 or IPv6 address>  that address may reach <port>
#   close:<port>                          <port> is filtered (no address allowed
#                                         unless an allow names it)
#   log:<port>                            <port> is observed: after its allows,
#                                         a counting rule with no target and a
#                                         rate-limited LOG (10/min, burst 10,
#                                         prefix "APPCRANE-DB-WOULD-DROP ")
#                                         instead of the DROP, so nothing is
#                                         refused
# A port has close or log, not both (exit 2); a port named only by allows is
# closed. Each named port gets its DROP or LOG in both families; an IPv4 allow is
# written to iptables only and an IPv6 allow to ip6tables only. Ports in the
# order first named, allows in the order given, duplicates dropped. Ports not
# named fall through. No arguments empties the chain. Port 1-65535 with no
# leading zero; IPv4 a dotted quad of 0-255 with no leading zeros; IPv6 hex
# groups (no zone, no prefix, no embedded IPv4). Anything else exits 2 and
# changes nothing. Each family is replaced atomically (iptables-restore
# --noflush naming only this chain, which creates it when missing); no other
# chain is touched. ip6tables is skipped when it is not usable. Prints nothing
# on success.

set -uo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

bad() { echo "appcrane-db-chain: argument $1 $2" >&2; exit 2; }

port_ok() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 )); }

ipv4_ok() {
  local o
  [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  for o in ${1//./ }; do
    [[ "$o" =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( o <= 255 )) || return 1
  done
}

ipv6_ok() {
  local a="$1" head tail g n=0 parts groups
  [[ "$a" =~ ^[0-9A-Fa-f:]{2,39}$ ]] || return 1
  [[ "$a" != *:::* ]] || return 1
  if [[ "$a" == *::* ]]; then
    head="${a%%::*}"; tail="${a#*::}"
    [[ "$tail" != *::* ]] || return 1
  else
    head="$a"; tail=""
  fi
  for parts in "$head" "$tail"; do
    [[ -z "$parts" ]] && continue
    [[ "$parts" != :* && "$parts" != *: ]] || return 1
    IFS=: read -ra groups <<<"$parts"
    for g in "${groups[@]}"; do
      [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
      n=$((n + 1))
    done
  done
  if [[ "$a" == *::* ]]; then (( n <= 7 )); else (( n == 8 )); fi
}

(( $# <= 2048 )) || { echo "appcrane-db-chain: at most 2048 arguments" >&2; exit 2; }
declare -A seen=() ports=()
order=()
declare -A allow4=() allow6=() mode=()
i=0
for a in "$@"; do
  i=$((i + 1))
  if [[ "$a" =~ ^(close|log):([^:]*)$ ]]; then
    m="${BASH_REMATCH[1]}"; p="${BASH_REMATCH[2]}"
    port_ok "$p" || bad "$i" "is not $m:<1-65535>"
    [[ -z "${mode[$p]:-}" || "${mode[$p]}" == "$m" ]] || bad "$i" "names port $p, which is already ${mode[$p]}: a port has close or log, not both"
    mode[$p]="$m"
    addr=""
  elif [[ "$a" =~ ^allow:([^:]*):(.*)$ ]]; then
    p="${BASH_REMATCH[1]}"; addr="${BASH_REMATCH[2]}"
    port_ok "$p" || bad "$i" "is not allow:<1-65535>:<address>"
    if ipv4_ok "$addr"; then fam=4
    elif ipv6_ok "$addr"; then fam=6
    else bad "$i" "is not allow:<port>:<IPv4 or IPv6 address>"
    fi
  else
    bad "$i" "is not allow:<port>:<address>, close:<port> or log:<port>"
  fi
  if [[ -z "${ports[$p]:-}" ]]; then ports[$p]=1; order+=("$p"); fi
  [[ -z "$addr" || -n "${seen[$p/$addr]:-}" ]] && continue
  seen[$p/$addr]=1
  rule="-A APPCRANE-DB -s $addr/$([[ $fam == 4 ]] && echo 32 || echo 128) -p tcp -m conntrack --ctorigdstport $p --ctdir ORIGINAL -j RETURN"$'\n'
  if [[ $fam == 4 ]]; then allow4[$p]+="$rule"; else allow6[$p]+="$rule"; fi
done

rules4=""; rules6=""
for p in ${order[@]+"${order[@]}"}; do
  if [[ "${mode[$p]:-}" == log ]]; then
    drop="-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport $p --ctdir ORIGINAL"$'\n'
    drop+="-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport $p --ctdir ORIGINAL -m limit --limit 10/min --limit-burst 10 -j LOG --log-prefix \"APPCRANE-DB-WOULD-DROP \""$'\n'
  else
    drop="-A APPCRANE-DB -p tcp -m conntrack --ctorigdstport $p --ctdir ORIGINAL -j DROP"$'\n'
  fi
  rules4+="${allow4[$p]:-}$drop"
  rules6+="${allow6[$p]:-}$drop"
done

replace() {
  "$1-restore" -w --noflush <<EOF
*filter
:APPCRANE-DB - [0:0]
${2}COMMIT
EOF
}

replace iptables "$rules4" || exit 1
if command -v ip6tables-restore >/dev/null 2>&1 && ip6tables -w -n -L INPUT >/dev/null 2>&1; then
  replace ip6tables "$rules6" || exit 1
fi
exit 0
