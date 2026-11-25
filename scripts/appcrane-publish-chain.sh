#!/usr/bin/env bash
#
# Replaces the contents of the APPCRANE-PUBLISH chain (iptables and ip6tables)
# with one ACCEPT per published port. scripts/install-host-hardening.sh installs
# a root-owned copy at /usr/local/lib/appcrane/appcrane-publish-chain.sh and a
# sudoers rule for it, so a non-root AppCrane can keep the chain in step with
# the ports it publishes:
#
#   sudo -n /usr/local/lib/appcrane/appcrane-publish-chain.sh tcp:8080 udp:31001
#
# No arguments empties the chain. Every argument must be <tcp|udp>:<port>
# (1-65535, no leading zero; at most 512); anything else exits 2 and changes
# nothing. Each family is replaced atomically (iptables-restore --noflush naming
# only this chain, which creates it when missing); no other chain is touched.
# ip6tables is skipped when it is not usable. Prints nothing on success.

set -uo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

(( $# <= 512 )) || { echo "appcrane-publish-chain: at most 512 arguments" >&2; exit 2; }
declare -A seen=()
rules=""
i=0
for a in "$@"; do
  i=$((i + 1))
  if [[ ! "$a" =~ ^(tcp|udp):([1-9][0-9]{0,4})$ ]] || (( BASH_REMATCH[2] > 65535 )); then
    echo "appcrane-publish-chain: argument $i is not <tcp|udp>:<1-65535>" >&2
    exit 2
  fi
  [[ -n "${seen[$a]:-}" ]] && continue
  seen[$a]=1
  rules+="-A APPCRANE-PUBLISH -p ${BASH_REMATCH[1]} -m conntrack --ctstate DNAT --ctorigdstport ${BASH_REMATCH[2]} --ctdir ORIGINAL -j ACCEPT"$'\n'
done

replace() {
  "$1-restore" -w --noflush <<EOF
*filter
:APPCRANE-PUBLISH - [0:0]
${rules}COMMIT
EOF
}

replace iptables || exit 1
if command -v ip6tables-restore >/dev/null 2>&1 && ip6tables -w -n -L INPUT >/dev/null 2>&1; then
  replace ip6tables || exit 1
fi
exit 0
