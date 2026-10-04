#!/usr/bin/env bash
# Sets up the Nesher device as the VPN exit: WireGuard server + NAT + the sync agent.
# Tested target: Debian 12 / Ubuntu 22.04+ / Raspberry Pi OS (bookworm). Run as root:
#
#   sudo CRANE_URL=https://nesher-vpn.crane.glick.run AGENT_TOKEN=... ./install.sh
#
# Optional: WG_PORT (51820), BLOCK_LAN (1 = pass holders cannot reach the Nesher home LAN).
set -euo pipefail

: "${CRANE_URL:?set CRANE_URL, e.g. https://nesher-vpn.crane.glick.run}"
: "${AGENT_TOKEN:?set AGENT_TOKEN (same value as the app env var)}"
WG_IF=wg0
WG_PORT="${WG_PORT:-51820}"
BLOCK_LAN="${BLOCK_LAN:-1}"
SUBNET=10.77.0.0/24
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

echo "==> installing packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools iptables jq curl

echo "==> enabling IPv4 forwarding"
echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-nesher-vpn.conf
sysctl -q --system

WAN_IF="$(ip -4 route show default | awk '{print $5; exit}')"
[[ -n "$WAN_IF" ]] || { echo "no default route — is the device online?"; exit 1; }
echo "==> outbound interface: $WAN_IF"

umask 077
mkdir -p /etc/wireguard /etc/nesher-vpn
if [[ ! -f /etc/wireguard/$WG_IF.key ]]; then
  wg genkey >/etc/wireguard/$WG_IF.key
fi
PRIV="$(cat /etc/wireguard/$WG_IF.key)"

LAN_RULES=""
if [[ "$BLOCK_LAN" == 1 ]]; then
  # Pass holders get the internet, not the house: no RFC1918 / link-local destinations.
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
    LAN_RULES+="PostUp = iptables -I FORWARD -i %i -d $net -j DROP"$'\n'
    LAN_RULES+="PostDown = iptables -D FORWARD -i %i -d $net -j DROP"$'\n'
  done
fi

cat >/etc/wireguard/$WG_IF.conf <<CONF
# Managed by nesher-vpn install.sh. Peers are added at runtime by nesher-vpn-agent.
[Interface]
Address = 10.77.0.1/24
ListenPort = $WG_PORT
PrivateKey = $PRIV
SaveConfig = false
PostUp = iptables -A FORWARD -i %i -o $WAN_IF -j ACCEPT
PostUp = iptables -A FORWARD -i $WAN_IF -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -I FORWARD -i %i -o %i -j DROP
PostUp = iptables -t nat -A POSTROUTING -s $SUBNET -o $WAN_IF -j MASQUERADE
PostUp = iptables -t mangle -A FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i %i -o $WAN_IF -j ACCEPT
PostDown = iptables -D FORWARD -i $WAN_IF -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o %i -j DROP
PostDown = iptables -t nat -D POSTROUTING -s $SUBNET -o $WAN_IF -j MASQUERADE
PostDown = iptables -t mangle -D FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
$LAN_RULES
CONF
chmod 600 /etc/wireguard/$WG_IF.conf

cat >/etc/nesher-vpn/agent.env <<ENV
CRANE_URL=${CRANE_URL%/}
AGENT_TOKEN=$AGENT_TOKEN
WG_IF=$WG_IF
INTERVAL=15
ENV
chmod 600 /etc/nesher-vpn/agent.env

install -m 755 "$HERE/nesher-vpn-agent.sh" /usr/local/bin/nesher-vpn-agent
cat >/etc/systemd/system/nesher-vpn-agent.service <<UNIT
[Unit]
Description=Nesher VPN agent (syncs WireGuard peers from AppCrane)
After=network-online.target wg-quick@$WG_IF.service
Wants=network-online.target
Requires=wg-quick@$WG_IF.service

[Service]
EnvironmentFile=/etc/nesher-vpn/agent.env
ExecStart=/usr/local/bin/nesher-vpn-agent
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

echo "==> starting WireGuard and the agent"
systemctl daemon-reload
systemctl enable --now wg-quick@$WG_IF
systemctl enable --now nesher-vpn-agent
systemctl restart nesher-vpn-agent

LAN_IP="$(ip -4 addr show "$WAN_IF" | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')"
cat <<DONE

Done. Server public key: $(wg pubkey </etc/wireguard/$WG_IF.key)

Last step, on the Nesher router:
  forward UDP port $WG_PORT  ->  $LAN_IP:$WG_PORT   (this device)
and give this device a fixed LAN IP (DHCP reservation).

If the home IP changes, set up a dynamic-DNS name (e.g. DuckDNS) and set the app's
VPN_ENDPOINT env var to  <name>:$WG_PORT . Without it, the app uses the IP the agent
checks in from.

Logs:  journalctl -u nesher-vpn-agent -f      Peers:  wg show
DONE
