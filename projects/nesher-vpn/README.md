# Nesher VPN

Browse from your PC or iPhone **with the public IP of a device sitting in Nesher**,
using short-lived passes issued at `crane.glick.run`.

```
 iPhone / PC                         Nesher home                     Internet
 WireGuard app ──── UDP 51820 ────▶ router ──▶ Nesher device ──NAT──▶ (sites see Nesher's IP)
                                                   │
                                                   │ HTTPS poll every 15s (outbound only)
                                                   ▼
                         nesher-vpn app on crane.glick.run  ◀── you sign in (AppCrane SSO),
                                                                 create a pass → QR code
```

- **Client:** the official **WireGuard** app — free, open source, on the iOS App Store,
  Android, Windows, macOS and Linux. No custom app to build or sideload.
- **Auth:** this app runs on AppCrane, so only users AppCrane lets into it can get a pass.
  A pass is a WireGuard peer with an expiry (1h / 8h / 1d / 3d / 7d) and can be revoked
  any time; the device drops it within ~15s.
- **Security:** the per-pass private key is generated, put in the QR/config and **never
  stored**. Each pass also gets a preshared key. Expiry is enforced on the device too, so a
  pass dies on time even if crane is unreachable. Pass holders can't reach the Nesher home
  LAN or each other (`BLOCK_LAN=1`). The device opens no control port — only WireGuard UDP,
  which stays silent to anyone without a valid key.

## 1. Deploy the app on AppCrane

1. Create an app (e.g. slug `nesher-vpn`) from this directory (`projects/nesher-vpn`).
2. Env vars (see `.env.example`): set `AGENT_TOKEN` to `openssl rand -hex 32`.
   Optionally `VPN_ENDPOINT=<ddns-name>:51820`.
3. Let the device reach the agent API without SSO — it authenticates with `AGENT_TOKEN`:
   `appcrane_set_app_meta slug=nesher-vpn auth_bypass_paths=["/agent/"]`
4. Give the people who should be able to surf via Nesher a role on the app
   (`user` or above — `viewer` can look but not create passes).

## 2. Set up the Nesher device

Any always-on Linux box at the Nesher location: a Raspberry Pi 4/5, an old mini-PC, etc.
(Debian 12 / Ubuntu 22.04+ / Raspberry Pi OS bookworm.)

```bash
git clone https://github.com/gitayg/appCrane.git && cd appCrane/projects/nesher-vpn/agent
sudo CRANE_URL=https://nesher-vpn.crane.glick.run AGENT_TOKEN=<same token> ./install.sh
```

Then on the Nesher **router**: give the device a fixed LAN IP and **forward UDP 51820** to it.
Within ~15s the app shows *Nesher device online*.

> **CGNAT check:** if the router's WAN IP differs from what `curl ifconfig.me` shows,
> the ISP uses carrier-grade NAT and port-forwarding won't work. Ask the ISP for a public IP
> (Israeli ISPs usually do this on request), or see *No port forward possible* below.

## 3. Connect

1. Open `https://nesher-vpn.crane.glick.run`, sign in, name the device, pick a duration,
   **Create pass**.
2. **iPhone:** WireGuard app → **+** → *Create from QR code* → scan → toggle on.
   **PC:** install WireGuard → *Import tunnel(s) from file* → the downloaded `.conf`.
3. Visit `ifconfig.me` — it shows Nesher's IP.

All traffic (IPv4) goes through Nesher; IPv6 is blocked rather than leaked. DNS uses
`VPN_DNS` (Cloudflare by default) through the tunnel. On iPhone you can enable
*On-Demand* in the tunnel settings to auto-connect on untrusted Wi-Fi.

## No port forward possible?

If Nesher is behind CGNAT, the alternative is Headscale (self-hosted, open source) on the
crane box + the Nesher device as a Tailscale *exit node* — it traverses NAT without port
forwarding, and preauth keys play the role of ad-hoc tokens. The trade-off is the Tailscale
iOS app (its core is open source, the iOS UI is not). Ask before switching; the direct
WireGuard path above is simpler and fully open source.

## Operating

| What | Where |
|---|---|
| Agent logs | `journalctl -u nesher-vpn-agent -f` on the device |
| Live peers | `sudo wg show` on the device |
| All passes (admins) | app UI → *everyone's* |
| Rotate the agent token | change `AGENT_TOKEN` in the app env and in `/etc/nesher-vpn/agent.env`, `systemctl restart nesher-vpn-agent` |

## Develop

```bash
npm install && npm test
DEV_USER=me@example.com AGENT_TOKEN=$(openssl rand -hex 32) VPN_ENDPOINT=example:51820 npm start
```
`DEV_USER` acts as a signed-in admin when no AppCrane proxy is in front — never set it on crane.
