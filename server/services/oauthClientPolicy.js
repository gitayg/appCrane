import { getDb } from '../db.js';
import {
  OAuthError, DCR_MODES, DCR_DEFAULT_MODE, DCR_DEFAULT_REDIRECT_HOSTS, normalizeRedirectHost, redirectAllowedByHosts,
} from './oauthPolicy.js';

// Who may register an MCP OAuth client (RFC 7591 dynamic registration is
// anonymous by design) and where it may send a user back to:
//   open       any https or loopback redirect, as the MCP spec assumes
//   allowlist  loopback, or https to a listed host (default: Claude.ai and Claude Code)
//   approval   any https or loopback redirect, but a platform admin approves the
//              client before anyone can connect it
// A client a platform admin approved is allowed in every mode.
// Checked at registration AND at /oauth/authorize, so tightening the mode also
// holds against clients registered while it was looser.

export const DCR_MODE_SETTING = 'oauth_dcr_mode';
export const DCR_HOSTS_SETTING = 'oauth_dcr_redirect_hosts';
const MAX_HOSTS = 50;

function setting(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;
}

function putSetting(db, key, value, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(key, value, userId ?? null);
}

export function getDcrPolicy(db = getDb()) {
  const mode = DCR_MODES.includes(setting(db, DCR_MODE_SETTING)) ? setting(db, DCR_MODE_SETTING) : DCR_DEFAULT_MODE;
  let hosts = DCR_DEFAULT_REDIRECT_HOSTS;
  const raw = setting(db, DCR_HOSTS_SETTING);
  if (raw != null) {
    try {
      const list = JSON.parse(raw);
      if (Array.isArray(list)) hosts = list.map(normalizeRedirectHost).filter(Boolean);
    } catch (_) { /* keep the default */ }
  }
  return { mode, redirect_hosts: hosts, default_mode: DCR_DEFAULT_MODE, default_redirect_hosts: DCR_DEFAULT_REDIRECT_HOSTS, modes: DCR_MODES };
}

/** Validate and store { mode?, redirect_hosts? }. Throws { status: 400 } on a bad value. */
export function updateDcrPolicy(db, body, userId) {
  const bad = (m) => Object.assign(new Error(m), { status: 400 });
  if (body.mode !== undefined) {
    if (!DCR_MODES.includes(body.mode)) throw bad(`mode must be one of ${DCR_MODES.join(', ')}`);
    putSetting(db, DCR_MODE_SETTING, body.mode, userId);
  }
  if (body.redirect_hosts !== undefined) {
    if (!Array.isArray(body.redirect_hosts) || body.redirect_hosts.length > MAX_HOSTS) throw bad(`redirect_hosts must be an array of at most ${MAX_HOSTS} hosts`);
    const hosts = [];
    for (const h of body.redirect_hosts) {
      const n = normalizeRedirectHost(h);
      if (!n) throw bad(`${JSON.stringify(String(h)).slice(0, 80)} is not a host name (write it bare, like claude.ai or app.example.com:8443)`);
      if (!hosts.includes(n)) hosts.push(n);
    }
    putSetting(db, DCR_HOSTS_SETTING, JSON.stringify(hosts), userId);
  }
  return getDcrPolicy(db);
}

/** Registration: refuse redirect URIs the allowlist does not cover. */
export function checkRegistration(redirectUris, db = getDb()) {
  const p = getDcrPolicy(db);
  if (p.mode === 'allowlist') {
    const off = redirectUris.find((u) => !redirectAllowedByHosts(u, p.redirect_hosts));
    if (off) {
      throw new OAuthError('invalid_redirect_uri',
        `This AppCrane only accepts MCP clients that return to ${p.redirect_hosts.length ? p.redirect_hosts.join(', ') : 'no listed host'} or to this computer (localhost). ${String(off).slice(0, 100)} is not one; a platform admin can add its host.`);
    }
  }
}

/** /oauth/authorize: may this client start a connection under the current policy? Null when yes, else why not. */
export function clientRefusal(client, redirectUri, db = getDb()) {
  const p = getDcrPolicy(db);
  if (client.approved_at) return null;
  if (p.mode === 'allowlist' && !redirectAllowedByHosts(redirectUri, p.redirect_hosts)) {
    return 'This app returns to a host this AppCrane does not allow for MCP connections. A platform admin can add the host under MCP OAuth settings.';
  }
  if (p.mode === 'approval' && !client.approved_at) {
    return 'This app is waiting for a platform admin to approve it. Ask an admin to approve it under MCP OAuth settings, then start again.';
  }
  return null;
}
