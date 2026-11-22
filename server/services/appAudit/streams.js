import { getDb } from '../../db.js';
import { validateSink, hydrate, maskSink } from '../siem/store.js';
import { getAllowlist, assertResolvable } from '../siem/netGuard.js';

// Owner-managed audit streams: the platform SIEM sink shape (validateSink, the
// same senders) scoped to ONE app's audit events. Stricter than a platform
// sink because the person configuring it is an app owner, not the operator:
//   - TLS verification cannot be turned off and syslog is TLS only;
//   - the destination must be public. Private, loopback and CGNAT addresses
//     are refused unless a platform admin turned on OWNER_PRIVATE_KEY, and then
//     only those on the platform SIEM private allowlist; link-local (cloud
//     metadata) is refused always (siem/netGuard.js policyFor).
// The check runs when the stream is saved (here) and again on every
// connection (the senders' guarded DNS lookup), so a name re-pointed at a
// private address later is still refused.

export const OWNER_STREAMS_KEY = 'app_audit_owner_streams_enabled';
export const OWNER_PRIVATE_KEY = 'app_audit_owner_streams_private';
const MAX_PER_APP = 5;

function bad(message, status = 400, code = 'VALIDATION') {
  return Object.assign(new Error(message), { status, code });
}

function flag(db, key, def) {
  const v = db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value;
  return v == null ? def : v === 'true' || v === '1';
}

export function platformPolicy(db = getDb()) {
  return { owner_streams_enabled: flag(db, OWNER_STREAMS_KEY, true), owner_streams_private: flag(db, OWNER_PRIVATE_KEY, false) };
}

export function setPlatformPolicy({ owner_streams_enabled, owner_streams_private }, userId, db = getDb()) {
  const up = db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`);
  if (owner_streams_enabled !== undefined) up.run(OWNER_STREAMS_KEY, owner_streams_enabled ? 'true' : 'false', userId ?? null);
  if (owner_streams_private !== undefined) up.run(OWNER_PRIVATE_KEY, owner_streams_private ? 'true' : 'false', userId ?? null);
  return platformPolicy(db);
}

/** The private allowlist an owner stream may use: empty unless the platform allows it. */
export function ownerAllowlist(db = getDb()) {
  return platformPolicy(db).owner_streams_private ? getAllowlist(db) : [];
}

function hostOf(u) {
  try { return new URL(u).hostname.replace(/^\[(.*)\]$/, '$1'); } catch { return null; }
}

/** Every host a stream of this shape will connect to. */
export function destinationHosts(s) {
  const c = s.config || {};
  const hosts = [];
  if (s.type === 'syslog') hosts.push(c.host);
  else if (s.type === 's3') hosts.push(c.endpoint ? hostOf(c.endpoint) : `s3.${c.region || 'us-east-1'}.amazonaws.com`);
  else if (s.preset === 'sumo') hosts.push(hostOf(s.secrets?.url));
  else if (s.preset === 'datadog') hosts.push(c.url ? hostOf(c.url) : `http-intake.logs.${c.site || 'datadoghq.com'}`);
  else if (s.preset === 'sentinel') hosts.push(hostOf(c.dce_url), c.authority ? hostOf(c.authority) : 'login.microsoftonline.com');
  else hosts.push(hostOf(c.url));
  return [...new Set(hosts.filter(Boolean))];
}

async function assertDestinations(s, allowlist) {
  for (const h of destinationHosts(s)) {
    try { await assertResolvable(h, allowlist); } catch (e) {
      if (e.code === 'EBLOCKEDADDRESS') throw bad(`${h}: ${e.message}. Owner streams may only send to public addresses.`, 400, 'DESTINATION_NOT_ALLOWED');
      throw bad(`${h} could not be resolved: ${e.code || e.message}`, 400, 'DESTINATION_UNRESOLVED');
    }
  }
}

function parseActions(list) {
  if (list == null) return null;
  if (!Array.isArray(list) || list.length > 50) throw bad('filters.actions must be an array of at most 50 action names or prefixes');
  const out = [...new Set(list.map(a => String(a || '').trim()))].filter(Boolean);
  for (const a of out) if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(a)) throw bad(`filters.actions: ${a} is not an action name or prefix`);
  return out.length ? out : null;
}

/** Validate a create (current = null) or update for app `appId`. Async: resolves the destination. */
export async function validateStream(body, current = null, db = getDb()) {
  if (!platformPolicy(db).owner_streams_enabled) throw bad('A platform admin has turned off app audit streams', 403, 'OWNER_STREAMS_DISABLED');
  if (body?.tls_skip_verify === true) throw bad('App audit streams always verify TLS; add the server CA in ca_pem instead');
  const cfg = body?.config ?? (current ? JSON.parse(current.config || '{}') : {});
  const type = current ? current.type : body?.type;
  if (type === 'syslog' && cfg.transport === 'udp') throw bad('App audit streams send syslog over TCP with TLS only');
  let values;
  try {
    values = validateSink({ ...body, filters: {}, tls_skip_verify: false }, current ? { ...current, filter_kinds: null, filter_apps: null, min_severity: 'info' } : null);
  } catch (e) { throw bad(e.message); }
  await assertDestinations(hydrate({ ...values, id: current?.id ?? 0 }), ownerAllowlist(db));
  const actions = body?.filters?.actions !== undefined ? parseActions(body.filters.actions)
    : (current?.filter_actions ? JSON.parse(current.filter_actions) : null);
  return {
    name: values.name, type: values.type, preset: values.preset, format: values.format, enabled: values.enabled,
    config: values.config, secrets_enc: values.secrets_enc, ca_pem: values.ca_pem, tls_skip_verify: 0,
    filter_actions: actions ? JSON.stringify(actions) : null,
  };
}

export function getStreamRow(appId, id, db = getDb()) {
  return /^\d+$/.test(String(id)) ? db.prepare('SELECT * FROM app_audit_streams WHERE id = ? AND app_id = ?').get(Number(id), appId) || null : null;
}

export function listStreamRows(appId = null, db = getDb()) {
  return appId == null ? db.prepare('SELECT * FROM app_audit_streams ORDER BY id').all()
    : db.prepare('SELECT * FROM app_audit_streams WHERE app_id = ? ORDER BY id').all(appId);
}

export function insertStream(appId, values, { userId, startFrom = 'now' } = {}, db = getDb()) {
  if (db.prepare('SELECT COUNT(*) AS n FROM app_audit_streams WHERE app_id = ?').get(appId).n >= MAX_PER_APP) {
    throw bad(`An app can have at most ${MAX_PER_APP} audit streams`, 409, 'LIMIT');
  }
  const cursor = startFrom === 'all' ? 0 : (db.prepare('SELECT MAX(id) AS m FROM app_audit_events WHERE app_id = ?').get(appId)?.m || 0);
  return Number(db.prepare(`INSERT INTO app_audit_streams (app_id, name, type, preset, format, enabled, config, secrets_enc, ca_pem,
      tls_skip_verify, filter_actions, cursor_event_id, created_by)
    VALUES (@app_id, @name, @type, @preset, @format, @enabled, @config, @secrets_enc, @ca_pem, 0, @filter_actions, @cursor, @created_by)`)
    .run({ ...values, app_id: appId, cursor, created_by: userId ?? null }).lastInsertRowid);
}

export function updateStream(id, values, db = getDb()) {
  db.prepare(`UPDATE app_audit_streams SET name = @name, preset = @preset, format = @format, enabled = @enabled, config = @config,
      secrets_enc = @secrets_enc, ca_pem = @ca_pem, filter_actions = @filter_actions, updated_at = datetime('now') WHERE id = @id`)
    .run({ ...values, id });
}

export function deleteStream(id, db = getDb()) {
  return db.prepare('DELETE FROM app_audit_streams WHERE id = ?').run(id).changes > 0;
}

/** API view: credentials as { set, preview } (maskSink), never the value. */
export function maskStream(row) {
  const m = maskSink({ ...row, filter_kinds: null, filter_apps: null, min_severity: 'info' });
  delete m.filters;
  return { ...m, app_id: row.app_id, filters: { actions: row.filter_actions ? JSON.parse(row.filter_actions) : [] } };
}
