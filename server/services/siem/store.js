import crypto from 'crypto';
import { isIP } from 'net';
import { getDb } from '../../db.js';
import { encrypt, decrypt } from '../encryption.js';
import { secretPreview } from '../secretMask.js';
import { HTTPS_PRESETS } from './https.js';

// SIEM sink rows: validation, encrypted credentials, and the masked view the
// API returns. A credential is written once and never read back out: GET shows
// { set, preview } like an env var, and an update that omits a secret keeps it.

export const SINK_TYPES = ['syslog', 'https', 's3'];
export const FORMATS = ['json', 'cef'];
export const SEVERITIES = ['info', 'warning', 'critical'];
const S3_SECRETS = ['secret_access_key'];
const CA_MAX = 64 * 1024;

export const DEFAULTS = { batch_size: 500, max_lag_sec: 900, alert_after_sec: 300, flush_sec: 300 };

function bad(msg) {
  return Object.assign(new Error(msg), { status: 400, code: 'VALIDATION' });
}

function str(v, max = 512) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

function httpsUrl(v, field, required = true) {
  const s = str(v, 2048);
  if (!s) { if (required) throw bad(`${field} is required`); return ''; }
  let u;
  try { u = new URL(s); } catch { throw bad(`${field} is not a valid URL`); }
  if (u.protocol !== 'https:') throw bad(`${field} must be an https:// URL`);
  if (u.username || u.password) throw bad(`${field} must not carry credentials; use the credential fields`);
  return s;
}

function hostName(v) {
  const s = str(v, 255).toLowerCase();
  if (!s) throw bad('config.host is required');
  if (!isIP(s) && !/^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$/.test(s)) throw bad('config.host is not a valid host name or IP');
  return s;
}

function intIn(v, lo, hi, def, field) {
  if (v === undefined || v === null || v === '') return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < lo || n > hi) throw bad(`${field} must be a whole number from ${lo} to ${hi}`);
  return n;
}

export function secretKeysFor(type, preset) {
  if (type === 'https') return HTTPS_PRESETS[preset]?.secrets || [];
  if (type === 's3') return S3_SECRETS;
  return [];
}

function validateConfig(type, preset, format, c = {}) {
  const common = {
    batch_size: intIn(c.batch_size, 1, 5000, DEFAULTS.batch_size, 'config.batch_size'),
    max_lag_sec: intIn(c.max_lag_sec, 60, 7 * 86400, DEFAULTS.max_lag_sec, 'config.max_lag_sec'),
    alert_after_sec: intIn(c.alert_after_sec, 0, 86400, DEFAULTS.alert_after_sec, 'config.alert_after_sec'),
  };
  if (type === 'syslog') {
    const transport = c.transport === 'udp' ? 'udp' : c.transport === 'tcp-tls' || c.transport == null ? 'tcp-tls' : null;
    if (!transport) throw bad("config.transport must be 'tcp-tls' or 'udp'");
    return { ...common, host: hostName(c.host), port: intIn(c.port, 1, 65535, transport === 'udp' ? 514 : 6514, 'config.port'), transport,
      facility: intIn(c.facility, 0, 23, 13, 'config.facility') };
  }
  if (type === 's3') {
    const bucket = str(c.bucket, 63);
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) throw bad('config.bucket is not a valid bucket name');
    const accessKeyId = str(c.access_key_id, 128);
    if (!accessKeyId) throw bad('config.access_key_id is required');
    const region = str(c.region, 32) || 'us-east-1';
    if (!/^[a-z0-9-]+$/.test(region)) throw bad('config.region is not valid');
    const prefix = str(c.prefix, 200);
    if (prefix && !/^[A-Za-z0-9!_.*'()/-]+$/.test(prefix)) throw bad('config.prefix has characters S3 keys should not carry');
    return { ...common, bucket, region, access_key_id: accessKeyId, endpoint: httpsUrl(c.endpoint, 'config.endpoint', false),
      prefix, gzip: !!c.gzip, flush_sec: intIn(c.flush_sec, 10, 86400, DEFAULTS.flush_sec, 'config.flush_sec') };
  }
  const out = { ...common, gzip: !!c.gzip, max_bytes: intIn(c.max_bytes, 1024, 10 * 1024 * 1024, 1024 * 1024, 'config.max_bytes') };
  switch (preset) {
    case 'splunk':
      return { ...out, url: httpsUrl(c.url, 'config.url'), index: str(c.index, 80), sourcetype: str(c.sourcetype, 80) };
    case 'datadog': {
      const site = str(c.site, 64);
      if (site && !/^[a-z0-9.-]+$/.test(site)) throw bad('config.site is not valid');
      return { ...out, url: httpsUrl(c.url, 'config.url', false), site, service: str(c.service, 80), tags: str(c.tags, 512) };
    }
    case 'elastic':
      return { ...out, url: httpsUrl(c.url, 'config.url'), index: str(c.index, 120), username: str(c.username, 120) };
    case 'sumo':
      return { ...out, category: str(c.category, 200) };
    case 'sentinel': {
      if (format !== 'json') throw bad('Sentinel takes JSON rows only');
      const req = (k) => { const v = str(c[k], 200); if (!v) throw bad(`config.${k} is required`); return v; };
      return { ...out, tenant_id: req('tenant_id'), client_id: req('client_id'), dce_url: httpsUrl(c.dce_url, 'config.dce_url'),
        dcr_id: req('dcr_id'), stream: req('stream'), authority: httpsUrl(c.authority, 'config.authority', false) };
    }
    default: {
      const header = str(c.auth_header, 80);
      if (header && !/^[A-Za-z0-9-]+$/.test(header)) throw bad('config.auth_header is not a valid header name');
      return { ...out, url: httpsUrl(c.url, 'config.url'), auth_header: header };
    }
  }
}

function validateCa(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v !== 'string' || v.length > CA_MAX) throw bad('ca_pem must be a PEM certificate bundle under 64 KB');
  const pems = v.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (!pems) throw bad('ca_pem holds no PEM certificate');
  for (const p of pems) {
    try { new crypto.X509Certificate(p); } catch { throw bad('ca_pem holds a certificate that does not parse'); }
  }
  return pems.join('\n') + '\n';
}

function validateFilters(f = {}) {
  const kinds = Array.isArray(f.kinds) ? [...new Set(f.kinds.map(k => str(k, 64).toLowerCase()).filter(Boolean))] : [];
  for (const k of kinds) if (!/^[a-z0-9_.]+$/.test(k)) throw bad(`filters.kinds: ${k} is not an event kind`);
  const apps = Array.isArray(f.apps) ? [...new Set(f.apps.map(a => str(a, 64).toLowerCase()).filter(Boolean))] : [];
  for (const a of apps) if (!/^[a-z0-9][a-z0-9-]*$/.test(a)) throw bad(`filters.apps: ${a} is not an app slug`);
  const minSeverity = f.min_severity == null ? 'info' : f.min_severity;
  if (!SEVERITIES.includes(minSeverity)) throw bad(`filters.min_severity must be one of ${SEVERITIES.join(', ')}`);
  return { kinds, apps, min_severity: minSeverity };
}

function readSecrets(row) {
  if (!row?.secrets_enc) return {};
  try { return JSON.parse(decrypt(row.secrets_enc)); } catch { return {}; }
}

function mergeSecrets(allowed, current, incoming) {
  const out = {};
  for (const k of allowed) if (typeof current[k] === 'string' && current[k]) out[k] = current[k];
  if (incoming == null) return out;
  if (typeof incoming !== 'object' || Array.isArray(incoming)) throw bad('secrets must be an object');
  for (const [k, v] of Object.entries(incoming)) {
    if (!allowed.includes(k)) throw bad(`secrets.${k} is not a credential of this sink type`);
    if (v === null || v === '') delete out[k];
    else if (typeof v === 'string') {
      if (v.length > 4096) throw bad(`secrets.${k} is too long`);
      out[k] = v.trim();
    } else throw bad(`secrets.${k} must be a string`);
  }
  return out;
}

function parseJson(v, def) {
  try { return v ? JSON.parse(v) : def; } catch { return def; }
}

/** Runtime view of a row, with decrypted secrets. Server-side only. */
export function hydrate(row) {
  if (!row) return null;
  return {
    id: row.id, name: row.name, type: row.type, preset: row.preset, format: row.format, enabled: !!row.enabled,
    config: parseJson(row.config, {}), ca_pem: row.ca_pem || null, tls_skip_verify: !!row.tls_skip_verify,
    filters: { kinds: parseJson(row.filter_kinds, []), apps: parseJson(row.filter_apps, []), min_severity: row.min_severity },
    cursor: row.cursor_event_id, row,
    secrets: readSecrets(row),
  };
}

/** What the API returns: credentials as { set, preview }, never the value. */
export function maskSink(row) {
  const s = hydrate(row);
  const secrets = {};
  for (const k of secretKeysFor(s.type, s.preset)) {
    const v = s.secrets[k];
    secrets[k] = v ? { set: true, preview: secretPreview(v) } : { set: false };
  }
  return {
    id: s.id, name: s.name, type: s.type, preset: s.preset, format: s.format, enabled: s.enabled,
    config: s.config, has_ca: !!s.ca_pem, ca_pem: s.ca_pem, tls_skip_verify: s.tls_skip_verify, filters: s.filters, secrets,
    cursor_event_id: row.cursor_event_id, delivered_count: row.delivered_count,
    last_success_at: row.last_success_at, last_attempt_at: row.last_attempt_at, last_error: row.last_error,
    last_error_at: row.last_error_at, failing_since: row.failing_since, consecutive_failures: row.consecutive_failures,
    created_at: row.created_at, updated_at: row.updated_at,
  };
}

export function getSinkRow(id, db = getDb()) {
  return db.prepare('SELECT * FROM siem_sinks WHERE id = ?').get(id) || null;
}

export function listSinkRows(db = getDb()) {
  return db.prepare('SELECT * FROM siem_sinks ORDER BY id').all();
}

/** Validate a create (current = null) or an update into column values. Throws 400s. */
export function validateSink(body, current = null) {
  if (!body || typeof body !== 'object') throw bad('body must be an object');
  const cur = current ? hydrate(current) : null;
  const type = current ? current.type : body.type;
  if (!SINK_TYPES.includes(type)) throw bad(`type must be one of ${SINK_TYPES.join(', ')}`);
  if (current && body.type && body.type !== current.type) throw bad('type cannot be changed; create a new sink');
  let preset = body.preset ?? cur?.preset ?? 'generic';
  if (type === 'https' && !HTTPS_PRESETS[preset]) throw bad(`preset must be one of ${Object.keys(HTTPS_PRESETS).join(', ')}`);
  if (type !== 'https') preset = 'generic';
  const name = body.name !== undefined ? str(body.name, 80) : cur?.name;
  if (!name) throw bad('name is required');
  const format = body.format ?? cur?.format ?? 'json';
  if (!FORMATS.includes(format)) throw bad(`format must be one of ${FORMATS.join(', ')}`);
  if (type === 's3' && format !== 'json') throw bad('the S3 export writes JSONL only');
  const config = validateConfig(type, preset, format, body.config ?? cur?.config ?? {});
  const filters = validateFilters(body.filters ?? cur?.filters ?? {});
  const ca = body.ca_pem !== undefined ? validateCa(body.ca_pem) : (cur?.ca_pem ?? null);
  const skip = body.tls_skip_verify !== undefined ? body.tls_skip_verify === true : !!cur?.tls_skip_verify;
  if (type === 's3' && (skip || ca)) throw bad('the S3 export uses the system trust store; custom CA and skip-verify do not apply');
  const allowed = secretKeysFor(type, preset);
  const secrets = mergeSecrets(allowed, cur && cur.preset === preset ? cur.secrets : {}, body.secrets);
  if (type === 'https' && preset === 'sumo') httpsUrl(secrets.url, 'secrets.url');
  if (type === 'https' && preset === 'splunk' && !secrets.token) throw bad('secrets.token is required for Splunk HEC');
  if (type === 'https' && preset === 'datadog' && !secrets.api_key) throw bad('secrets.api_key is required for Datadog');
  if (type === 'https' && preset === 'sentinel' && !secrets.client_secret) throw bad('secrets.client_secret is required for Sentinel');
  if (type === 's3' && !secrets.secret_access_key) throw bad('secrets.secret_access_key is required');
  return {
    name, type, preset, format,
    enabled: body.enabled !== undefined ? (body.enabled ? 1 : 0) : (cur ? (cur.enabled ? 1 : 0) : 1),
    config: JSON.stringify(config),
    secrets_enc: Object.keys(secrets).length ? encrypt(JSON.stringify(secrets)) : null,
    ca_pem: ca, tls_skip_verify: skip ? 1 : 0,
    filter_kinds: filters.kinds.length ? JSON.stringify(filters.kinds) : null,
    filter_apps: filters.apps.length ? JSON.stringify(filters.apps) : null,
    min_severity: filters.min_severity,
  };
}

export function insertSink(values, { userId, startFrom = 'now' } = {}, db = getDb()) {
  const cursor = startFrom === 'all' ? 0 : (db.prepare('SELECT MAX(id) AS m FROM events').get()?.m || 0);
  const info = db.prepare(`INSERT INTO siem_sinks (name, type, preset, format, enabled, config, secrets_enc, ca_pem, tls_skip_verify,
      filter_kinds, filter_apps, min_severity, cursor_event_id, created_by)
    VALUES (@name, @type, @preset, @format, @enabled, @config, @secrets_enc, @ca_pem, @tls_skip_verify,
      @filter_kinds, @filter_apps, @min_severity, @cursor, @created_by)`)
    .run({ ...values, cursor, created_by: userId ?? null });
  return Number(info.lastInsertRowid);
}

export function updateSink(id, values, db = getDb()) {
  db.prepare(`UPDATE siem_sinks SET name = @name, preset = @preset, format = @format, enabled = @enabled, config = @config,
      secrets_enc = @secrets_enc, ca_pem = @ca_pem, tls_skip_verify = @tls_skip_verify, filter_kinds = @filter_kinds,
      filter_apps = @filter_apps, min_severity = @min_severity, updated_at = datetime('now') WHERE id = @id`)
    .run({ ...values, id });
}

export function deleteSink(id, db = getDb()) {
  return db.prepare('DELETE FROM siem_sinks WHERE id = ?').run(id).changes > 0;
}

/** Move the cursor: 'now' (skip the backlog), 'all' (replay what the store still holds) or an event id. */
export function setCursor(id, to, db = getDb()) {
  let cursor;
  if (to === 'now') cursor = db.prepare('SELECT MAX(id) AS m FROM events').get()?.m || 0;
  else if (to === 'all') cursor = 0;
  else if (Number.isInteger(to) && to >= 0) cursor = to;
  else throw bad("to must be 'now', 'all' or an event id");
  db.prepare("UPDATE siem_sinks SET cursor_event_id = ?, updated_at = datetime('now') WHERE id = ?").run(cursor, id);
  return cursor;
}
