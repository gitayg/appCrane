import crypto from 'crypto';
import { getDb } from '../../db.js';
import { encrypt, decrypt, generateApiKey, hashApiKey } from '../encryption.js';
import { SSO_SETTING_KEY, ssoRequired } from '../authPolicy.js';
import { validateSink, insertSink, deleteSink, getSinkRow, maskSink } from '../siem/store.js';
import { unregisterJob } from '../siem/delivery.js';
import { testOidc, testSaml } from './connectionTest.js';

// Changes made from an IT setup link. A section edit is staged; it takes effect
// only when the IT contact confirms it, and an SSO change only after its
// connection test passed for exactly those values. Applying records the
// settings rows it replaced, so a platform admin can roll the last change back.
//
// What a link can never do: write auth_sso_only to on, turn auto-provisioning
// on, or edit the join-without-approval list. If applying an SSO change would
// switch "Require SSO sign-in" into force (a provider enabled where none was),
// the setting is stored off instead, as the first-provider rule in oidc.js
// does, so password and break-glass admin sign-in keep working.

const KEYS = {
  oidc: ['oidc_enabled', 'oidc_discovery_url', 'oidc_client_id', 'oidc_provider_name', 'oidc_client_secret_enc', SSO_SETTING_KEY],
  saml: ['saml_enabled', 'saml_idp_sso_url', 'saml_provider_name', 'saml_idp_cert_enc', SSO_SETTING_KEY],
  scim: ['scim_enabled', 'scim_token_hash', 'scim_token_created_at'],
};
export const NEEDS_TEST = new Set(['oidc', 'saml']);

const bad = (message, status = 400, code = 'VALIDATION') => Object.assign(new Error(message), { status, code });
const str = (v, max = 500) => String(v ?? '').trim().slice(0, max);

function setting(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;
}

function snapshot(db, keys) {
  return Object.fromEntries(keys.map((k) => [k, setting(db, k)]));
}

function writeSetting(db, key, value) {
  if (value === null) { db.prepare('DELETE FROM settings WHERE key = ?').run(key); return; }
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, NULL, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = NULL, updated_at = datetime('now')`).run(key, String(value));
}

function decryptOr(v) {
  if (!v) return '';
  try { return decrypt(v); } catch { return ''; }
}

/** Validate what the page sent for one scope into the values to stage. */
export function validateInput(scope, body = {}) {
  if (scope === 'oidc') {
    const v = {
      enabled: body.enabled === true, discovery_url: str(body.discovery_url), client_id: str(body.client_id, 300),
      provider_name: str(body.provider_name, 60) || 'SSO', client_secret: body.client_secret ? String(body.client_secret).slice(0, 2000) : null,
    };
    if (v.discovery_url && !/^https:\/\//i.test(v.discovery_url)) throw bad('discovery_url must start with https://');
    if (v.enabled && (!v.discovery_url || !v.client_id)) throw bad('Enter the discovery URL and client ID before turning SSO sign-in on.');
    return v;
  }
  if (scope === 'saml') {
    const v = { enabled: body.enabled === true, idp_sso_url: str(body.idp_sso_url), provider_name: str(body.provider_name, 60) || 'SSO', idp_cert: body.idp_cert ? String(body.idp_cert).trim().slice(0, 20000) : null };
    if (v.idp_sso_url && !/^https:\/\//i.test(v.idp_sso_url)) throw bad('idp_sso_url must start with https://');
    if (v.enabled && !v.idp_sso_url) throw bad('Enter the IdP sign-in URL before turning SAML on.');
    return v;
  }
  if (scope === 'scim') {
    const v = { enabled: body.enabled === true, rotate_token: body.rotate_token === true };
    return v;
  }
  if (scope === 'siem') {
    if (body.tls_skip_verify === true) throw bad('A setup link cannot turn TLS verification off; ask a platform admin.');
    const values = validateSink({ ...body, tls_skip_verify: false });
    return { values };
  }
  throw bad(`Unknown scope ${scope}`);
}

export function stageChange(linkId, scope, body, db = getDb()) {
  const after = validateInput(scope, body);
  return db.transaction(() => {
    db.prepare("UPDATE it_setup_changes SET status = 'discarded' WHERE link_id = ? AND scope = ? AND status = 'staged'").run(linkId, scope);
    return db.prepare('INSERT INTO it_setup_changes (link_id, scope, after_enc) VALUES (?, ?, ?)')
      .run(linkId, scope, encrypt(JSON.stringify(after))).lastInsertRowid;
  })();
}

export function getChange(linkId, id, db = getDb()) {
  if (!/^\d+$/.test(String(id))) return undefined;
  return db.prepare('SELECT * FROM it_setup_changes WHERE id = ? AND link_id = ?').get(Number(id), linkId);
}

const afterOf = (change) => JSON.parse(decrypt(change.after_enc));
const recordOf = (change) => (change.before_enc ? JSON.parse(decrypt(change.before_enc)) : null);

/** Run the connection test for a staged SSO change and remember the outcome. */
export async function testChange(change, db = getDb()) {
  if (!NEEDS_TEST.has(change.scope)) throw bad('This section has no connection test.');
  if (change.status !== 'staged') throw bad('Only a staged change can be tested.', 409, 'NOT_STAGED');
  const after = afterOf(change);
  const result = change.scope === 'oidc'
    ? await testOidc(after)
    : testSaml({ ...after, idp_cert: after.idp_cert || decryptOr(setting(db, 'saml_idp_cert_enc')) });
  db.prepare('UPDATE it_setup_changes SET test_ok = ? WHERE id = ?').run(result.ok ? 1 : 0, change.id);
  return result;
}

function settingsFor(scope, after, db) {
  if (scope === 'oidc') {
    const out = {
      oidc_enabled: after.enabled ? '1' : '0', oidc_discovery_url: after.discovery_url,
      oidc_client_id: after.client_id, oidc_provider_name: after.provider_name,
    };
    if (after.client_secret) out.oidc_client_secret_enc = encrypt(after.client_secret);
    return { out };
  }
  if (scope === 'saml') {
    const out = { saml_enabled: after.enabled ? '1' : '0', saml_idp_sso_url: after.idp_sso_url, saml_provider_name: after.provider_name };
    if (after.idp_cert) out.saml_idp_cert_enc = encrypt(after.idp_cert);
    return { out };
  }
  const out = { scim_enabled: after.enabled ? '1' : '0' };
  let token = null;
  if (after.rotate_token || !setting(db, 'scim_token_hash')) {
    token = generateApiKey('scim');
    out.scim_token_hash = hashApiKey(token);
    out.scim_token_created_at = new Date().toISOString();
  }
  return { out, token };
}

/**
 * Apply a staged change. Returns { change, token?, sso_only_turned_off }.
 * token is the new SCIM bearer token, returned once and never stored.
 */
export function applyChange(change, db = getDb()) {
  if (change.status !== 'staged') throw bad('This change is not waiting for confirmation.', 409, 'NOT_STAGED');
  if (NEEDS_TEST.has(change.scope) && !change.test_ok) throw bad('Run the connection test and get a pass before confirming.', 409, 'TEST_REQUIRED');
  const after = afterOf(change);
  return db.transaction(() => {
    let token = null;
    let ssoOnlyTurnedOff = false;
    let record;
    if (change.scope === 'siem') {
      const sinkId = insertSink(after.values, { userId: null, startFrom: 'now' }, db);
      record = { sink_id: sinkId };
    } else {
      const keys = KEYS[change.scope];
      const before = snapshot(db, keys);
      const requiredBefore = ssoRequired(db);
      const r = settingsFor(change.scope, after, db);
      token = r.token;
      for (const [k, v] of Object.entries(r.out)) writeSetting(db, k, v);
      if (!requiredBefore && ssoRequired(db)) {
        writeSetting(db, SSO_SETTING_KEY, 'false');
        ssoOnlyTurnedOff = true;
      }
      record = { before, after: snapshot(db, keys), sso_only_turned_off: ssoOnlyTurnedOff };
    }
    db.prepare("UPDATE it_setup_changes SET status = 'applied', applied_at = datetime('now'), before_enc = ? WHERE id = ?")
      .run(encrypt(JSON.stringify(record)), change.id);
    return { change: db.prepare('SELECT * FROM it_setup_changes WHERE id = ?').get(change.id), token, sso_only_turned_off: ssoOnlyTurnedOff };
  })();
}

export function discardChange(change, db = getDb()) {
  if (change.status !== 'staged') throw bad('This change is not waiting for confirmation.', 409, 'NOT_STAGED');
  db.prepare("UPDATE it_setup_changes SET status = 'discarded' WHERE id = ?").run(change.id);
}

export function lastApplied(linkId, db = getDb()) {
  return db.prepare("SELECT * FROM it_setup_changes WHERE link_id = ? AND status = 'applied' ORDER BY applied_at DESC, id DESC LIMIT 1").get(linkId);
}

/**
 * Undo an applied change: put back the settings rows it replaced (or delete
 * the SIEM destination it added). Refused with 409 CHANGED_SINCE when those
 * settings changed after it was applied, unless force.
 */
export function rollbackChange(change, adminId, { force = false } = {}, db = getDb()) {
  if (change.status !== 'applied') throw bad('Only an applied change can be rolled back.', 409, 'NOT_APPLIED');
  const record = recordOf(change);
  return db.transaction(() => {
    if (change.scope === 'siem') {
      deleteSink(record.sink_id, db);
      unregisterJob(record.sink_id);
    } else {
      const now = snapshot(db, Object.keys(record.after));
      const drifted = Object.keys(record.after).filter((k) => now[k] !== record.after[k]);
      if (drifted.length && !force) throw Object.assign(bad(`Changed since this was applied: ${drifted.join(', ')}. Pass force to roll back anyway.`, 409, 'CHANGED_SINCE'), { drifted });
      for (const [k, v] of Object.entries(record.before)) writeSetting(db, k, v);
    }
    db.prepare("UPDATE it_setup_changes SET status = 'rolled_back', rolled_back_at = datetime('now'), rolled_back_by = ? WHERE id = ?").run(adminId, change.id);
    return db.prepare('SELECT * FROM it_setup_changes WHERE id = ?').get(change.id);
  })();
}

function certSummary(pem) {
  if (!pem) return null;
  try {
    const text = pem.includes('BEGIN CERTIFICATE') ? pem : `-----BEGIN CERTIFICATE-----\n${pem.replace(/\s+/g, '')}\n-----END CERTIFICATE-----`;
    const c = new crypto.X509Certificate(text);
    return { fingerprint256: c.fingerprint256, valid_to: c.validTo };
  } catch { return { unreadable: true }; }
}

/** A change as the page and the admin see it: no secret, ever. */
export function changeView(change, db = getDb()) {
  const after = afterOf(change);
  let values;
  if (change.scope === 'oidc') values = { ...after, client_secret: undefined, client_secret_set: !!after.client_secret };
  else if (change.scope === 'saml') values = { ...after, idp_cert: certSummary(after.idp_cert) };
  else if (change.scope === 'siem') {
    const v = after.values;
    values = { name: v.name, type: v.type, preset: v.preset, format: v.format, config: JSON.parse(v.config), has_secrets: !!v.secrets_enc };
    const applied = recordOf(change);
    const row = applied?.sink_id ? getSinkRow(applied.sink_id, db) : null;
    if (row) values.sink = maskSink(row);
  } else values = after;
  const record = recordOf(change);
  return {
    id: change.id, link_id: change.link_id, scope: change.scope, status: change.status, values,
    needs_test: NEEDS_TEST.has(change.scope), test_ok: !!change.test_ok,
    sso_only_turned_off: !!record?.sso_only_turned_off,
    changed_keys: record?.before ? Object.keys(record.before).filter((k) => record.before[k] !== record.after[k]) : undefined,
    created_at: change.created_at, applied_at: change.applied_at, rolled_back_at: change.rolled_back_at,
  };
}

export function listChanges(linkId, db = getDb()) {
  return db.prepare('SELECT * FROM it_setup_changes WHERE link_id = ? ORDER BY id DESC').all(linkId).map((c) => changeView(c, db));
}

function base() {
  return process.env.CRANE_DOMAIN ? 'https://' + process.env.CRANE_DOMAIN : 'http://localhost:' + (process.env.PORT || 5001);
}

/** The live configuration of one section, masked. */
export function currentSection(scope, linkId, db = getDb()) {
  if (scope === 'oidc') {
    return {
      enabled: setting(db, 'oidc_enabled') === '1', discovery_url: setting(db, 'oidc_discovery_url') || '',
      client_id: setting(db, 'oidc_client_id') || '', provider_name: setting(db, 'oidc_provider_name') || 'SSO',
      client_secret_set: !!setting(db, 'oidc_client_secret_enc'), redirect_uri: base() + '/api/auth/oidc/callback',
    };
  }
  if (scope === 'saml') {
    return {
      enabled: setting(db, 'saml_enabled') === '1', idp_sso_url: setting(db, 'saml_idp_sso_url') || '',
      provider_name: setting(db, 'saml_provider_name') || 'Okta', idp_cert: certSummary(decryptOr(setting(db, 'saml_idp_cert_enc'))),
      acs_url: base() + '/api/auth/saml/callback', entity_id: base() + '/api/auth/saml/metadata', metadata_url: base() + '/api/auth/saml/metadata',
    };
  }
  if (scope === 'scim') {
    return {
      enabled: setting(db, 'scim_enabled') === '1', token_set: !!setting(db, 'scim_token_hash'),
      token_created_at: setting(db, 'scim_token_created_at'), base_url: base() + '/api/scim/v2',
    };
  }
  if (scope === 'siem') {
    const ids = db.prepare("SELECT before_enc FROM it_setup_changes WHERE link_id = ? AND scope = 'siem' AND status = 'applied'").all(linkId)
      .map((c) => JSON.parse(decrypt(c.before_enc)).sink_id);
    return { sinks: ids.map((id) => getSinkRow(id, db)).filter(Boolean).map(maskSink) };
  }
  return null;
}
