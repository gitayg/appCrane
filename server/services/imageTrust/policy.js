// Platform settings for image trust: the verify-before-run mode and the license
// policy. Written only through /api/image-trust/policy (the generic settings PUT
// refuses image_trust_* keys), read here.

import { getDb } from '../../db.js';

export const MODES = Object.freeze(['off', 'warn', 'enforce']);
// warn: an upgrade must not stop apps whose current images were never signed.
export const DEFAULT_MODE = 'warn';
export const KEYS = {
  mode: 'image_trust_mode',
  denied: 'image_trust_license_denied',
  flagged: 'image_trust_license_flagged',
};
export const UNKNOWN_LICENSE = 'unknown';
export const DEFAULT_FLAGGED = Object.freeze(['AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', UNKNOWN_LICENSE]);
const SPDXISH = /^[A-Za-z0-9.+-]{1,64}$/;

function get(db, k) { return db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? null; }
function set(db, k, v, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(k, v, userId ?? null);
}

function list(db, k, fallback) {
  const raw = get(db, k);
  if (raw == null) return [...fallback];
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a.filter((x) => typeof x === 'string') : [...fallback]; } catch { return [...fallback]; }
}

export function getTrustMode(db = getDb()) {
  const v = get(db, KEYS.mode);
  return MODES.includes(v) ? v : DEFAULT_MODE;
}

/** @returns {{ denied: string[], flagged: string[] }} */
export function getLicensePolicy(db = getDb()) {
  return { denied: list(db, KEYS.denied, []), flagged: list(db, KEYS.flagged, DEFAULT_FLAGGED) };
}

function cleanList(v, field) {
  if (!Array.isArray(v)) throw Object.assign(new Error(`${field} must be an array of SPDX license ids`), { status: 400 });
  const out = [...new Set(v.map((x) => String(x).trim()).filter(Boolean))];
  const bad = out.filter((x) => x !== UNKNOWN_LICENSE && !SPDXISH.test(x));
  if (bad.length) throw Object.assign(new Error(`${field}: not an SPDX license id: ${bad.slice(0, 3).join(', ')}`), { status: 400 });
  if (out.length > 200) throw Object.assign(new Error(`${field}: at most 200 entries`), { status: 400 });
  return out;
}

/** Partial patch { mode?, denied?, flagged? }. Returns the full policy. */
export function setTrustPolicy(db, patch, userId) {
  const p = patch || {};
  if (p.mode !== undefined && !MODES.includes(p.mode)) throw Object.assign(new Error(`mode must be one of ${MODES.join(', ')}`), { status: 400 });
  const denied = p.denied !== undefined ? cleanList(p.denied, 'denied') : null;
  const flagged = p.flagged !== undefined ? cleanList(p.flagged, 'flagged') : null;
  if (p.mode !== undefined) set(db, KEYS.mode, p.mode, userId);
  if (denied) set(db, KEYS.denied, JSON.stringify(denied), userId);
  if (flagged) set(db, KEYS.flagged, JSON.stringify(flagged), userId);
  return { mode: getTrustMode(db), ...getLicensePolicy(db) };
}
