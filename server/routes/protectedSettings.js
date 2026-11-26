import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { stepUpRefusal, ctxFromReq, windowMinutes } from '../services/stepUp.js';
import { PROTECTED_ROUTE_KEYS, READ_ONLY_KEYS } from '../services/settingsOwnedKeys.js';
import { DB_ALLOWLIST_MODES, DEFAULT_DB_ALLOWLIST_MODE, parseDbAllowlistMode, dbModeWeakens } from '../services/hostFirewall/dbMode.js';

// /api/settings/protected/:key (v2.147.0): settings whose value is a
// protection or a limit, and that have no route of their own. Platform admin
// only. Reads take a dashboard session or a user API key; writes take a
// dashboard session only, a write that weakens the protection (turns it off,
// raises a limit, shortens a window or a retention) also needs a recent
// step-up, and every write is audited with its old and new value. The state
// AppCrane records about a protection (READ_ONLY_KEYS) is readable, never
// writable. PUT /api/settings/:key refuses all of them (settingsOwnedKeys.js).

const READ_KINDS = ['session', 'api_key'];

const onOff = (on, off, isOff) => ({
  kind: 'switch',
  parse(v) {
    if (v === true || v === on) return on;
    if (v === false || v === off) return off;
    throw new AppError(`value must be true or false`, 400, 'VALIDATION');
  },
  effective: (raw) => !isOff(raw),
  weakens: (from, to) => from && !to,
});

const int = (min, max, def, weakerWhen) => ({
  kind: 'integer', min, max, default: def,
  parse(v) {
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max) throw new AppError(`value must be a whole number from ${min} to ${max}`, 400, 'VALIDATION');
    return String(n);
  },
  effective(raw) {
    const n = Number(raw);
    return raw != null && raw !== '' && Number.isInteger(n) && n >= min && n <= max ? n : def;
  },
  weakens: (from, to) => (weakerWhen === 'raised' ? to > from : to < from),
});

const lower = (v) => String(v ?? '').trim().toLowerCase();

export const SPEC = Object.freeze({
  host_gateway_auto_repair: onOff('1', '0', (r) => ['0', 'false', 'off'].includes(lower(r))),
  supply_chain_verify_enabled: onOff('1', '0', (r) => (r ?? '1') !== '1'),
  vuln_alerts_immediate: onOff('true', 'false', (r) => r != null && lower(r) === 'false'),
  app_access_mail_enabled: onOff('1', '0', (r) => r === '0'),
  restart_loop_short_count: int(1, 100_000, 3, 'raised'),
  restart_loop_short_minutes: int(1, 100_000, 10, 'lowered'),
  restart_loop_long_count: int(1, 100_000, 6, 'raised'),
  restart_loop_long_minutes: int(1, 100_000, 60, 'lowered'),
  restart_loop_quiet_minutes: int(1, 100_000, 60, 'lowered'),
  restart_backoff_base_minutes: int(1, 100_000, 5, 'lowered'),
  restart_backoff_max_minutes: int(1, 100_000, 360, 'lowered'),
  restart_incident_retention_days: int(1, 3650, 90, 'lowered'),
  max_dev_containers: int(1, 1000, 5, 'raised'),
  app_disk_quota_mb: int(1, 10_000_000, 2048, 'raised'),
  db_allowlist_mode: {
    kind: 'enum', values: DB_ALLOWLIST_MODES, default: DEFAULT_DB_ALLOWLIST_MODE,
    parse(v) {
      const s = lower(v);
      if (!DB_ALLOWLIST_MODES.includes(s)) throw new AppError('value must be off, observe or enforce', 400, 'VALIDATION');
      return s;
    },
    effective: parseDbAllowlistMode,
    weakens: dbModeWeakens,
    applied: async () => {
      const chain = await import('../services/hostFirewall/dbChain.js');
      if (chain.dbChainEnabled()) chain.requestDbChainSync();
    },
  },
});

const ipOf = (req) => req.ip || req.socket?.remoteAddress || 'unknown';
const actor = (req) => req.real_user || req.user;
const raw = (db, key) => db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;

function describe(db, key) {
  const value = raw(db, key);
  if (READ_ONLY_KEYS.includes(key)) return { key, value, writable: false, read_only: true };
  const s = SPEC[key];
  return {
    key, value, effective: s.effective(value), kind: s.kind, writable: true,
    ...(s.kind === 'integer' ? { min: s.min, max: s.max, default: s.default } : s.kind === 'enum' ? { values: s.values, default: s.default } : { default: true }),
  };
}

function knownKey(req, res, next) {
  const key = req.params.key;
  if (!Object.hasOwn(SPEC, key) && !READ_ONLY_KEYS.includes(key)) {
    return next(new AppError(`${key} is not a protected setting`, 404, 'NOT_FOUND'));
  }
  next();
}

function readKinds(req, res, next) {
  if (!READ_KINDS.includes(req.auth_kind)) {
    return next(new AppError('Protected settings are read with a dashboard session or a user API key', 403, 'SESSION_REQUIRED'));
  }
  next();
}

export function createProtectedSettingsRouter() {
  const router = Router();

  router.get('/', requireAuth, requirePlatformAdmin, readKinds, (req, res) => {
    const db = getDb();
    res.json({ settings: [...PROTECTED_ROUTE_KEYS, ...READ_ONLY_KEYS].map((k) => describe(db, k)) });
  });

  router.get('/:key', requireAuth, requirePlatformAdmin, readKinds, knownKey, (req, res) => {
    res.json(describe(getDb(), req.params.key));
  });

  router.put('/:key', requireAuth, requirePlatformAdmin, knownKey, async (req, res) => {
    const key = req.params.key;
    const who = actor(req);
    if (READ_ONLY_KEYS.includes(key)) {
      throw new AppError(`${key} is recorded by AppCrane only and cannot be written`, 409, 'READ_ONLY_SETTING');
    }
    if (req.auth_kind !== 'session') {
      throw new AppError('Protected settings are changed from a signed-in dashboard session, not with an API key, MCP key or agent', 403, 'SESSION_REQUIRED');
    }
    const s = SPEC[key];
    const db = getDb();
    const value = s.parse((req.body || {}).value);
    const beforeRaw = raw(db, key);
    const from = s.effective(beforeRaw);
    const to = s.effective(value);
    const weakens = s.weakens(from, to);
    if (weakens) {
      const err = stepUpRefusal(db, ctxFromReq(req), 'platform_archive');
      if (err) {
        err.message = `Confirm it's you: to weaken ${key} you need to have signed in within the last ${windowMinutes(db)} minutes.`;
        throw err;
      }
    }
    db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
      .run(key, value, who.id);
    logAudit(who.id, null, 'protected-setting-change', { key, from: beforeRaw, to: value, effective_from: from, effective_to: to, weakens, ip: ipOf(req) });
    if (s.applied) await s.applied();
    res.json(describe(db, key));
  });

  return router;
}

export default createProtectedSettingsRouter();
