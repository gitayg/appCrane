import { Router } from 'express';
import { requireStepUp } from '../services/stepUp.js';
import { requireAuth, requirePlatformAdmin, requireAppAccess } from '../middleware/auth.js';
import { userHasAppPermission, isAppOwnerOrPlatformAdmin, isAppOwnerAdminOrPlatformAdmin } from '../services/permissions.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { sanitizeError } from '../services/jobHealth.js';
import { validAction, LIMITS } from '../services/appAudit/schema.js';
import {
  listAppEvents, listEventTypes, getAppAuditSettings, setAppAuditSettings, toCsv, EXPORT_MAX,
} from '../services/appAudit/store.js';
import {
  validateStream, getStreamRow, listStreamRows, insertStream, updateStream, deleteStream, maskStream,
  platformPolicy, setPlatformPolicy,
} from '../services/appAudit/streams.js';
import { deliverStream, sendStreamTest } from '../services/appAudit/delivery.js';
import { getAppAuditRetentionDays, setAppAuditRetentionDays, validDays, MIN_DAYS, MAX_DAYS } from '../services/appAudit/retention.js';
import { getDb } from '../db.js';
import { HTTPS_PRESETS } from '../services/siem/https.js';
import { secretKeysFor } from '../services/siem/store.js';

// App audit events (services/appAudit/*): what hosted apps wrote about
// themselves, read by the people the role matrix lets see the app's audit
// trail (app.audit.view: owner and app admins by default, platform admins
// always); event types by the owner or app admins; owner streams by the owner
// or a platform admin. Mounted once at '/api'; every route carries its own
// guards (a router.use() here would gate every /api request).

const router = Router();

// requireAppAccess replaces req.app with the app row, which breaks Express 5's
// req.query getter, so the query string is parsed from the URL.
const queryOf = (req) => Object.fromEntries(new URL(req.originalUrl || req.url, 'http://local').searchParams);

function rethrow(e) {
  if (e instanceof AppError) return e;
  if (e?.status) return new AppError(e.message, e.status, e.code || 'VALIDATION');
  return e;
}

function canRead(req) {
  if (!userHasAppPermission(req.user, req.app, 'app.audit.view')) {
    throw new AppError('Viewing the audit trail for this app is not permitted by your role', 403, 'FORBIDDEN');
  }
}

function sendExport(res, q, appId, name) {
  const { events } = listAppEvents(appId, { ...q, limit: EXPORT_MAX }, { max: EXPORT_MAX });
  const stamp = new Date().toISOString().slice(0, 10);
  if (q.format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${name}-audit-events-${stamp}.csv"`);
    return { count: events.length, send: () => res.send(toCsv(events)) };
  }
  res.setHeader('Content-Disposition', `attachment; filename="${name}-audit-events-${stamp}.json"`);
  return { count: events.length, send: () => res.json({ exported_at: new Date().toISOString(), truncated: events.length >= EXPORT_MAX, events }) };
}

// ── per app: events ──────────────────────────────────────────────────────

router.get('/apps/:slug/audit-events', requireAuth, requireAppAccess, (req, res) => {
  canRead(req);
  try { res.json(listAppEvents(req.app.id, queryOf(req))); } catch (e) { throw rethrow(e); }
});

router.get('/apps/:slug/audit-events/export', requireAuth, requireAppAccess, (req, res) => {
  canRead(req);
  const q = queryOf(req);
  let out;
  try { out = sendExport(res, q, req.app.id, req.app.slug); } catch (e) { throw rethrow(e); }
  logAudit(req.user.id, req.app.id, 'app-audit-events-export', { format: q.format === 'csv' ? 'csv' : 'json', count: out.count });
  out.send();
});

router.get('/apps/:slug/audit-events/config', requireAuth, requireAppAccess, (req, res) => {
  canRead(req);
  res.json({
    types: listEventTypes(req.app.id), settings: getAppAuditSettings(req.app.id), retention_days: getAppAuditRetentionDays(),
    can_manage_types: isAppOwnerAdminOrPlatformAdmin(req.user, req.app), can_manage_streams: isAppOwnerOrPlatformAdmin(req.user, req.app),
  });
});

function canManageTypes(req) {
  if (!isAppOwnerAdminOrPlatformAdmin(req.user, req.app)) {
    throw new AppError('Only the app owner, an app admin or a platform admin can change audit event types', 403, 'FORBIDDEN');
  }
}

router.post('/apps/:slug/audit-events/types', requireAuth, requireAppAccess, (req, res) => {
  canManageTypes(req);
  const { action, description } = req.body || {};
  if (!validAction(action)) throw new AppError('action must look like "invoice.paid": lower-case words joined by dots, at most 64 characters', 400, 'VALIDATION');
  if (description != null && (typeof description !== 'string' || description.length > LIMITS.descriptionMax)) {
    throw new AppError(`description must be a string of at most ${LIMITS.descriptionMax} characters`, 400, 'VALIDATION');
  }
  const db = getDb();
  const r = db.prepare('INSERT OR IGNORE INTO app_audit_event_types (app_id, action, description, created_by) VALUES (?, ?, ?, ?)')
    .run(req.app.id, action, description || null, req.user.id);
  if (!r.changes) throw new AppError(`${action} is already registered`, 409, 'EXISTS');
  logAudit(req.user.id, req.app.id, 'app-audit-type-create', { action });
  res.status(201).json({ types: listEventTypes(req.app.id) });
});

router.delete('/apps/:slug/audit-events/types/:id', requireAuth, requireAppAccess, (req, res) => {
  canManageTypes(req);
  const db = getDb();
  const row = db.prepare('SELECT * FROM app_audit_event_types WHERE id = ? AND app_id = ?').get(Number(req.params.id), req.app.id);
  if (!row) throw new AppError('Event type not found', 404, 'NOT_FOUND');
  db.prepare('DELETE FROM app_audit_event_types WHERE id = ?').run(row.id);
  logAudit(req.user.id, req.app.id, 'app-audit-type-delete', { action: row.action });
  res.json({ types: listEventTypes(req.app.id) });
});

router.put('/apps/:slug/audit-events/settings', requireAuth, requireAppAccess, (req, res) => {
  if (!isAppOwnerOrPlatformAdmin(req.user, req.app)) throw new AppError('Only the app owner or a platform admin can change this', 403, 'FORBIDDEN');
  const v = req.body?.allow_unregistered;
  if (typeof v !== 'boolean') throw new AppError('allow_unregistered must be true or false', 400, 'VALIDATION');
  const settings = setAppAuditSettings(req.app.id, { allow_unregistered: v }, req.user.id);
  logAudit(req.user.id, req.app.id, 'app-audit-settings', settings);
  res.json({ settings });
});

// ── per app: owner streams ───────────────────────────────────────────────

function canManageStreams(req) {
  if (!isAppOwnerOrPlatformAdmin(req.user, req.app)) {
    throw new AppError('Audit streams are managed by the app owner or a platform admin', 403, 'FORBIDDEN');
  }
}

function streamOr404(req) {
  const row = getStreamRow(req.app.id, req.params.id);
  if (!row) throw new AppError('Stream not found', 404, 'NOT_FOUND');
  return row;
}

const streamDetail = (row, extra = {}) => ({ stream_id: row.id, name: row.name, type: row.type, preset: row.preset, ...extra });

router.get('/apps/:slug/audit-streams', requireAuth, requireAppAccess, (req, res) => {
  canManageStreams(req);
  res.json({
    streams: listStreamRows(req.app.id).map(maskStream), policy: platformPolicy(),
    options: {
      presets: Object.fromEntries(Object.entries(HTTPS_PRESETS).map(([k, v]) => [k, { label: v.label, secrets: v.secrets }])),
      s3_secrets: secretKeysFor('s3'),
    },
  });
});

router.post('/apps/:slug/audit-streams', requireAuth, requireAppAccess, async (req, res) => {
  canManageStreams(req);
  let id;
  try {
    const values = await validateStream(req.body);
    id = insertStream(req.app.id, values, { userId: req.user.id, startFrom: req.body?.start_from === 'all' ? 'all' : 'now' });
  } catch (e) { throw rethrow(e); }
  const row = getStreamRow(req.app.id, id);
  logAudit(req.user.id, req.app.id, 'app-audit-stream-create', streamDetail(row));
  res.status(201).json({ stream: maskStream(row) });
});

router.put('/apps/:slug/audit-streams/:id', requireAuth, requireAppAccess, async (req, res) => {
  canManageStreams(req);
  const current = streamOr404(req);
  try { updateStream(current.id, await validateStream(req.body, current)); } catch (e) { throw rethrow(e); }
  const row = getStreamRow(req.app.id, current.id);
  logAudit(req.user.id, req.app.id, 'app-audit-stream-update', streamDetail(row, {
    fields: Object.keys(req.body || {}).filter(k => k !== 'secrets'), secrets_changed: Object.keys(req.body?.secrets || {}),
  }));
  res.json({ stream: maskStream(row) });
});

router.delete('/apps/:slug/audit-streams/:id', requireAuth, requireAppAccess, (req, res) => {
  canManageStreams(req);
  const row = streamOr404(req);
  deleteStream(row.id);
  logAudit(req.user.id, req.app.id, 'app-audit-stream-delete', streamDetail(row));
  res.json({ deleted: true });
});

router.post('/apps/:slug/audit-streams/:id/test', requireAuth, requireAppAccess, async (req, res) => {
  canManageStreams(req);
  const row = streamOr404(req);
  if (!platformPolicy().owner_streams_enabled) throw new AppError('A platform admin has turned off app audit streams', 403, 'OWNER_STREAMS_DISABLED');
  try {
    const r = await sendStreamTest({ ...row, app_slug: req.app.slug });
    logAudit(req.user.id, req.app.id, 'app-audit-stream-test', streamDetail(row, { ok: true }));
    res.json({ ok: true, ...r });
  } catch (e) {
    logAudit(req.user.id, req.app.id, 'app-audit-stream-test', streamDetail(row, { ok: false }));
    res.json({ ok: false, error: sanitizeError(e) });
  }
});

router.post('/apps/:slug/audit-streams/:id/flush', requireAuth, requireAppAccess, async (req, res) => {
  canManageStreams(req);
  const row = streamOr404(req);
  try {
    const r = await deliverStream(row.id, { force: true });
    res.json({ ok: true, ...r, stream: maskStream(getStreamRow(req.app.id, row.id)) });
  } catch (e) {
    res.json({ ok: false, error: sanitizeError(e), stream: maskStream(getStreamRow(req.app.id, row.id)) });
  }
});

// ── platform ─────────────────────────────────────────────────────────────

router.get('/app-audit-events', requireAuth, requirePlatformAdmin, (req, res) => {
  try { res.json(listAppEvents(null, queryOf(req))); } catch (e) { throw rethrow(e); }
});

router.get('/app-audit-events/export', requireAuth, requirePlatformAdmin, (req, res) => {
  const q = queryOf(req);
  let out;
  try { out = sendExport(res, q, null, q.app || 'all-apps'); } catch (e) { throw rethrow(e); }
  logAudit(req.user.id, null, 'app-audit-events-export', { format: q.format === 'csv' ? 'csv' : 'json', count: out.count, app: q.app || null });
  out.send();
});

router.get('/app-audit/settings', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ retention_days: getAppAuditRetentionDays(), min_days: MIN_DAYS, max_days: MAX_DAYS, ...platformPolicy() });
});

router.put('/app-audit/settings', requireAuth, requirePlatformAdmin, requireStepUp('security_settings'), (req, res) => {
  const b = req.body || {};
  for (const k of ['owner_streams_enabled', 'owner_streams_private']) {
    if (b[k] !== undefined && typeof b[k] !== 'boolean') throw new AppError(`${k} must be true or false`, 400, 'VALIDATION');
  }
  if (b.retention_days !== undefined) {
    const d = validDays(b.retention_days);
    if (d == null) throw new AppError(`retention_days must be a whole number from ${MIN_DAYS} to ${MAX_DAYS}`, 400, 'VALIDATION');
    setAppAuditRetentionDays(d, req.user.id);
  }
  const policy = setPlatformPolicy(b, req.user.id);
  const out = { retention_days: getAppAuditRetentionDays(), ...policy };
  logAudit(req.user.id, null, 'app-audit-settings', out);
  res.json(out);
});

export default router;
