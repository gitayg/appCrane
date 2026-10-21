import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { sanitizeError } from '../services/jobHealth.js';
import { HTTPS_PRESETS } from '../services/siem/https.js';
import { getAllowlist, setAllowlist } from '../services/siem/netGuard.js';
import {
  SINK_TYPES, FORMATS, SEVERITIES, DEFAULTS, secretKeysFor, maskSink, getSinkRow, listSinkRows,
  validateSink, insertSink, updateSink, deleteSink, setCursor,
} from '../services/siem/store.js';
import { deliverSink, sendTestEvent, sinkHealth, unregisterJob, tickSink } from '../services/siem/delivery.js';

// SIEM and log streaming (Settings > Security). Platform admin only. Mounted at
// /api/settings, where GETs are public at the global gate, so every route here
// carries its own auth through the path-scoped router.use below.

const router = Router();
router.use('/siem', requireAuth, requirePlatformAdmin);

function toAppError(e) {
  if (e instanceof AppError) return e;
  if (e?.status === 400) return new AppError(e.message, 400, e.code || 'VALIDATION');
  return e;
}

function sinkOr404(id) {
  const row = /^\d+$/.test(String(id)) ? getSinkRow(Number(id)) : null;
  if (!row) throw new AppError('Sink not found', 404, 'NOT_FOUND');
  return row;
}

function view(row) {
  return { ...maskSink(row), health: sinkHealth(row) };
}

function auditDetail(row, extra = {}) {
  return { sink_id: row.id, name: row.name, type: row.type, preset: row.preset, ...extra };
}

router.get('/siem', (req, res) => {
  res.json({
    sinks: listSinkRows().map(view),
    private_allowlist: getAllowlist(),
    options: {
      types: SINK_TYPES, formats: FORMATS, severities: SEVERITIES, defaults: DEFAULTS,
      presets: Object.fromEntries(Object.entries(HTTPS_PRESETS).map(([k, v]) => [k, { label: v.label, secrets: v.secrets }])),
      s3_secrets: secretKeysFor('s3'),
    },
  });
});

router.put('/siem/network', (req, res) => {
  let list;
  try { list = setAllowlist(req.body?.private_allowlist, req.user.id); } catch (e) { throw new AppError(e.message, 400, 'VALIDATION'); }
  logAudit(req.user.id, null, 'siem.private-allowlist', { private_allowlist: list });
  res.json({ private_allowlist: list });
});

router.post('/siem', (req, res) => {
  let values;
  try { values = validateSink(req.body); } catch (e) { throw toAppError(e); }
  const startFrom = req.body?.start_from === 'all' ? 'all' : 'now';
  const id = insertSink(values, { userId: req.user.id, startFrom });
  const row = getSinkRow(id);
  logAudit(req.user.id, null, 'siem.sink-create', auditDetail(row, { start_from: startFrom }));
  if (row.tls_skip_verify) logAudit(req.user.id, null, 'siem.tls-verify-disabled', auditDetail(row));
  res.status(201).json({ sink: view(row) });
});

router.put('/siem/:id', (req, res) => {
  const current = sinkOr404(req.params.id);
  let values;
  try { values = validateSink(req.body, current); } catch (e) { throw toAppError(e); }
  updateSink(current.id, values);
  const row = getSinkRow(current.id);
  logAudit(req.user.id, null, 'siem.sink-update', auditDetail(row, {
    fields: Object.keys(req.body || {}).filter(k => k !== 'secrets'),
    secrets_changed: Object.keys(req.body?.secrets || {}),
  }));
  if (row.tls_skip_verify !== current.tls_skip_verify) {
    logAudit(req.user.id, null, row.tls_skip_verify ? 'siem.tls-verify-disabled' : 'siem.tls-verify-enabled', auditDetail(row));
  }
  res.json({ sink: view(row) });
});

router.delete('/siem/:id', (req, res) => {
  const row = sinkOr404(req.params.id);
  deleteSink(row.id);
  unregisterJob(row.id);
  logAudit(req.user.id, null, 'siem.sink-delete', auditDetail(row));
  res.json({ deleted: true });
});

router.post('/siem/:id/test', async (req, res) => {
  const row = sinkOr404(req.params.id);
  try {
    const r = await sendTestEvent(row.id);
    logAudit(req.user.id, null, 'siem.sink-test', auditDetail(row, { ok: true }));
    res.json({ ok: true, ...r });
  } catch (e) {
    logAudit(req.user.id, null, 'siem.sink-test', auditDetail(row, { ok: false }));
    res.json({ ok: false, error: sanitizeError(e) });
  }
});

router.post('/siem/:id/cursor', (req, res) => {
  const row = sinkOr404(req.params.id);
  let cursor;
  try { cursor = setCursor(row.id, req.body?.to); } catch (e) { throw toAppError(e); }
  logAudit(req.user.id, null, 'siem.sink-cursor', auditDetail(row, { to: req.body?.to, cursor }));
  res.json({ sink: view(getSinkRow(row.id)) });
});

router.post('/siem/:id/flush', async (req, res) => {
  const row = sinkOr404(req.params.id);
  try {
    const r = await deliverSink(row.id, { force: true });
    await tickSink(getSinkRow(row.id)).catch(() => {});
    res.json({ ok: true, ...r, sink: view(getSinkRow(row.id)) });
  } catch (e) {
    res.json({ ok: false, error: sanitizeError(e), sink: view(getSinkRow(row.id)) });
  }
});

export default router;
