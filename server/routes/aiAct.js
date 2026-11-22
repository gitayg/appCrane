import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { intakeGate } from '../services/appIntake.js';
import { getAiProfile, setAiUse, AI_USES, ANNEX_III_CATEGORIES, AI_USE_GUIDANCE } from '../services/aiAct/classification.js';
import { statement, acknowledgement, acknowledge } from '../services/aiAct/literacy.js';
import { getNotice, setNotice, MAX_NOTICE_LENGTH, DEFAULT_NOTICE_TEXT } from '../services/aiAct/transparency.js';
import { retentionPolicy, setConfiguredDays, appRetention } from '../services/aiAct/retention.js';
import { aiInventory, aiInventoryCsv } from '../services/aiAct/inventory.js';

// EU AI Act deployer records (services/aiAct/*). Mounted at /api; auth is per
// route so unmatched /api traffic passes through to the other routers.

const router = Router();

function requireOwnerOrPlatformAdmin(req, _res, next) {
  if (isPlatformAdmin(req.user) || roleForUserOnApp(req.user, req.app) === 'owner') return next();
  next(new AppError('Only the app owner or a platform admin can change this', 403, 'FORBIDDEN'));
}

export function sendAckRequired(res, e) {
  if (e?.code !== 'AI_LITERACY_ACK_REQUIRED') throw e;
  res.status(409).json({ error: { code: e.code, message: e.message, statement: e.details?.statement || statement() } });
}

const literacyView = (db, user) => {
  const ack = acknowledgement(db, user.id);
  return { statement: statement(), acknowledged: !!ack, acknowledged_at: ack?.acknowledged_at ?? null };
};

/** GET /api/ai-act/literacy — the current statement and whether the caller acknowledged it. */
router.get('/ai-act/literacy', requireAuth, (req, res) => {
  res.json(literacyView(getDb(), req.user));
});

/** POST /api/ai-act/literacy/acknowledge — { version }. */
router.post('/ai-act/literacy/acknowledge', requireAuth, (req, res) => {
  const db = getDb();
  const ack = acknowledge(db, req.user, req.body?.version);
  res.status(ack.created ? 201 : 200).json({ ...literacyView(db, req.user), created: ack.created });
});

/** GET /api/ai-act/inventory — every app using AI (platform admin). ?format=csv for the export. */
router.get('/ai-act/inventory', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  if (new URL(req.originalUrl, 'http://local').searchParams.get('format') === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="ai-inventory-${new Date().toISOString().slice(0, 10)}.csv"`);
    return res.send(aiInventoryCsv(db));
  }
  res.json(aiInventory(db));
});

/** GET /api/ai-act/retention — the LLM gateway log retention and the AI floor. */
router.get('/ai-act/retention', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(retentionPolicy(getDb()));
});

/** PUT /api/ai-act/retention — { days }. The floor for AI apps still applies. */
router.put('/ai-act/retention', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(setConfiguredDays(req.body?.days, req.user, getDb()));
});

function appView(db, req) {
  return {
    app: req.app.slug,
    ai: getAiProfile(db, req.app.id),
    options: { ai_uses: AI_USES, annex_iii_categories: ANNEX_III_CATEGORIES, guidance: AI_USE_GUIDANCE },
    notice: { ...getNotice(db, req.app.id), default_text: DEFAULT_NOTICE_TEXT, max_length: MAX_NOTICE_LENGTH },
    retention: appRetention(db, req.app.id),
    gate: intakeGate(db, req.app),
    literacy: literacyView(db, req.user),
    can_edit: isPlatformAdmin(req.user) || roleForUserOnApp(req.user, req.app) === 'owner',
  };
}

/** GET /api/apps/:slug/ai-act — the app's AI use, notice, effective log retention and gate. */
router.get('/apps/:slug/ai-act', requireAuth, requireAppAccess, (req, res) => {
  res.json(appView(getDb(), req));
});

/** PUT /api/apps/:slug/ai-use — { ai_use, annex_iii_category? }. Owner or platform admin. */
router.put('/apps/:slug/ai-use', requireAuth, requireAppAccess, requireOwnerOrPlatformAdmin, (req, res) => {
  const db = getDb();
  let out;
  try { out = setAiUse(db, req.app, req.body || {}, req.user); } catch (e) { return sendAckRequired(res, e); }
  res.json({ ...appView(db, req), changed: out.changed, intake_back_to_review: !!out.intake_back_to_review });
});

/** PUT /api/apps/:slug/ai-notice — { enabled, text? }. Owner or platform admin. */
router.put('/apps/:slug/ai-notice', requireAuth, requireAppAccess, requireOwnerOrPlatformAdmin, (req, res) => {
  const db = getDb();
  setNotice(db, req.app, req.body || {}, req.user);
  res.json({ ...appView(db, req), redeploy_needed_for_env: true });
});

export default router;
