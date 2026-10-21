import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { submitIntake, getIntake, intakeGate, reviewIntake, listIntake } from '../services/appIntake.js';
import { getClassification, setClassification, getClassificationPolicy, setClassificationPolicy, LEVELS } from '../services/dataClassification.js';

const router = Router();

// App intake and data classification. Mounted at /api; auth is per route so
// unmatched /api traffic passes through to the other routers.

function requireOwnerOrPlatformAdmin(req, _res, next) {
  if (isPlatformAdmin(req.user) || roleForUserOnApp(req.user, req.app) === 'owner') return next();
  next(new AppError('Only the app owner or a platform admin can change the intake', 403, 'FORBIDDEN'));
}

function requirePlatformAdminHere(req, _res, next) {
  if (req.user.role !== 'platform_admin') return next(new AppError('Platform admins only', 403, 'FORBIDDEN'));
  next();
}

/** GET /api/data-classification/policy — levels and the policy each carries. */
router.get('/data-classification/policy', requireAuth, (req, res) => {
  res.json({ levels: LEVELS, policy: getClassificationPolicy(getDb()) });
});

/** PUT /api/data-classification/policy — partial update, platform admin. */
router.put('/data-classification/policy', requireAuth, requirePlatformAdminHere, (req, res) => {
  res.json({ levels: LEVELS, policy: setClassificationPolicy(getDb(), req.body, req.user) });
});

/** GET /api/data-classification/apps — { [slug]: level } for the apps the caller can see (Launch tile badges). */
router.get('/data-classification/apps', requireAuth, (req, res) => {
  const db = getDb();
  const rows = isPlatformAdmin(req.user)
    ? db.prepare("SELECT a.slug, COALESCE(i.data_classification, 'internal') AS level FROM apps a LEFT JOIN app_intake i ON i.app_id = a.id").all()
    : db.prepare(`SELECT a.slug, COALESCE(i.data_classification, 'internal') AS level FROM apps a
        JOIN app_users au ON au.app_id = a.id AND au.user_id = ? LEFT JOIN app_intake i ON i.app_id = a.id`).all(req.user.id);
  res.json({ levels: Object.fromEntries(rows.map((r) => [r.slug, r.level])) });
});

/** GET /api/intake/queue?status=pending|approved|rejected|all — the approver queue. */
router.get('/intake/queue', requireAuth, requirePlatformAdminHere, (req, res) => {
  const status = ['pending', 'approved', 'rejected', 'all'].includes(req.query.status) ? req.query.status : 'pending';
  res.json({ status, items: listIntake(getDb(), { status }) });
});

/** GET /api/apps/:slug/intake — the intake, the classification and whether production is open. */
router.get('/apps/:slug/intake', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  res.json({
    intake: getIntake(db, req.app.id),
    classification: getClassification(db, req.app.id),
    gate: intakeGate(db, req.app),
    can_edit: isPlatformAdmin(req.user) || roleForUserOnApp(req.user, req.app) === 'owner',
    can_review: isPlatformAdmin(req.user),
  });
});

/** PUT /api/apps/:slug/intake — submit or resubmit the intake form. */
router.put('/apps/:slug/intake', requireAuth, requireAppAccess, requireOwnerOrPlatformAdmin, (req, res) => {
  const db = getDb();
  const body = req.body || {};
  const current = getClassification(db, req.app.id);
  if (current.locked && !isPlatformAdmin(req.user) && body.data_classification && body.data_classification !== current.level) {
    throw new AppError('A platform admin set this classification; ask a platform admin to change it', 403, 'CLASSIFICATION_LOCKED');
  }
  const out = submitIntake(req.app, { ...body, data_classification: body.data_classification || current.level, owner: req.user.id, submitted_by: req.user.id, db });
  res.json({ ...out, intake: getIntake(db, req.app.id), gate: intakeGate(db, req.app) });
});

/** POST /api/apps/:slug/intake/review — { decision: 'approve'|'reject', comment }. Platform admin. */
router.post('/apps/:slug/intake/review', requireAuth, requireAppAccess, requirePlatformAdminHere, (req, res) => {
  const db = getDb();
  const intake = reviewIntake(db, req.app, req.body || {}, req.user);
  res.json({ intake, gate: intakeGate(db, req.app) });
});

/** PUT /api/apps/:slug/classification — { data_classification }. Owner (rules in dataClassification.js) or platform admin. */
router.put('/apps/:slug/classification', requireAuth, requireAppAccess, requireOwnerOrPlatformAdmin, (req, res) => {
  const db = getDb();
  const out = setClassification(db, req.app, req.body?.data_classification, req.user);
  res.json({ classification: out, gate: intakeGate(db, req.app) });
});

export default router;
