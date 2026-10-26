import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import {
  getPolicy, setPolicy, createCampaign, getCampaign, listCampaigns, closeCampaign,
  decide, campaignReport, campaignCsv, reviewsForUser, reviewDetail, LEVELS, OVERDUE_ACTIONS,
} from '../services/accessReviews/index.js';
import { campaignReviews } from '../services/accessReviews/queries.js';

// Periodic access reviews. Mounted at '/api'; every route carries its own
// requireAuth. Reviewers (an app's owners, platform admins for the platform
// review) decide; platform admins run campaigns and read every report.

const router = Router();

const idOf = (v) => {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) throw new AppError('Not found', 404, 'NOT_FOUND');
  return n;
};
const queryOf = (req) => Object.fromEntries(new URL(req.originalUrl || req.url, 'http://local').searchParams);

router.get('/access-reviews/mine', requireAuth, (req, res) => {
  res.json({ reviews: reviewsForUser(getDb(), req.user) });
});

router.get('/access-reviews/reviews/:id', requireAuth, (req, res) => {
  res.json({ review: reviewDetail(getDb(), idOf(req.params.id), req.user) });
});

router.post('/access-reviews/items/:id/decision', requireAuth, async (req, res) => {
  const { decision, new_role = null, note = null } = req.body || {};
  const item = await decide(getDb(), { itemId: idOf(req.params.id), user: req.user, decision, newRole: new_role, note });
  res.json({ item });
});

router.get('/access-reviews/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ policy: getPolicy(getDb()), levels: LEVELS, overdue_actions: OVERDUE_ACTIONS });
});

router.put('/access-reviews/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  const policy = setPolicy(getDb(), req.body, req.user.id);
  logAudit(req.user.id, null, 'access-review-policy-change', { policy });
  res.json({ policy });
});

router.get('/access-reviews/campaigns', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ campaigns: listCampaigns(getDb()) });
});

router.post('/access-reviews/campaigns', requireAuth, requirePlatformAdmin, (req, res) => {
  const { scope = 'default', due_days = null } = req.body || {};
  const campaign = createCampaign(getDb(), { scope, createdBy: req.user.id, dueDays: due_days == null ? null : Number(due_days) });
  res.status(201).json({ campaign });
});

router.get('/access-reviews/campaigns/:id', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const campaign = getCampaign(db, idOf(req.params.id));
  if (!campaign) throw new AppError('Campaign not found', 404, 'NOT_FOUND');
  res.json({ campaign, reviews: campaignReviews(db, campaign.id, req.user) });
});

router.post('/access-reviews/campaigns/:id/close', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ campaign: closeCampaign(getDb(), idOf(req.params.id), { userId: req.user.id, reason: 'manual' }) });
});

router.get('/access-reviews/campaigns/:id/report', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const id = idOf(req.params.id);
  const format = queryOf(req).format === 'csv' ? 'csv' : 'json';
  const report = format === 'csv' ? campaignCsv(db, id) : campaignReport(db, id);
  if (!report) throw new AppError('Campaign not found', 404, 'NOT_FOUND');
  logAudit(req.user.id, null, 'access-review-report-export', { campaign_id: id, format });
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="access-review-${id}.csv"`);
    return res.send(report);
  }
  res.setHeader('Content-Disposition', `attachment; filename="access-review-${id}.json"`);
  res.json(report);
});

export default router;
