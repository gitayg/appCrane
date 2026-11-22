import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { getDb } from '../db.js';
import { listOrphanedApps } from '../services/appOwnership.js';
import {
  ownershipOf, nominateOwner, decideTransfer, cancelTransfer, assignOwner, transfersForNominee,
} from '../services/appOwnerTransfers.js';

// Required owner, orphaned apps and ownership transfer. Mounted at /api; auth
// is per route. Who may do what is decided in services/appOwnerTransfers.js.
const router = Router();

/** GET /api/apps/:slug/ownership — active owners, orphan state and the pending nomination. Any member. */
router.get('/apps/:slug/ownership', requireAuth, requireAppAccess, (req, res) => {
  res.json(ownershipOf(getDb(), req.app, req.user));
});

/** POST /api/apps/:slug/owner-transfers — nominate a new owner. Body: { user_id | email, step_down?, note? } */
router.post('/apps/:slug/owner-transfers', requireAuth, requireAppAccess, (req, res) => {
  res.status(201).json({ transfer: nominateOwner(getDb(), req.user, req.app, req.body || {}) });
});

/** POST /api/apps/:slug/owner-transfers/:id/cancel — withdraw a pending nomination. */
router.post('/apps/:slug/owner-transfers/:id/cancel', requireAuth, requireAppAccess, (req, res) => {
  res.json({ transfer: cancelTransfer(getDb(), req.user, req.app, req.params.id) });
});

/** POST /api/apps/:slug/owner — platform admin assigns an owner directly. Body: { user_id | email } */
router.post('/apps/:slug/owner', requireAuth, requirePlatformAdmin, requireAppAccess, (req, res) => {
  res.json(assignOwner(getDb(), req.user, req.app, req.body || {}));
});

/** GET /api/owner-transfers/mine — nominations waiting for the caller's answer. */
router.get('/owner-transfers/mine', requireAuth, (req, res) => {
  res.json({ transfers: transfersForNominee(getDb(), req.user.id) });
});

/** POST /api/owner-transfers/:id/accept — the nominee only. */
router.post('/owner-transfers/:id/accept', requireAuth, (req, res) => {
  res.json({ transfer: decideTransfer(getDb(), req.user, req.params.id, true) });
});

/** POST /api/owner-transfers/:id/decline — the nominee only. */
router.post('/owner-transfers/:id/decline', requireAuth, (req, res) => {
  res.json({ transfer: decideTransfer(getDb(), req.user, req.params.id, false) });
});

/** GET /api/admin/orphaned-apps — every app without an active owner, oldest first, with its age. */
router.get('/admin/orphaned-apps', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ apps: listOrphanedApps(getDb()) });
});

export default router;
