import { Router } from 'express';
import { requireAuth, requireAppUser } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { roleForUserOnApp } from '../services/permissions.js';
import {
  listRoles, createRole, updateRole, deleteRole,
  listMembersWithRoles, setUserRoleKeys,
} from '../services/appDefinedRoles.js';

const router = Router();

/**
 * App-defined roles — CRUD for the vocabulary an app invents for itself, plus
 * the grants that say who holds what. AppCrane stores and issues these; it
 * never reads them back when deciding anything about AppCrane. See
 * services/appDefinedRoles.js for why that separation is absolute.
 *
 * Mounted at /api/apps, so the paths are /api/apps/:slug/app-roles*. NOT
 * `/roles` — that is taken by users.js and sets AppCrane's own per-app tier.
 * The two must not look alike in the URL space either.
 *
 * No pathless `router.use(requireAuth)`: this router sits at the shared
 * '/api/apps' mount point, and a router-level guard there 401s every request
 * that merely passes through on its way to another router. Auth is per-route.
 */

/**
 * READ is gated by requireAppUser, not requireAppAccess.
 *
 * requireAppAccess would additionally admit any global admin who is NOT
 * assigned to the app. That is the wider surface and the wrong one here: a role
 * roster answers "who is an approver in someone else's HR app", which is
 * app-internal policy data, not platform metadata. v2.39.0 deliberately made
 * assignment authoritative for every role including platform_admin, so that
 * reaching into a specific app's data is a deliberate, audited act rather than
 * an invisible ambient capability. Route around it and this endpoint becomes
 * the read hole that fix just closed. A platform admin who needs this assigns
 * themselves through the normal (admin-gated, audited) member route.
 *
 * WRITE additionally requires the app's own owner or admin tier
 * (requireAppRoleAdmin). A plain member must not be able to invent a role or
 * grant themselves one — inventing roles is authoring the app's permission
 * model, and self-granting is the escalation this feature has to make
 * impossible.
 *
 * The guards are repeated inline on every route rather than hoisted into shared
 * arrays: scripts/check-route-authz.mjs reads the route declaration to prove
 * each app-scoped path is guarded, and an array indirection makes that watchdog
 * blind exactly where it is meant to see.
 */

/**
 * roleForUserOnApp deliberately does not map AppCrane global admins to a
 * per-app tier, so an unassigned platform admin gets no implicit write here.
 * That matches the feature's own rule: platform_admin holds no app-defined role
 * unless someone granted it explicitly.
 */
function requireAppRoleAdmin(req, _res, next) {
  const tier = roleForUserOnApp(req.user, req.app);
  if (tier !== 'owner' && tier !== 'admin') {
    return next(new AppError(
      'Only an owner or admin of this app can manage its app-defined roles.',
      403, 'FORBIDDEN',
    ));
  }
  next();
}

/** GET /api/apps/:slug/app-roles — roles this app defines + how many hold each. */
router.get('/:slug/app-roles', requireAuth, requireAppUser, (req, res) => {
  res.json({ app: req.app.slug, roles: listRoles(req.app.id) });
});

/** GET /api/apps/:slug/app-roles/members — members with the keys they hold. */
router.get('/:slug/app-roles/members', requireAuth, requireAppUser, (req, res) => {
  res.json({ app: req.app.slug, members: listMembersWithRoles(req.app.id) });
});

/** POST /api/apps/:slug/app-roles — create { key, label, description }. */
router.post('/:slug/app-roles', requireAuth, requireAppUser, requireAppRoleAdmin, auditMiddleware('app-defined-role-create'), (req, res) => {
  const { key, label, description } = req.body || {};
  const role = createRole(req.app.id, { key, label, description }, req.user.id);
  res.status(201).json({ role });
});

/** PATCH /api/apps/:slug/app-roles/:id — update { label, description }; key is immutable. */
router.patch('/:slug/app-roles/:id', requireAuth, requireAppUser, requireAppRoleAdmin, auditMiddleware('app-defined-role-update'), (req, res) => {
  const { label, description, key } = req.body || {};
  if (key !== undefined) {
    throw new AppError(
      'A role key cannot be changed — the app compares against it. Delete the role and create a new one.',
      400, 'KEY_IMMUTABLE',
    );
  }
  const role = updateRole(req.app.id, parseInt(req.params.id, 10), { label, description });
  res.json({ role });
});

/** DELETE /api/apps/:slug/app-roles/:id — deletes the role and cascades its grants. */
router.delete('/:slug/app-roles/:id', requireAuth, requireAppUser, requireAppRoleAdmin, auditMiddleware('app-defined-role-delete'), (req, res) => {
  const { role, grants_removed } = deleteRole(req.app.id, parseInt(req.params.id, 10));
  res.json({
    message: `Role '${role.key}' deleted`,
    key: role.key,
    grants_removed,
  });
});

/** PUT /api/apps/:slug/app-roles/members/:userId — replace that user's whole set. */
router.put('/:slug/app-roles/members/:userId', requireAuth, requireAppUser, requireAppRoleAdmin, auditMiddleware('app-defined-role-grant'), (req, res) => {
  const { keys } = req.body || {};
  const userId = parseInt(req.params.userId, 10);
  const app_roles = setUserRoleKeys(req.app.id, userId, keys, req.user.id);
  res.json({ user_id: userId, app_roles });
});

export default router;
