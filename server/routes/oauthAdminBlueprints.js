import { Router } from 'express';
import { requireStepUp } from '../services/stepUp.js';
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { listBlueprints, createBlueprint, updateBlueprint, deleteBlueprint, getBlueprint } from '../services/mcpBlueprints.js';
import { ALL_SCOPES, TOOL_SCOPES, scopeGroups } from '../services/mcpScopes.js';

// MCP scope blueprints, platform admin only: mounted by oauthAdmin.js under
// /api/oauth/admin, behind its requirePlatformAdmin and oauthConsent.js's
// refusal of MCP credentials.
const router = Router();

const audit = (req, action, detail) => { try { logAudit(req.user.id, null, action, detail); } catch (_) {} };
const idParam = (v) => {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n) || n <= 0 || String(n) !== String(v)) throw new AppError('Invalid blueprint id', 400, 'VALIDATION');
  return n;
};
const asAppError = (e) => (e.status === 400 || e.status === 409 ? new AppError(e.message, e.status, e.status === 409 ? 'CONFLICT' : 'VALIDATION') : e);

router.get('/blueprints', (req, res) => {
  res.json({ blueprints: listBlueprints(), scopes: ALL_SCOPES, scope_groups: scopeGroups(), tool_scopes: TOOL_SCOPES });
});

router.post('/blueprints', requireStepUp('security_settings'), (req, res) => {
  let bp;
  try { bp = createBlueprint(req.body, req.user.id); } catch (e) { throw asAppError(e); }
  audit(req, 'mcp-blueprint-created', { id: bp.id, name: bp.name, scopes: bp.scopes, apps: bp.apps });
  res.status(201).json({ blueprint: bp });
});

router.patch('/blueprints/:id', requireStepUp('security_settings'), (req, res) => {
  const id = idParam(req.params.id);
  let bp;
  try { bp = updateBlueprint(id, req.body); } catch (e) { throw asAppError(e); }
  if (!bp) throw new AppError('Blueprint not found', 404, 'NOT_FOUND');
  audit(req, 'mcp-blueprint-updated', { id, scopes: bp.scopes, apps: bp.apps });
  res.json({ blueprint: bp });
});

router.delete('/blueprints/:id', (req, res) => {
  const id = idParam(req.params.id);
  let bp;
  try { bp = deleteBlueprint(id); } catch (e) { throw asAppError(e); }
  if (!bp) throw new AppError('Blueprint not found', 404, 'NOT_FOUND');
  audit(req, 'mcp-blueprint-deleted', { id, name: bp.name });
  res.json({ message: 'Blueprint deleted; credentials issued under it can no longer call any tool', id });
});

// Pin a blueprint to a client: every new connection of that client gets it,
// whatever the consenting user picks, and an ID-JAG client must have one.
router.put('/clients/:clientId/blueprint', requireStepUp('security_settings'), (req, res) => {
  const { blueprint_id } = req.body || {};
  if (blueprint_id !== null && (!Number.isInteger(blueprint_id) || !getBlueprint(blueprint_id))) {
    throw new AppError('blueprint_id must be the id of an existing blueprint, or null', 400, 'VALIDATION');
  }
  const clientId = String(req.params.clientId);
  const r = getDb().prepare('UPDATE oauth_clients SET blueprint_id = ? WHERE client_id = ?').run(blueprint_id, clientId);
  if (!r.changes) throw new AppError('Client not found', 404, 'NOT_FOUND');
  audit(req, 'oauth-client-blueprint-set', { client_id: clientId, blueprint_id });
  res.json({ client_id: clientId, blueprint_id });
});

export default router;
