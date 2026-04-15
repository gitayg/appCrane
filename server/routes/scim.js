/**
 * SCIM 2.0 — User provisioning for Okta (and other IdPs).
 *
 * Supported endpoints:
 *   GET    /api/scim/v2/ServiceProviderConfig
 *   GET    /api/scim/v2/Schemas
 *   GET    /api/scim/v2/Users          (list + filter)
 *   POST   /api/scim/v2/Users          (create)
 *   GET    /api/scim/v2/Users/:id      (get)
 *   PUT    /api/scim/v2/Users/:id      (replace)
 *   PATCH  /api/scim/v2/Users/:id      (partial update — active flag, name, etc.)
 *   DELETE /api/scim/v2/Users/:id      (hard delete)
 *
 * Auth: Bearer token. Generate via POST /api/auth/scim/token (admin only).
 */

import { Router } from 'express';
import { timingSafeEqual } from 'crypto';
import { getDb } from '../db.js';
import { hashApiKey, generateApiKey, hashPassword } from '../services/encryption.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import log from '../utils/logger.js';

const router = Router();

const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_LIST_SCHEMA  = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
const SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

// ---------------------------------------------------------------------------
// Auth middleware — Bearer token verified against stored hash
// ---------------------------------------------------------------------------
function requireScimToken(req, res, next) {
  const auth  = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token) return res.status(401).type('json').json(scimError(401, 'Unauthorized'));

  const db  = getDb();
  const row = db.prepare("SELECT value FROM settings WHERE key = 'scim_token_hash'").get();
  const enabledRow = db.prepare("SELECT value FROM settings WHERE key = 'scim_enabled'").get();

  if (!enabledRow || enabledRow.value !== '1') {
    return res.status(403).type('json').json(scimError(403, 'SCIM provisioning is not enabled'));
  }
  const storedHash = row ? Buffer.from(row.value, 'utf8') : null;
  const tokenHash  = Buffer.from(hashApiKey(token), 'utf8');
  if (!row || !timingSafeEqual(storedHash, tokenHash)) {
    return res.status(401).type('json').json(scimError(401, 'Invalid SCIM token'));
  }
  next();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function scimError(status, detail) {
  return { schemas: [SCIM_ERROR_SCHEMA], status: String(status), detail };
}

function baseUrl(req) {
  return (process.env.CRANE_DOMAIN
    ? 'https://' + process.env.CRANE_DOMAIN
    : 'http://' + req.headers.host) + '/api/scim/v2';
}

function toScimUser(u, req) {
  const nameParts = (u.name || '').trim().split(/\s+/);
  const givenName  = nameParts[0] || '';
  const familyName = nameParts.slice(1).join(' ') || '';
  return {
    schemas:    [SCIM_USER_SCHEMA],
    id:         String(u.id),
    externalId: u.scim_external_id || undefined,
    userName:   u.email || u.username || String(u.id),
    name: {
      formatted:  u.name || '',
      givenName,
      familyName,
    },
    emails: u.email ? [{ value: u.email, primary: true, type: 'work' }] : [],
    active: u.active !== 0,
    meta: {
      resourceType:  'User',
      created:       u.created_at ? u.created_at.replace(' ', 'T') + 'Z' : undefined,
      lastModified:  u.created_at ? u.created_at.replace(' ', 'T') + 'Z' : undefined,
      location:      baseUrl(req) + '/Users/' + u.id,
    },
  };
}

// Minimal SCIM filter parser — handles what Okta actually sends:
//   userName eq "value"
//   externalId eq "value"
//   id eq "value"
function parseFilter(filter) {
  if (!filter) return null;
  const m = filter.match(/^(\w+)\s+eq\s+"([^"]*)"$/i);
  if (!m) return null;
  return { attr: m[1].toLowerCase(), value: m[2] };
}

function applyUpdateToUser(db, id, attrs) {
  const updates = [];
  const values  = [];

  if (attrs.name !== undefined) {
    const formatted = attrs.name.formatted
      || [attrs.name.givenName, attrs.name.familyName].filter(Boolean).join(' ')
      || '';
    if (formatted) { updates.push('name = ?'); values.push(formatted); }
  }
  if (attrs.userName !== undefined) {
    updates.push('email = ?'); values.push(attrs.userName);
  }
  if (attrs.emails !== undefined) {
    const primary = (attrs.emails || []).find(e => e.primary) || attrs.emails[0];
    if (primary?.value) { updates.push('email = ?'); values.push(primary.value); }
  }
  if (attrs.active !== undefined) {
    updates.push('active = ?'); values.push(attrs.active ? 1 : 0);
    // Expire sessions of deactivated users immediately
    if (!attrs.active) {
      db.prepare("DELETE FROM identity_sessions WHERE user_id = ?").run(id);
    }
  }
  if (attrs.externalId !== undefined) {
    updates.push('scim_external_id = ?'); values.push(attrs.externalId);
  }

  if (updates.length) {
    values.push(id);
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  }
}

// ---------------------------------------------------------------------------
// ServiceProviderConfig
// ---------------------------------------------------------------------------
router.get('/ServiceProviderConfig', requireScimToken, (req, res) => {
  res.json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    documentationUri: baseUrl(req).replace('/api/scim/v2', '/docs'),
    patch:  { supported: true },
    bulk:   { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort:   { supported: false },
    etag:   { supported: false },
    authenticationSchemes: [{
      type: 'oauthbearertoken',
      name: 'OAuth Bearer Token',
      description: 'Authentication scheme using the OAuth Bearer Token standard',
    }],
    meta: { resourceType: 'ServiceProviderConfig', location: baseUrl(req) + '/ServiceProviderConfig' },
  });
});

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
router.get('/Schemas', requireScimToken, (req, res) => {
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 1,
    Resources: [{
      id: SCIM_USER_SCHEMA,
      name: 'User',
      description: 'User Account',
      attributes: [
        { name: 'userName',  type: 'string',  required: true,  uniqueness: 'server' },
        { name: 'name',      type: 'complex', required: false },
        { name: 'emails',    type: 'complex', required: false, multiValued: true },
        { name: 'active',    type: 'boolean', required: false },
        { name: 'externalId', type: 'string', required: false },
      ],
    }],
  });
});

// ---------------------------------------------------------------------------
// GET /Users — list with optional filter + pagination
// ---------------------------------------------------------------------------
router.get('/Users', requireScimToken, (req, res) => {
  const db = getDb();
  const startIndex = Math.max(1, parseInt(req.query.startIndex) || 1);
  const count      = Math.min(200, Math.max(1, parseInt(req.query.count) || 100));
  const filter     = parseFilter(req.query.filter);

  let query  = "SELECT * FROM users WHERE role = 'user'";
  const args = [];

  if (filter) {
    if (filter.attr === 'username' || filter.attr === 'email') {
      query += ' AND (email = ? OR username = ?)'; args.push(filter.value, filter.value);
    } else if (filter.attr === 'externalid') {
      query += ' AND scim_external_id = ?'; args.push(filter.value);
    } else if (filter.attr === 'id') {
      query += ' AND id = ?'; args.push(parseInt(filter.value));
    }
  }

  const total = db.prepare(query.replace('SELECT *', 'SELECT COUNT(*) as n')).get(...args).n;
  const rows  = db.prepare(query + ' ORDER BY id LIMIT ? OFFSET ?').all(...args, count, startIndex - 1);

  res.json({
    schemas:      [SCIM_LIST_SCHEMA],
    totalResults: total,
    startIndex,
    itemsPerPage: rows.length,
    Resources:    rows.map(u => toScimUser(u, req)),
  });
});

// ---------------------------------------------------------------------------
// POST /Users — create user
// ---------------------------------------------------------------------------
router.post('/Users', requireScimToken, (req, res) => {
  const db   = getDb();
  const body = req.body;

  const email = (body.emails?.find(e => e.primary)?.value) || body.emails?.[0]?.value || body.userName;
  const name  = body.name?.formatted
    || [body.name?.givenName, body.name?.familyName].filter(Boolean).join(' ')
    || email;

  if (!email) return res.status(400).json(scimError(400, 'userName or emails required'));

  // Check for existing user by email or externalId
  const existing = db.prepare('SELECT * FROM users WHERE email = ? OR scim_external_id = ?').get(email, body.externalId || '');
  if (existing) {
    // Idempotent — return existing user (Okta may retry)
    return res.status(409).json(scimError(409, 'User already exists'));
  }

  const apiKey  = generateApiKey('dhk_user');
  const keyHash = hashApiKey(apiKey);
  const active  = body.active !== false ? 1 : 0;

  const result = db.prepare(`
    INSERT INTO users (name, email, role, api_key_hash, active, scim_external_id, created_at)
    VALUES (?, ?, 'user', ?, ?, ?, datetime('now'))
  `).run(name, email, keyHash, active, body.externalId || null);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  log.info(`SCIM: created user "${name}" (${email})`);
  res.status(201).json(toScimUser(user, req));
});

// ---------------------------------------------------------------------------
// GET /Users/:id
// ---------------------------------------------------------------------------
router.get('/Users/:id', requireScimToken, (req, res) => {
  const db   = getDb();
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'user'").get(parseInt(req.params.id));
  if (!user) return res.status(404).json(scimError(404, 'User not found'));
  res.json(toScimUser(user, req));
});

// ---------------------------------------------------------------------------
// PUT /Users/:id — full replace
// ---------------------------------------------------------------------------
router.put('/Users/:id', requireScimToken, (req, res) => {
  const db   = getDb();
  const id   = parseInt(req.params.id);
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'user'").get(id);
  if (!user) return res.status(404).json(scimError(404, 'User not found'));

  applyUpdateToUser(db, id, req.body);
  if (req.body.externalId) {
    db.prepare('UPDATE users SET scim_external_id = ? WHERE id = ?').run(req.body.externalId, id);
  }

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  log.info(`SCIM: replaced user ${id}`);
  res.json(toScimUser(updated, req));
});

// ---------------------------------------------------------------------------
// PATCH /Users/:id — partial update (Okta uses this for activate/deactivate)
// ---------------------------------------------------------------------------
router.patch('/Users/:id', requireScimToken, (req, res) => {
  const db   = getDb();
  const id   = parseInt(req.params.id);
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'user'").get(id);
  if (!user) return res.status(404).json(scimError(404, 'User not found'));

  const ops = req.body?.Operations || [];
  for (const op of ops) {
    const action = (op.op || '').toLowerCase();
    if (action === 'replace' || action === 'add') {
      // op.path = 'active', op.value = false  (deactivate)
      // op.path = null, op.value = { active: false, name: {...} }  (bulk replace)
      if (op.path) {
        const attr = op.path.toLowerCase();
        const patch = {};
        if (attr === 'active')   patch.active   = op.value;
        if (attr === 'username') patch.userName  = op.value;
        if (attr === 'name')     patch.name      = op.value;
        if (attr === 'emails')   patch.emails    = op.value;
        applyUpdateToUser(db, id, patch);
      } else if (op.value && typeof op.value === 'object') {
        applyUpdateToUser(db, id, op.value);
      }
    }
  }

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  log.info(`SCIM: patched user ${id}`);
  res.json(toScimUser(updated, req));
});

// ---------------------------------------------------------------------------
// DELETE /Users/:id — hard delete
// ---------------------------------------------------------------------------
router.delete('/Users/:id', requireScimToken, (req, res) => {
  const db   = getDb();
  const id   = parseInt(req.params.id);
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'user'").get(id);
  if (!user) return res.status(404).json(scimError(404, 'User not found'));

  db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  log.info(`SCIM: deleted user ${id} (${user.email})`);
  res.status(204).send();
});

// ---------------------------------------------------------------------------
// Admin token management — mounted separately at /api/auth/scim/token
// ---------------------------------------------------------------------------
export const scimAdminRouter = Router();

/**
 * POST /api/auth/scim/token — generate a new SCIM bearer token (admin only)
 * Returns the plaintext token ONCE — it is never stored.
 */
scimAdminRouter.post('/token', requireAuth, requireAdmin, (req, res) => {
  const db    = getDb();
  const token = generateApiKey('scim');
  const hash  = hashApiKey(token);
  const save  = (k, v) => db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(k, String(v), req.user.id);

  save('scim_token_hash', hash);
  save('scim_token_created_at', new Date().toISOString());
  log.info(`SCIM: new token generated by admin ${req.user.id}`);
  res.json({ token, message: 'Copy this token — it will not be shown again.' });
});

/**
 * PUT /api/auth/scim/config — enable/disable SCIM (admin only)
 */
scimAdminRouter.put('/config', requireAuth, requireAdmin, (req, res) => {
  const { enabled } = req.body || {};
  const db = getDb();
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run('scim_enabled', enabled ? '1' : '0', req.user.id);
  res.json({ message: 'SCIM settings saved' });
});

/**
 * GET /api/auth/scim/config — admin: current SCIM state
 */
scimAdminRouter.get('/config', requireAuth, requireAdmin, (req, res) => {
  const db = getDb();
  const rows = db.prepare("SELECT key, value FROM settings WHERE key LIKE 'scim_%' AND key != 'scim_token_hash'").all();
  const cfg  = Object.fromEntries(rows.map(r => [r.key, r.value]));
  res.json({
    enabled:          cfg.scim_enabled === '1',
    token_created_at: cfg.scim_token_created_at || null,
    base_url:         (process.env.CRANE_DOMAIN ? 'https://' + process.env.CRANE_DOMAIN : 'http://localhost:' + (process.env.PORT || 5001)) + '/api/scim/v2',
  });
});

export default router;
