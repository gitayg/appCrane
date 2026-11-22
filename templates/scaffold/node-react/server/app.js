import express from 'express';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { verifyRequest, atLeast } from './identity.js';

// Paths served without a verified identity. AppCrane's health probe calls the
// container directly, with no identity headers, so /api/health must be here.
// Add to this list only for routes that are genuinely public.
const PUBLIC_PATHS = new Set(['/api/health']);

function refuse(res, status, code, message) {
  res.status(status).json({ error: { code, message } });
}

/** Refuse every request whose AppCrane identity does not verify. */
export function requireIdentity() {
  return (req, res, next) => {
    if (PUBLIC_PATHS.has(req.path)) return next();
    const result = verifyRequest(req);
    if (!result.ok) {
      const status = result.code === 'IDENTITY_NOT_CONFIGURED' ? 503 : 401;
      return refuse(res, status, result.code, result.message);
    }
    req.identity = result.identity;
    next();
  };
}

/** Require at least `min` on the per-app ladder: viewer < user < admin < owner. */
export function requireAppRole(min) {
  return (req, res, next) => {
    if (!req.identity || !atLeast(req.identity.appRole, min)) {
      return refuse(res, 403, 'ROLE_REQUIRED', `this needs the ${min} role or higher`);
    }
    next();
  };
}

/** Require one of the roles this app defines for itself (X-AppCrane-App-Roles). */
export function requireAppDefinedRole(key) {
  return (req, res, next) => {
    if (!req.identity || !req.identity.appRoles.includes(key)) {
      return refuse(res, 403, 'APP_ROLE_REQUIRED', `this needs the ${key} role`);
    }
    next();
  };
}

/**
 * @param {{ version: string, db: { query: Function } | null, clientDir?: string }} opts
 *   db is a pg Pool (or anything with the same query()), or null when no
 *   database is configured.
 */
export function createApp({ version, db, clientDir }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '100kb' }));
  app.use(requireIdentity());

  app.get('/api/health', async (_req, res) => {
    if (!db) return res.json({ status: 'ok', version, database: 'not_configured' });
    try {
      await db.query('SELECT 1');
      res.json({ status: 'ok', version, database: 'ok' });
    } catch {
      res.status(503).json({ status: 'error', version, database: 'unreachable' });
    }
  });

  const needDb = (_req, res, next) => (db ? next() : refuse(res, 503, 'NO_DATABASE', 'DATABASE_URL is not set'));

  app.get('/api/me', (req, res) => res.json({ user: req.identity }));

  app.get('/api/notes', requireAppRole('viewer'), needDb, async (_req, res, next) => {
    try {
      const { rows } = await db.query('SELECT id, body, author_id, created_at FROM notes ORDER BY id DESC LIMIT 100');
      res.json({ notes: rows });
    } catch (e) { next(e); }
  });

  app.post('/api/notes', requireAppRole('user'), needDb, async (req, res, next) => {
    const body = typeof req.body?.body === 'string' ? req.body.body.trim() : '';
    if (!body || body.length > 2000) return refuse(res, 400, 'VALIDATION', 'body must be 1-2000 characters');
    try {
      const { rows } = await db.query(
        'INSERT INTO notes (body, author_id) VALUES ($1, $2) RETURNING id, body, author_id, created_at',
        [body, req.identity.userId],
      );
      res.status(201).json({ note: rows[0] });
    } catch (e) { next(e); }
  });

  // Gated twice on purpose: here, and by the "access" rule in deployhub.json
  // that makes AppCrane's proxy refuse /api/admin/* below admin.
  app.delete('/api/admin/notes/:id', requireAppRole('admin'), needDb, async (req, res, next) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return refuse(res, 400, 'VALIDATION', 'id must be a positive integer');
    try {
      const r = await db.query('DELETE FROM notes WHERE id = $1', [id]);
      res.json({ deleted: r.rowCount });
    } catch (e) { next(e); }
  });

  app.use('/api', (_req, res) => refuse(res, 404, 'NOT_FOUND', 'no such API route'));

  if (clientDir && existsSync(join(clientDir, 'index.html'))) {
    app.use(express.static(clientDir, { index: false }));
    app.use((req, res, next) => (req.method === 'GET' ? res.sendFile(join(clientDir, 'index.html')) : next()));
  }

  app.use((err, _req, res, _next) => {
    console.error(err);
    refuse(res, 500, 'INTERNAL', 'something went wrong');
  });

  return app;
}
