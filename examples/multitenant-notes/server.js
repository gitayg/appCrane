// Minimal multitenant app for AppCrane: a per-tenant notes store.
// Each (org, user) gets an isolated SQLite DB — the app never sees another
// tenant's data, and never builds a tenant path by hand. All the isolation
// comes from `appcrane-tenant` + the identity headers AppCrane injects.
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { basename } from 'path';
import express from 'express';
import { tenantDb, tenantFile, assertTenantQuota } from 'appcrane-tenant';

const app = express();
app.use(express.json());

// Open (and lazily create) the caller's own notes DB from the request identity.
function db(req) {
  const d = tenantDb(req);
  d.exec('CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)');
  return d;
}

app.get('/api/health', (_req, res) => res.json({ status: 'ok', version: '1.0.0' }));

app.get('/api/notes', (req, res) => {
  res.json({ notes: db(req).prepare('SELECT id, body, created_at FROM notes ORDER BY id DESC').all() });
});

app.post('/api/notes', (req, res) => {
  const body = String(req.body?.body || '').trim();
  if (!body) return res.status(400).json({ error: 'body required' });
  const info = db(req).prepare('INSERT INTO notes (body) VALUES (?)').run(body);
  res.status(201).json({ id: info.lastInsertRowid, body });
});

// Per-tenant file storage, honouring the quota AppCrane injects (if configured).
app.put('/api/files/:name', (req, res) => {
  try {
    assertTenantQuota(req);                         // 413 if this tenant is full
  } catch (e) {
    if (e.code === 'TENANT_QUOTA_EXCEEDED') return res.status(413).json({ error: e.message });
    throw e;
  }
  const path = tenantFile(req, req.params.name);    // safe path inside the tenant's storage/
  writeFileSync(path, JSON.stringify(req.body ?? null));
  res.json({ saved: basename(path) });
});

app.get('/api/files/:name', (req, res) => {
  const path = tenantFile(req, req.params.name);
  if (!existsSync(path)) return res.status(404).json({ error: 'not found' });
  res.type('json').send(readFileSync(path, 'utf8'));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`multitenant-notes listening on ${port}`));
