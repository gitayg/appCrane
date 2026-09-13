import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The app list marks where each app's code comes from (crane-hosted, managed on
// GitHub, GitHub App, GitHub token, public GitHub). The label is derived once on
// the server so the dashboard never re-derives it from raw columns.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-codesource-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const KEY = generateApiKey('dhk_admin');
db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','admin@example.com','platform_admin',?,1,'human')"
).run(hashApiKey(KEY));

const TOKEN = 'ghp_' + 'x'.repeat(36);
const APPS = [
  { slug: 'cs-local',   source_type: 'managed', repo_backend: 'local', expected: 'crane_hosted',   attached: false },
  { slug: 'cs-managed', source_type: 'managed', repo_backend: null,    expected: 'managed_github', attached: false },
  { slug: 'cs-ghapp',   source_type: 'github',  token: true, install: true, expected: 'github_app', attached: true },
  { slug: 'cs-token',   source_type: 'github',  token: true,           expected: 'github_token',   attached: false },
  { slug: 'cs-public',  source_type: 'github',                         expected: 'github_public',  attached: false },
  { slug: 'cs-upload',  source_type: 'upload',                         expected: null,             attached: false },
];

let slot = 0;
for (const a of APPS) {
  a.id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,github_url,repo_backend,github_token_encrypted) VALUES (?,?,?,?,?,?,?)'
  ).run(a.slug, a.slug, ++slot, a.source_type,
    a.source_type === 'github' ? `https://github.com/example/${a.slug}` : null,
    a.repo_backend ?? null,
    a.token ? encrypt(TOKEN) : null).lastInsertRowid;
  if (a.install) {
    db.prepare('INSERT INTO app_github_installations (app_id, slug, installation_id, repo_full_name) VALUES (?,?,?,?)')
      .run(a.id, a.slug, 4242, `example/${a.slug}`);
  }
}

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);

const server = await new Promise((resolve) => {
  const s = api.listen(0, '127.0.0.1', () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function get(path) {
  const res = await fetch(`${BASE}${path}`, { headers: { 'X-API-Key': KEY } });
  const text = await res.text();
  return { status: res.status, text, body: JSON.parse(text) };
}

for (const a of APPS) {
  test(`list: ${a.slug} reports code_source=${a.expected}`, async () => {
    const r = await get('/api/apps');
    assert.equal(r.status, 200, r.text);
    const row = r.body.apps.find(x => x.slug === a.slug);
    assert.ok(row, `${a.slug} missing from the list`);
    assert.equal(row.code_source, a.expected);
    assert.equal(row.github_app_attached, a.attached);
    assert.equal(row.repo_backend, a.repo_backend ?? null);
  });

  test(`detail: ${a.slug} agrees with the list`, async () => {
    const r = await get(`/api/apps/${a.slug}`);
    assert.equal(r.status, 200, r.text);
    assert.equal(r.body.app.code_source, a.expected);
    assert.equal(r.body.app.github_app_attached, a.attached);
  });
}

test('an unrecognised repo_backend yields no label instead of breaking the list', async () => {
  const id = db.prepare('INSERT INTO apps (name,slug,slot,source_type,repo_backend) VALUES (?,?,?,?,?)')
    .run('cs-bad', 'cs-bad', ++slot, 'managed', 'bogus').lastInsertRowid;
  try {
    const r = await get('/api/apps');
    assert.equal(r.status, 200, r.text);
    assert.equal(r.body.apps.find(x => x.slug === 'cs-bad').code_source, null);
  } finally {
    db.prepare('DELETE FROM apps WHERE id = ?').run(id);
  }
});

test('the plaintext token never appears in the list or detail payload', async () => {
  assert.ok(!(await get('/api/apps')).text.includes(TOKEN));
  assert.ok(!(await get('/api/apps/cs-token')).text.includes(TOKEN));
});
