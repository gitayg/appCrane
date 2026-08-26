import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';

// An agent holding the only credential it can hold must be able to deploy.
//
// A personal MCP key (dhk_mcp_*) is allow-listed to /api/mcp and
// /api/files/staged and refused everywhere else (middleware/auth.js), and
// dhk_app_* keys were removed entirely in v2.2.12. So POST
// /api/apps/:slug/deploy/upload — the whole upload path — was unreachable with
// an MCP key. That is fine while the managed-repo path works, and stops being
// fine the moment it does not: an expired service-account PAT returns 401 on
// every repo write, and the fallback was refused by key scope. Both doors shut,
// with a valid bundle sitting on disk.
//
// appcrane_deploy_artifact is the door that opens with the key an agent has:
// stage the bytes on the one allowed endpoint, then deploy by token.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mcp-art-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

// Docker must not be reachable: the deploy is started detached and is not what
// these assertions are about.
const SHIM = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

const SLUG = 'artifact-app';
let owner;
let other;

before(() => {
  const mk = (name, email) => {
    const id = db.prepare(
      "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,'platform_admin',?,1,'human')"
    ).run(name, email, hashApiKey(generateApiKey('dhk_admin'))).lastInsertRowid;
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  };
  owner = mk('Owner', 'o@x.io');
  other = mk('Other', 'p@x.io');
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('Artifact App', ?, 93, 'upload')").run(SLUG);
});

function makeBundle(marker) {
  const src = mkdtempSync(join(tmpdir(), 'ab-src-'));
  writeFileSync(join(src, 'package.json'), JSON.stringify({ name: 'a', version: '1.0.0' }));
  writeFileSync(join(src, 'index.js'), `// ${marker}\n`);
  const out = join(mkdtempSync(join(tmpdir(), 'ab-out-')), 'dist.zip');
  execFileSync('zip', ['-qr', out, '.'], { cwd: src });
  return out;
}

/** Stand in for POST /api/files/staged, which routes/files.js already covers. */
function stage(bundlePath, user, { filename = 'dist.zip', expires = '2099-01-01 00:00:00' } = {}) {
  const scratch = join(mkdtempSync(join(tmpdir(), 'staged-')), filename);
  copyFileSync(bundlePath, scratch);
  const bytes = readFileSync(scratch);
  const token = createHash('sha256').update(scratch).digest('hex').slice(0, 32);
  db.prepare(`
    INSERT INTO staged_files (token, user_id, filename, size_bytes, sha256, scratch_path, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(token, user.id, filename, bytes.length,
    createHash('sha256').update(bytes).digest('hex'), scratch, expires);
  return { token, scratch, sha256: createHash('sha256').update(bytes).digest('hex') };
}

const unwrap = (r) => (typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r));

test('the tool exists and is callable with the key an agent actually holds', async () => {
  const { listTools } = await import('../server/services/mcpTools.js');
  const names = listTools(owner).map((t) => t.name);
  assert.ok(names.includes('appcrane_deploy_artifact'),
    'without this tool there is no deploy path at all for a dhk_mcp_* key');
});

test('a staged bundle deploys, and is identified by its digest', async () => {
  const bundle = makeBundle('one');
  const { token, sha256 } = stage(bundle, owner);

  const out = unwrap(await callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token, env: 'sandbox' }));
  assert.equal(out.artifact.sha256, sha256);
  assert.equal(out.commit_hash, `sha256:${sha256}`);

  const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(out.deployment_id);
  assert.equal(row.commit_hash, `sha256:${sha256}`);
  assert.equal(row.artifact_sha256, sha256);
  assert.equal(row.env, 'sandbox');
});

test('bytes changed after staging are refused, not deployed', async () => {
  const bundle = makeBundle('two');
  const { token, scratch } = stage(bundle, owner);
  writeFileSync(scratch, 'tampered');

  await assert.rejects(
    () => callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token }),
    /no longer matches/,
    'reading the digest out of the staged row instead of re-hashing would record the digest of the ' +
    'bytes that were uploaded while deploying whatever is on disk now',
  );
});

test("another user's staged file cannot be deployed", async () => {
  const { token } = stage(makeBundle('three'), other);
  await assert.rejects(
    () => callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token }),
    /owned by a different user/,
  );
});

test('a token cannot be replayed', async () => {
  const { token } = stage(makeBundle('four'), owner);
  await callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token });
  await assert.rejects(
    () => callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token }),
    /already consumed/,
  );
});

test('an expired token is refused', async () => {
  const { token } = stage(makeBundle('five'), owner, { expires: '2000-01-01 00:00:00' });
  await assert.rejects(() => callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token }), /expired/);
});

test('a bundle with a disallowed extension is refused', async () => {
  const { token } = stage(makeBundle('six'), owner, { filename: 'payload.sh' });
  await assert.rejects(
    () => callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token }),
    /files allowed/,
    'the HTTP route filters on extension via multer; the MCP door has no multer in front of it and ' +
    'would otherwise accept anything the staging endpoint took',
  );
});

test('the declared commit_sha is recorded but never becomes the identity', async () => {
  const bundle = makeBundle('seven');
  const { token, sha256 } = stage(bundle, owner);
  const out = unwrap(await callTool(owner, 'appcrane_deploy_artifact', {
    slug: SLUG, token, commit_sha: 'c'.repeat(40), commit_message: 'release 1',
  }));
  assert.equal(out.commit_hash, `sha256:${sha256}`);
  assert.equal(out.artifact.declared_commit_sha, 'c'.repeat(40));

  const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(out.deployment_id);
  assert.equal(row.declared_commit_sha, 'c'.repeat(40));
  assert.equal(row.commit_message, 'release 1');
});

test('the staged bytes survive the deploy — the store sweeps its own files', async () => {
  const { token, scratch } = stage(makeBundle('eight'), owner);
  await callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token });
  assert.doesNotThrow(() => readFileSync(scratch),
    'deleting the blob here would pull the file out from under staged_files bookkeeping, which ' +
    'expects to sweep it on its own schedule');
});

test('a read-only MCP key cannot deploy an artifact', async () => {
  // mcpTools treats any tool without an explicit `readOnly: true` as a write
  // tool and refuses it (v2.44.0, default-deny). Asserted rather than assumed:
  // this tool deploys code, and the marker that would exempt it is one word.
  const { token } = stage(makeBundle('nine'), owner);
  await assert.rejects(
    () => callTool(owner, 'appcrane_deploy_artifact', { slug: SLUG, token }, { read_only: 1 }),
    /read-only/i,
  );
});
