import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';

// The whole flow over MCP, with no curl and no REST (v2.54.0).
//
// An agent holds a dhk_mcp_* key, which reaches /api/mcp and /api/files/staged
// and nothing else. Two operations it needed were therefore impossible:
//
//   - getting BYTES to the server. appcrane_deploy_artifact took a staged
//     token, but the only way to create one was `curl -F file=@... 
//     /api/files/staged` — an HTTP call, outside MCP. appcrane_cat is capped at
//     256KB and lossy on binary; appcrane_cp only writes INTO a container.
//   - renaming an app. POST /api/apps/:slug/rename is requireAdmin REST, so the
//     supported way to change an app's identity was closed, and people
//     recreated apps instead — which is what loses deploy history.
//
// This drives the real tools end to end: chunk a real archive over JSON-RPC,
// assemble it, deploy it, then rename the app and confirm the release survived.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mcpnative-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

let admin;
before(() => {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin',?,1,'human')"
  ).run(hashApiKey(generateApiKey('dhk_admin'))).lastInsertRowid;
  admin = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('Old','oldname',960,'upload')").run();
});

const unwrap = (r) => (typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r));
const call = async (n, a) => unwrap(await callTool(admin, n, a));

/** A real .zip, big enough to need several parts. */
function makeBundle() {
  const src = mkdtempSync(join(tmpdir(), 'mn-src-'));
  writeFileSync(join(src, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  writeFileSync(join(src, 'big.js'), '// filler\n'.repeat(4000));
  const out = join(mkdtempSync(join(tmpdir(), 'mn-out-')), 'dist.zip');
  execFileSync('zip', ['-qr', out, '.'], { cwd: src });
  return readFileSync(out);
}

test('a file crosses MCP in parts and comes back byte-identical', async () => {
  const bytes = makeBundle();
  const want = createHash('sha256').update(bytes).digest('hex');

  // Deliberately out of order, to prove assembly sorts by part rather than by
  // arrival — the failure would be a corrupt archive with a plausible size.
  const SIZE = 16 * 1024;
  const parts = [];
  for (let i = 0; i < bytes.length; i += SIZE) parts.push(bytes.subarray(i, i + SIZE));
  const order = [...parts.keys()].reverse();

  for (const i of order) {
    const r = await call('appcrane_stage_chunk', {
      session: 's1', part: i + 1, of: parts.length,
      content: parts[i].toString('base64'), encoding: 'base64',
      sha256: createHash('sha256').update(parts[i]).digest('hex'),
    });
    assert.equal(r.session, 's1');
  }

  const asm = await call('appcrane_stage_assemble', { session: 's1', filename: 'dist.zip', sha256: want });
  assert.equal(asm.sha256, want, 'the reassembled bytes must be the bytes that were sent');
  assert.equal(asm.size_bytes, bytes.length);
  assert.ok(asm.token, 'a staged token is what makes this deployable');
});

test('a corrupted part is caught, not deployed', async () => {
  await assert.rejects(
    () => call('appcrane_stage_chunk', {
      session: 's2', part: 1, of: 1, content: Buffer.from('abc').toString('base64'),
      encoding: 'base64', sha256: 'f'.repeat(64),
    }),
    /SHA-256 mismatch/,
  );
});

test('assembling refuses when the WHOLE file does not hash to what was declared', async () => {
  // Distinct from the per-part check above. Every part can arrive intact and
  // still assemble into the wrong file — a part re-sent with different content,
  // or a bundle rebuilt mid-upload. This digest is the only thing tying the
  // deployed artifact to the one that was built, so it has to be enforced.
  const bytes = Buffer.from('not the file you think');
  await call('appcrane_stage_chunk', {
    session: 's5', part: 1, of: 1, content: bytes.toString('base64'), encoding: 'base64',
  });
  await assert.rejects(
    () => call('appcrane_stage_assemble', { session: 's5', filename: 'x.zip', sha256: 'a'.repeat(64) }),
    /assembled file SHA-256 mismatch/,
  );
});

// NOT COVERED: the `ORDER BY part` in assembly.
//
// A test was written for it — parts pushed in reverse — and it could not fail:
// stage_chunks has PRIMARY KEY (session, part), so SQLite returns them in part
// order whether the clause is there or not. Removing ORDER BY leaves the suite
// green. It stays because the guarantee should be stated by the query rather
// than inherited from an index that a later migration could reshape, and this
// note is here so its absence from the tests is not read as an absence of
// reason.

test('assembling with parts missing refuses and says which', async () => {
  await call('appcrane_stage_chunk', { session: 's3', part: 1, of: 3, content: 'aGk=', encoding: 'base64' });
  await assert.rejects(() => call('appcrane_stage_assemble', { session: 's3', filename: 'x.zip' }),
    /parts 2, 3 of 3 are missing/);
});

test('the staged token deploys — bytes to running release, entirely over MCP', async () => {
  const bytes = makeBundle();
  const want = createHash('sha256').update(bytes).digest('hex');
  await call('appcrane_stage_chunk', {
    session: 's4', part: 1, of: 1, content: bytes.toString('base64'), encoding: 'base64',
  });
  const asm = await call('appcrane_stage_assemble', { session: 's4', filename: 'dist.zip', sha256: want });

  const dep = await call('appcrane_deploy_artifact', { slug: 'oldname', env: 'production', token: asm.token });
  assert.equal(dep.artifact.sha256, want,
    'the deployed artifact must be the file that was chunked across — no curl involved anywhere');
  assert.equal(dep.commit_hash, `sha256:${want}`);
});

test('an app renames over MCP, and its history survives', async () => {
  const before = db.prepare("SELECT id FROM apps WHERE slug = 'oldname'").get();
  const deploysBefore = db.prepare('SELECT COUNT(*) c FROM deployments WHERE app_id = ?').get(before.id).c;
  assert.ok(deploysBefore > 0, 'the previous test must have left a deploy to preserve');

  const out = await call('appcrane_rename_app', { slug: 'oldname', new_slug: 'newname' });
  assert.equal(out.new_slug, 'newname');

  const after = db.prepare("SELECT id, slug, slug_aliases FROM apps WHERE slug = 'newname'").get();
  assert.equal(after.id, before.id, 'same row — a rename must not create a new app');
  assert.equal(db.prepare('SELECT COUNT(*) c FROM deployments WHERE app_id = ?').get(after.id).c, deploysBefore,
    'deploy history is keyed on app id and must survive the rename intact');
  assert.match(after.slug_aliases || '', /oldname/, 'the old slug keeps redirecting');
  assert.ok(existsSync(join(process.env.DATA_DIR, 'apps', 'newname')), 'the data directory followed');
});

test('renaming onto a slug whose directory still exists is refused up front', async () => {
  // Deleting an app clears its rows but leaves data/apps/<slug>. Renaming onto
  // that slug used to get as far as stopping the containers before failing on
  // ENOTEMPTY; it must be refused before anything is touched.
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('Src','src-app',961,'upload')").run();
  const ghost = join(process.env.DATA_DIR, 'apps', 'ghost-slug');
  mkdirSync(join(ghost, 'releases'), { recursive: true });
  writeFileSync(join(ghost, 'releases', 'leftover.txt'), 'x');

  await assert.rejects(() => call('appcrane_rename_app', { slug: 'src-app', new_slug: 'ghost-slug' }),
    /still exists on disk/);
  assert.ok(db.prepare("SELECT 1 FROM apps WHERE slug = 'src-app'").get(), 'the source app is untouched');
});

test('freeing a slug by renaming the squatter out of the way, with no delete', async () => {
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('Empty','wanted',962,'upload')").run();
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('Real','realapp',963,'upload')").run();
  mkdirSync(join(process.env.DATA_DIR, 'apps', 'realapp'), { recursive: true });

  // redirect:false, or 'wanted' would keep resolving to the retired app.
  await call('appcrane_rename_app', { slug: 'wanted', new_slug: 'wanted-retired', redirect: false });
  const retired = db.prepare("SELECT slug_aliases FROM apps WHERE slug = 'wanted-retired'").get();
  assert.equal(retired.slug_aliases, null, 'redirect:false must not leave an alias claiming the freed slug');

  const out = await call('appcrane_rename_app', { slug: 'realapp', new_slug: 'wanted' });
  assert.equal(out.new_slug, 'wanted', 'the freed slug is now takeable — no app was deleted to get here');
});
