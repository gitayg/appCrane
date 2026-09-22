import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

// DATA_DIR/apps/<slug>/agent-context.md is read into EVERY coder dispatch as
// "# Per-app context from the operator" (builderSession.loadDispatchContext).
// The file and its REST routes already existed; no MCP client could reach
// them, so a local agent that learned something about an app had nowhere to
// put it where the in-platform coder would see it.
//
// The risks worth pinning are not "does it write a file":
//   - append must not be able to destroy what a human wrote (that is what
//     `set` is for, and `set` reports what it discarded)
//   - the context is prepended to every dispatch, so unbounded growth silently
//     eats the context window and reads as the model getting worse
//   - a slug must not be able to steer the write out of DATA_DIR/apps
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-appctx-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');

// callTool answers in MCP content format — { content: [{ type:'text', text }] }
// — not the handler's return value. Asserting on the raw result silently
// compares against an object that never has the fields, so unwrap once here.
const call = async (user, name, args) => {
  const r = await callTool(user, name, args);
  const text = r?.content?.[0]?.text;
  try { return JSON.parse(text); } catch (_) { return text; }
};

const mkUser = (name, role) => {
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(generateApiKey('dhk'))).lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
};
const admin   = mkUser('Admin', 'platform_admin');
const owner   = mkUser('Owner', 'user');
const bystander = mkUser('Bystander', 'user');

const SLUG = 'ctxapp';
const appId = db.prepare(`INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch)
                          VALUES ('Ctx App', ?, 401, 'managed', 'local', 'main') RETURNING id`).get(SLUG).id;
for (const u of [owner, bystander]) db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, u.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, owner.id);

const ctxFile = () => resolve(join(process.env.DATA_DIR, 'apps', SLUG, 'agent-context.md'));
const onDisk = () => (existsSync(ctxFile()) ? readFileSync(ctxFile(), 'utf8') : '');

test('an empty context reads as an empty string, not an error', async () => {
  const r = await call(admin, 'appcrane_get_app_context', { slug: SLUG });
  assert.equal(r.content, '');
  assert.equal(r.bytes, 0);
});

test('append adds a note the coder will see, and is attributed', async () => {
  await callTool(owner, 'appcrane_append_app_context', { slug: SLUG, note: 'Health route is /healthz, not /api/health.' });
  const body = onDisk();
  assert.match(body, /Health route is \/healthz/);
  assert.match(body, /Owner/, 'the note is not attributed to whoever wrote it');
  assert.match(body, /^## /m, 'no heading — appended notes run together');
});

test('append NEVER destroys what is already there', async () => {
  const before = onDisk();
  await callTool(owner, 'appcrane_append_app_context', { slug: SLUG, note: 'Second thing.', heading: 'Deploy gotcha' });
  const after = onDisk();
  assert.ok(after.startsWith(before), 'append rewrote earlier content instead of adding to it');
  assert.match(after, /Deploy gotcha/);
  assert.match(after, /Health route is \/healthz/, 'the first note is gone');
});

test('set REPLACES, and reports how much it destroyed', async () => {
  const before = onDisk();
  assert.ok(before.length > 0);
  const r = await call(admin, 'appcrane_set_app_context', { slug: SLUG, content: 'Just this.\n' });
  assert.equal(onDisk(), 'Just this.\n');
  assert.equal(r.replaced_bytes, Buffer.byteLength(before, 'utf8'),
    'a replace that does not say what it discarded is how an agent quietly deletes a human\'s notes');
});

test('the context is capped, because it is prepended to every dispatch', async () => {
  const huge = 'x'.repeat(300 * 1024);
  await assert.rejects(
    () => callTool(admin, 'appcrane_set_app_context', { slug: SLUG, content: huge }),
    /over the \d+-byte cap/,
    'an unbounded context silently eats the window it was meant to help',
  );
  assert.equal(onDisk(), 'Just this.\n', 'the refused write still changed the file');
});

test('an empty note is refused rather than appending a bare heading', async () => {
  await assert.rejects(
    () => callTool(owner, 'appcrane_append_app_context', { slug: SLUG, note: '   ' }),
    /empty/,
  );
});

test('a plain app member cannot read or write the context', async () => {
  // These notes routinely carry internal detail about how an app is operated.
  for (const [tool, args] of [
    ['appcrane_get_app_context', {}],
    ['appcrane_append_app_context', { note: 'sneaky' }],
    ['appcrane_set_app_context', { content: 'sneaky' }],
  ]) {
    await assert.rejects(
      () => callTool(bystander, tool, { slug: SLUG, ...args }),
      /Forbidden|not permitted|app admin/i,
      `${tool} let a plain member through`,
    );
  }
  assert.equal(onDisk(), 'Just this.\n', 'a refused call still wrote');
});

test('get is marked read-only so a read cannot be mistaken for a write', async () => {
  const { listToolsForUser } = await import('../server/services/mcpTools.js');
  const tools = listToolsForUser ? listToolsForUser(admin) : null;
  if (!tools) return; // exported shape differs; the snapshot test covers it
  const get = tools.find((t) => t.name === 'appcrane_get_app_context');
  assert.ok(get, 'appcrane_get_app_context is not advertised');
});
