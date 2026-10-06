import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Security audit 2026-10-06, H1: appcrane_cp checked its target path as text,
// then mkdir/write/rename on the HOST followed symbolic links the app's own
// code had planted in its /data, so an app admin got a file write anywhere the
// AppCrane process could write (root on a default install).
//
// Now: while the app's container runs, the write goes INTO the container
// (docker cp), where a link resolves inside the container; with it stopped,
// nothing can race the write, and the host path is walked with lstat and any
// symbolic link is refused.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-h1-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);

const SHIM = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker.log');
const RUNNING = join(process.env.DATA_DIR, 'running');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
let stdin = Buffer.alloc(0);
if (args[0] === 'cp' && args[1] === '-') { try { stdin = fs.readFileSync(0); } catch (_) {} }
fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify({ args, stdinBytes: stdin.length, tarHasPayload: stdin.includes('PAYLOAD') }) + '\\n');
if (args[0] === 'inspect' && fs.existsSync(${JSON.stringify(join(process.env.DATA_DIR, 'daemon-broken'))})) { process.stderr.write('Cannot connect to the Docker daemon\\n'); process.exit(1); }
if (args[0] === 'inspect') {
  const state = fs.existsSync(${JSON.stringify(RUNNING)}) ? 'true' : fs.existsSync(${JSON.stringify(join(process.env.DATA_DIR, 'stopped'))}) ? 'false' : null;
  if (state === null) { process.stderr.write('Error: No such object: ' + args[args.length - 1] + '\\n'); process.exit(1); }
  process.stdout.write(state + '\\n'); process.exit(0);
}
process.exit(0);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('a','a@t.test','user',1,?)").run(hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('W','writer',1,'managed','main')").run().lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, uid);
const USER = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
const { callTool } = await import('../server/services/mcpTools.js');

const DATA = join(process.env.DATA_DIR, 'apps', 'writer', 'sandbox', 'shared', 'data');
mkdirSync(DATA, { recursive: true });
const OUTSIDE = mkdtempSync(join(tmpdir(), 'crane-h1-outside-'));
const cp = (path, content = 'PAYLOAD') => callTool(USER, 'appcrane_cp', { slug: 'writer', env: 'sandbox', path, content });

test('no container: a planted directory link is refused, nothing lands outside', async () => {
  symlinkSync(OUTSIDE, join(DATA, 'linkdir'));
  await assert.rejects(cp('linkdir/pwned.txt'), /symbolic link/);
  assert.ok(!existsSync(join(OUTSIDE, 'pwned.txt')), 'the write followed the link out of /data');
});

test('no container: a planted file link is refused, its target is untouched', async () => {
  writeFileSync(join(OUTSIDE, 'victim.conf'), 'ORIGINAL');
  symlinkSync(join(OUTSIDE, 'victim.conf'), join(DATA, 'innocent.txt'));
  await assert.rejects(cp('innocent.txt'), /symbolic link/);
  assert.equal(readFileSync(join(OUTSIDE, 'victim.conf'), 'utf8'), 'ORIGINAL');
});

test('no container: an ordinary nested write still works', async () => {
  await cp('datasets/2026/threats.json', 'PAYLOAD-ok');
  assert.equal(readFileSync(join(DATA, 'datasets/2026/threats.json'), 'utf8'), 'PAYLOAD-ok');
});

test('stopped container: the write goes into the container too, never through the host path', async () => {
  // Commit review: "stopped, so write on the host" raced the container starting.
  writeFileSync(join(process.env.DATA_DIR, 'stopped'), '1');
  await cp('linkdir/via-stopped.txt');
  assert.ok(!existsSync(join(OUTSIDE, 'via-stopped.txt')), 'a host-side write followed the planted link');
  const calls = readFileSync(LOG, 'utf8').trim().split('\n').map(JSON.parse).filter(c => c.args[0] === 'cp');
  assert.deepEqual(calls.at(-1).args, ['cp', '-', 'appcrane-writer-sandbox:/data']);
});

test('running container: the write goes into the container, not through the host path', async () => {
  writeFileSync(RUNNING, '1');
  await cp('linkdir/via-container.txt');
  assert.ok(!existsSync(join(OUTSIDE, 'via-container.txt')), 'a host-side write followed the planted link');
  const cpCall = readFileSync(LOG, 'utf8').trim().split('\n').map(JSON.parse).find(c => c.args[0] === 'cp');
  assert.ok(cpCall, 'no docker cp was issued');
  assert.deepEqual(cpCall.args, ['cp', '-', 'appcrane-writer-sandbox:/data']);
  assert.ok(cpCall.tarHasPayload, 'the archive streamed into the container does not carry the content');
});

after(() => {});

test('a path that looks like a tar option is refused, never passed to tar', async () => {
  // Background security review: rel reached `tar -cf - <rel>` as an argument,
  // so "--checkpoint-action=exec=..." would have been a tar OPTION (host exec).
  writeFileSync(RUNNING, '1');
  const before = readFileSync(LOG, 'utf8').length;
  for (const evil of ['--checkpoint=1', '--checkpoint-action=exec=touch /tmp/crane-pwn', 'ok/-rf']) {
    await assert.rejects(cp(evil), /must not start with "-"/);
  }
  assert.equal(readFileSync(LOG, 'utf8').length, before, 'docker was called for a refused path');
});

test('an unreadable container state fails closed: nothing is written on the host', async () => {
  // Background commit review: a docker inspect error used to read as "not
  // running" and fall through to the host write while the app might be running.
  writeFileSync(join(process.env.DATA_DIR, 'daemon-broken'), '1');
  try {
    await assert.rejects(cp('fresh/should-not-exist.txt'), /cannot tell whether/);
    assert.ok(!existsSync(join(DATA, 'fresh')), 'a host-side write happened although the container state was unknown');
  } finally {
    rmSync(join(process.env.DATA_DIR, 'daemon-broken'));
  }
});
