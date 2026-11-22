import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, statSync, chmodSync } from 'fs';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { dirname, join } from 'path';

// An app's decrypted Claude login (access + refresh token) sits in a file for
// the whole session. The file has to be world-rw for the image's `studio` user,
// whose uid is not known on the host, so its directories are what keep other
// host users out. Before the fix they were 0755 and anyone could read it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-claude-creds-perms-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { setCredentials, prepareClaudeCredentialsMount } = await import('../server/services/claudeCredentials.js');

const ROOT = join(process.env.DATA_DIR, 'claude-credentials-tmp');
const mode = (p) => statSync(p).mode & 0o777;
const LOGIN = { claudeAiOauth: { accessToken: 'at-made-up', refreshToken: 'rt-made-up', expiresAt: 1 } };

let seq = 0;
function app() {
  const slug = `perms-${++seq}`;
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'managed')").run(slug, slug, seq);
  setCredentials(slug, LOGIN);
  return slug;
}

test('only the AppCrane user can reach the login file: both directories are 0700', () => {
  const m = prepareClaudeCredentialsMount(app());
  try {
    assert.equal(mode(ROOT).toString(8), '700');
    assert.equal(mode(dirname(m.tmpFile)).toString(8), '700');
    assert.equal(mode(m.tmpFile).toString(8), '666', 'the studio user inside the container must still write it');
  } finally { m.cleanup(); }
});

test('a root directory an earlier version left at 0755 is closed on the next mount', () => {
  mkdirSync(ROOT, { recursive: true });
  chmodSync(ROOT, 0o755);
  const m = prepareClaudeCredentialsMount(app());
  try { assert.equal(mode(ROOT).toString(8), '700'); } finally { m.cleanup(); }
});

let docker = false;
try { execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 15000 }); docker = true; } catch (_) {}

test('LIVE: a container user that is not the host user still reads and rewrites the mounted login', { skip: !docker && 'Docker is not available', timeout: 120000 }, () => {
  const m = prepareClaudeCredentialsMount(app());
  try {
    const out = execFileSync('docker', ['run', '--rm', '--user', '100:101',
      '-v', `${m.tmpFile}:/home/studio/.claude/.credentials.json`,
      'alpine:3.20', 'sh', '-c', 'cat /home/studio/.claude/.credentials.json && echo \'{"rotated":true}\' > /home/studio/.claude/.credentials.json'],
    { encoding: 'utf8', timeout: 100000 });
    assert.match(out, /rt-made-up/, 'the container could not read the login');
    assert.deepEqual(JSON.parse(readFileSync(m.tmpFile, 'utf8')), { rotated: true }, 'the container could not write the refreshed login');
  } finally { m.cleanup(); }
});
