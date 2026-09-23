import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// "I did a command and nothing happened." The session row said idle, but its
// container was gone (AppCrane restarted, or the container was evicted without
// the page hearing it). dispatch() threw "Session not active", the route turned
// it into a generic 500, and the panel kept showing "idle" next to an error it
// gave no way to act on. Three refusals, three wordings, none of them "paused".
//
// Now every one of them is SESSION_PAUSED (409), the row is marked paused, and
// the panel resumes the session and runs the message.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-sendpaused-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

// Brings its own docker so the result is the same on a host that has one.
const BIN = join(ROOT, 'bin');
mkdirSync(BIN, { recursive: true });
writeFileSync(join(BIN, 'docker'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { dispatch, subscribe } = await import('../server/services/builder/builderSession.js');

const userId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('u','u@x','platform_admin','h',1,'human')")
  .run().lastInsertRowid;
db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES ('n','notes',1,'managed','local','main')").run();
db.prepare(`INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status)
            VALUES ('s1','notes',?,'coder/x','idle')`).run(userId);

test('a message into a session whose container is gone is refused as SESSION_PAUSED, and the row says so', async () => {
  const events = [];
  subscribe('s1', (e) => events.push(e));
  const err = await dispatch('s1', 'add a button').then(() => null, (e) => e);
  assert.ok(err, 'dispatch accepted a message with no container behind it');
  assert.equal(err.code, 'SESSION_PAUSED', `refused with ${err.code}: ${err.message}`);
  assert.equal(db.prepare("SELECT status FROM coder_sessions WHERE id='s1'").get().status, 'paused',
    'the row still says idle, so the next page load shows idle again');
  assert.ok(events.some(e => e.type === 'status' && e.status === 'paused'),
    'the open panel was not told: its pill keeps saying idle');
  assert.equal(db.prepare("SELECT COUNT(*) c FROM coder_session_messages WHERE session_id='s1'").get().c, 0,
    'the refused message was recorded as if it ran');
});

const route = readFileSync(new URL('../server/routes/coder.js', import.meta.url), 'utf8');
const hook  = readFileSync(new URL('../studio-web/src/components/coder/useCoderSession.ts', import.meta.url), 'utf8');

test('the route answers a paused session with 409 SESSION_PAUSED, not WRONG_STATUS or a 500', () => {
  assert.match(route, /session\.status === 'paused'[\s\S]{0,200}409, 'SESSION_PAUSED'/);
  assert.match(route, /err\.code === 'SESSION_PAUSED'\) throw new AppError\(err\.message, 409, 'SESSION_PAUSED'\)/);
});

test('the panel resumes a paused session and then runs the message', () => {
  assert.match(hook, /e\.code === 'SESSION_PAUSED'/, 'a SESSION_PAUSED refusal is shown as a plain error again');
  assert.match(hook, /if \(status === 'paused'\) await resumeThenDispatch\(\)/,
    'a message typed into a known-paused session is not resumed first');
  assert.match(hook, /if \(!\(await resumeNow\(\)\)\)[\s\S]{0,120}was not run/,
    'a failed resume drops the message silently');
});
