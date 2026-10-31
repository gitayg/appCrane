import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The per-task Claude home of a Crew app coder turn (services/crewCoderHome.js).
// What is pinned: one directory per task under DATA_DIR/crew-coder, ids that
// are not a crew task id are refused (no path escape), stale mount points are
// cleared, a pre-upgrade transcript is copied in once, and homes of closed or
// missing tasks are swept while open ones stay.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-coder-home-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const home = await import('../server/services/crewCoderHome.js');
const { transcriptDirFor } = await import('../server/services/builder/appContainer.js');

test('one home per task under DATA_DIR/crew-coder; unsafe ids are refused', () => {
  assert.equal(home.crewTaskHomeDir('AbC_-1'), join(process.env.DATA_DIR, 'crew-coder', 'AbC_-1', 'claude'));
  for (const bad of ['../x', 'a/b', '', '.', 'a b', 'x'.repeat(65), null]) {
    assert.throws(() => home.crewTaskHomeDir(bad), /refusing task id/, String(bad));
    assert.throws(() => home.prepareCrewTaskHome(bad, {}), /refusing task id/);
  }
  assert.equal(home.removeCrewTaskHome('../..'), false);
  assert.ok(existsSync(process.env.DATA_DIR), 'a refused id removes nothing');
});

test('prepare creates the home, clears stale credential and skills mount points, keeps the transcript', () => {
  const dir = home.prepareCrewTaskHome('task1', { slug: 'shop' });
  assert.ok(statSync(dir).isDirectory());
  mkdirSync(join(dir, 'projects', '-workspace'), { recursive: true });
  writeFileSync(join(dir, 'projects', '-workspace', 's1.jsonl'), 'mine');
  writeFileSync(join(dir, 'credentials.json'), '');
  writeFileSync(join(dir, '.credentials.json'), 'stale');
  mkdirSync(join(dir, 'skills'));
  assert.equal(home.prepareCrewTaskHome('task1', { slug: 'shop' }), dir);
  assert.ok(!existsSync(join(dir, 'credentials.json')));
  assert.ok(!existsSync(join(dir, '.credentials.json')));
  assert.ok(!existsSync(join(dir, 'skills')));
  assert.equal(readFileSync(join(dir, 'projects', '-workspace', 's1.jsonl'), 'utf8'), 'mine');
});

test('a task resumed from before the upgrade gets its transcript copied in once, and only its own', () => {
  const legacy = join(transcriptDirFor('shop'), '-workspace');
  mkdirSync(legacy, { recursive: true });
  writeFileSync(join(legacy, 'old-sid.jsonl'), 'the task conversation');
  writeFileSync(join(legacy, 'owner-sid.jsonl'), 'the owner conversation');
  const dir = home.prepareCrewTaskHome('task2', { slug: 'shop', resumeId: 'old-sid' });
  assert.equal(readFileSync(join(dir, 'projects', '-workspace', 'old-sid.jsonl'), 'utf8'), 'the task conversation');
  assert.ok(!existsSync(join(dir, 'projects', '-workspace', 'owner-sid.jsonl')));
  // Once: the task's own newer transcript is not overwritten by the legacy copy.
  writeFileSync(join(dir, 'projects', '-workspace', 'old-sid.jsonl'), 'continued');
  home.prepareCrewTaskHome('task2', { slug: 'shop', resumeId: 'old-sid' });
  assert.equal(readFileSync(join(dir, 'projects', '-workspace', 'old-sid.jsonl'), 'utf8'), 'continued');
  // A resume id that is not a session id copies nothing.
  const d3 = home.prepareCrewTaskHome('task3', { slug: 'shop', resumeId: '../owner-sid' });
  assert.ok(!existsSync(join(d3, 'projects')));
});

test('the sweep removes homes of closed and missing tasks and keeps open ones', () => {
  db.prepare("INSERT INTO users (id, name, email, role, api_key_hash, active, kind) VALUES (1, 'U', 'u@example.com', 'user', 'h-home', 1, 'human')").run();
  db.prepare("INSERT INTO crew_agents (id, owner_user_id, name, kind) VALUES (1, 1, 'aa', 'mcp'), (2, 1, 'bb', 'mcp')").run();
  const add = (id, state) => db.prepare("INSERT INTO crew_tasks (id, from_agent_id, to_agent_id, title, state) VALUES (?, 1, 2, 't', ?)").run(id, state);
  add('open1', 'working');
  add('asks1', 'input_required');
  add('done1', 'completed');
  add('fail1', 'failed');
  for (const id of ['open1', 'asks1', 'done1', 'fail1', 'gone1']) home.prepareCrewTaskHome(id, {});
  mkdirSync(join(process.env.DATA_DIR, 'crew-coder', 'bad name'), { recursive: true });
  const removed = home.sweepCrewTaskHomes(db).sort();
  assert.deepEqual(removed, ['done1', 'fail1', 'gone1', 'task1', 'task2', 'task3'].sort());
  assert.ok(existsSync(home.crewTaskHomeDir('open1')));
  assert.ok(existsSync(home.crewTaskHomeDir('asks1')));
  assert.ok(!existsSync(join(process.env.DATA_DIR, 'crew-coder', 'bad name')));
  assert.equal(home.removeCrewTaskHome('open1'), true);
  assert.ok(!existsSync(join(process.env.DATA_DIR, 'crew-coder', 'open1')));
});

test('the daily retention purge removes the homes of the tasks it deletes, and only those', async () => {
  const { purgeExpiredCrewHistory } = await import('../server/services/crew.js');
  db.prepare("INSERT INTO crew_tasks (id, from_agent_id, to_agent_id, title, state, updated_at) VALUES ('expired1', 1, 2, 't', 'working', datetime('now','-31 days'))").run();
  db.prepare("INSERT INTO crew_tasks (id, from_agent_id, to_agent_id, title, state) VALUES ('fresh1', 1, 2, 't', 'working')").run();
  home.prepareCrewTaskHome('expired1', {});
  home.prepareCrewTaskHome('fresh1', {});
  const r = purgeExpiredCrewHistory(db);
  assert.equal(r.tasks, 1);
  assert.ok(!existsSync(join(process.env.DATA_DIR, 'crew-coder', 'expired1')), 'the purged task keeps no home until restart');
  assert.ok(existsSync(home.crewTaskHomeDir('fresh1')), 'a task the purge kept keeps its home');
});
