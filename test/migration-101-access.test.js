import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

// Migration 101 folds app_users into app_user_roles (v2.94.0). It must keep
// every grant that existed, in every shape the two tables could be in:
//   member + role            -> keeps the role
//   member, no role          -> becomes 'user' (could open the app before)
//   role, no member          -> keeps the role (the owner-locked-out case)
//   member + leftover 'none' -> becomes 'user' (could open the app before)
//   'none', no member        -> dropped (granted nothing)

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');
const files = readdirSync(DIR).filter(f => f.endsWith('.sql')).sort();

function dbAt(lastExcluded) {
  const db = new Database(':memory:');
  for (const f of files) {
    if (f >= lastExcluded) break;
    db.exec(readFileSync(join(DIR, f), 'utf8'));
  }
  return db;
}

test('every grant survives, in every shape the two tables could disagree in', () => {
  const db = dbAt('101-');
  db.pragma('foreign_keys = OFF');
  for (let i = 1; i <= 5; i++) db.prepare('INSERT INTO users (id,name,email,role,api_key_hash) VALUES (?,?,?,?,?)').run(i, `u${i}`, `u${i}@t.test`, 'user', `h${i}`);
  db.prepare("INSERT INTO apps (id,name,slug,slot,source_type) VALUES (1,'a','a',1,'managed')").run();
  const both = 1, memberOnly = 2, roleOnly = 3, memberNone = 4, noneOnly = 5;
  for (const u of [both, memberOnly, memberNone]) db.prepare('INSERT INTO app_users VALUES (1,?)').run(u);
  db.prepare("INSERT INTO app_user_roles VALUES (1,?,'admin')").run(both);
  db.prepare("INSERT INTO app_user_roles VALUES (1,?,'owner')").run(roleOnly);
  db.prepare("INSERT INTO app_user_roles VALUES (1,?,'none')").run(memberNone);
  db.prepare("INSERT INTO app_user_roles VALUES (1,?,'none')").run(noneOnly);

  db.exec(readFileSync(join(DIR, files.find(f => f.startsWith('101-'))), 'utf8'));

  const roles = Object.fromEntries(db.prepare('SELECT user_id, app_role FROM app_user_roles').all().map(r => [r.user_id, r.app_role]));
  assert.deepEqual(roles, { [both]: 'admin', [memberOnly]: 'user', [roleOnly]: 'owner', [memberNone]: 'user' });
  const members = db.prepare('SELECT user_id FROM app_users ORDER BY user_id').all().map(r => r.user_id);
  assert.deepEqual(members, [both, memberOnly, roleOnly, memberNone]);
  assert.equal(db.prepare("SELECT type FROM sqlite_master WHERE name = 'app_users'").get().type, 'view');
});
