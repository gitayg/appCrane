import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// The SECOND half of the env-file defect, which the first fix left in place.
//
// test/managed-db-envfile-location.test.js asserts that env files live in a
// `_env` directory. That is necessary and it is not sufficient, because a `_env`
// directory nested INSIDE dataDirFor(engine) is still inside the volume for the
// three shared engines: createServerContainer passes that exact directory to
// `-v ${dir}:${cfg.dataPath}`. Only redis mounts a per-instance SUBdirectory, so
// a fix measured on redis alone looks complete and is not.
//
// Measured on native Linux against postgres:16-alpine, with an env file both as
// a dotfile and as a `_env/` subdirectory of PGDATA. Both give the identical
// result, and the container never starts:
//
//   === dotfile: exited exit=1
//   initdb: error: directory "/var/lib/postgresql/data" exists but is not empty
//   === envdir: exited exit=1
//   initdb: error: directory "/var/lib/postgresql/data" exists but is not empty
//
// At HEAD this was a RACE, not a hard failure, which is why it read as flakiness
// rather than as a bug: `createServerContainer` deletes the env file in a
// `finally` immediately after `docker run -d` returns, and initdb's emptiness
// check happens a few hundred milliseconds later inside the container. A fast
// box wins the race and the server comes up; a loaded CI runner loses it and
// `test/managed-db.test.js` dies on its 120-second timeout with no explanation
// attached. Putting the file outside the volume removes the race rather than
// widening it.
//
// Asserted against the source, in the same style and for the same reason as the
// sibling file: it must fail on a box with no Docker daemon, because the live
// symptom is a two-minute timeout whose message names neither postgres nor the
// env file.

const src = readFileSync(new URL('../server/services/managedDb.js', import.meta.url), 'utf8');

const bodyOf = (name) => {
  const m = new RegExp(`(?:async )?function ${name}\\([\\s\\S]*?\\n\\}`).exec(src);
  assert.ok(m, `${name} was renamed or removed — update this test deliberately`);
  return m[0];
};

test('dataDirFor(engine) IS the bind-mounted volume, which is what makes the rule below matter', () => {
  const create = bodyOf('createServerContainer');
  assert.match(create, /const dir = dataDirFor\(engine\);/,
    'createServerContainer no longer derives its data directory from dataDirFor');
  assert.match(create, /'-v', `\$\{dir\}:\$\{cfg\.dataPath\}`/,
    'the shared-server data directory is no longer bind-mounted from `dir` — if the mount moved, ' +
    'the invariant this file guards moved with it and this test has to be rewritten, not deleted');
});

test('envFileFor never builds its path from the directory the container mounts', () => {
  // Comments stripped first: this function's own comment explains what
  // dataDirFor is, and matching that would make the test pass or fail on prose.
  const fn = bodyOf('envFileFor').replace(/^\s*\/\/.*$/gm, '');
  assert.doesNotMatch(fn, /dataDirFor/,
    'envFileFor is deriving its directory from dataDirFor(engine), which createServerContainer ' +
    'bind-mounts as the database volume. A `_env` subdirectory of it is still inside the volume: ' +
    'postgres refuses to initialise ("directory ... exists but is not empty"), and the superuser ' +
    'password is readable by the database process for the life of the container');
});

test('the env root and the data directories are siblings under one managed-db root', () => {
  // Sibling, stated as code rather than as a comment: both are built from
  // managedDbRoot(), so neither can be an ancestor of the other.
  assert.match(bodyOf('managedDbRoot'), /join\(resolve\(process\.env\.DATA_DIR \|\| '\.\/data'\), 'managed-db'\)/);
  assert.match(bodyOf('dataDirFor'), /join\(managedDbRoot\(\), engine\)/);
  assert.match(bodyOf('envFileFor'), /join\(managedDbRoot\(\), '_env', engine\)/);
});
