import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// The --env-file must not live inside the directory the database mounts.
//
// This reproduces a CI failure that macOS could not produce. The env file was
// written into the data directory, which is bind-mounted as the database's own
// volume. On Linux the server then writes into that directory as ITS uid (999
// for redis, postgres and mongo alike), and the next provision cannot rewrite
// the file in a directory it no longer owns:
//
//   managedDb: provisioning redis database failed: EACCES: permission denied,
//   open '/tmp/crane-mrds-AQcB3l/managed-db/redis/crane_a1/.init-env'
//
// Docker Desktop's file sharing remaps ownership to the invoking user, so the
// identical code passed locally on macOS and failed on the first real Linux
// runner. Watchdog had been green on every previous release.
//
// The second defect was silent on BOTH platforms and is the worse one: a file
// containing the superuser password sat inside the volume the database mounts,
// so the database process could read its own init credential back off
// /data/.init-env for the life of the container. Nothing ever needed it there —
// `docker run --env-file` reads the file on the HOST, before the container
// exists.
//
// Asserted against the source rather than by provisioning, so it runs on a box
// with no Docker daemon — which is exactly where the regression would otherwise
// go unnoticed until CI.

const src = readFileSync(new URL('../server/services/managedDb.js', import.meta.url), 'utf8');

test('no env file is written into a directory that is also bind-mounted', () => {
  // The precise shape of the bug: `join(dir, ...)` where `dir` is the same
  // variable passed to `-v ${dir}:...`.
  assert.doesNotMatch(src, /const envFile = join\(dir,/,
    'the env file is being written into `dir`, which is bind-mounted as the container volume — ' +
    'on Linux the server takes ownership of that directory and the next provision gets EACCES, ' +
    'and meanwhile the database can read its own superuser password out of its data volume');
});

test('both provision paths route through the shared helper', () => {
  // Two call sites had the identical line; fixing one would have left the other
  // failing on Linux only, which is the hardest kind of half-fix to notice.
  const uses = [...src.matchAll(/const envFile = envFileFor\(/g)];
  assert.equal(uses.length, 2,
    `expected both the shared-server and per-scope paths to use envFileFor(); found ${uses.length}`);
});

test('the helper places env files outside the data directory and locks the directory down', () => {
  const fn = /function envFileFor\([\s\S]*?\n\}/.exec(src);
  assert.ok(fn, 'envFileFor was renamed or removed — update this test deliberately');

  assert.match(fn[0], /'_env'/,
    'env files must live in a sibling directory, not in the mounted data directory');
  assert.match(fn[0], /mode: 0o700/,
    'the directory holding superuser passwords must not be world- or group-readable');
});

test('the secret file itself is still written 0600', () => {
  // Moving it out of the volume must not lose the mode it already had.
  // Scanned to the END OF THE STATEMENT, not to the first ')'. A lazy match on
  // ')' stops inside `mongo.envFileBody(adminPassword)` and never reaches the
  // options object — which is how the first version of this test reported a
  // false failure against code that was correct.
  const writes = [];
  for (const m of src.matchAll(/writeFileSync\(\s*\n?\s*envFile\b/g)) {
    const end = src.indexOf(');', m.index);
    writes.push(src.slice(m.index, end + 2));
  }
  assert.equal(writes.length, 2, `expected two env-file writes; found ${writes.length}`);
  for (const w of writes) {
    assert.match(w, /mode: 0o600/,
      `an env-file write lost its 0600 mode — it holds a superuser password: ${w.slice(0, 140)}`);
  }
});

test('the per-scope path still namespaces by database name', () => {
  // One file per Redis instance. A shared filename would mean two instances
  // racing on one path, and the second provision silently overwriting the
  // first instance's password file while that container still runs.
  const fn = /function envFileFor\([\s\S]*?\n\}/.exec(src)[0];
  assert.match(fn, /assertIdent\(dbName\)/,
    'the per-scope env file must be named by the database, and that name must be validated — ' +
    'it becomes a path segment');
});
