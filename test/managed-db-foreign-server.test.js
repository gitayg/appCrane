import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import crypto from 'crypto';

// A MariaDB server AppCrane did not start with its password must be refused
// by name, not adopted. Before v2.92.3 ensureServer() adopted any RUNNING
// container with the expected name, wrote its own root password into
// /root/.my.cnf, and the first SQL statement later failed with a bare
// "ERROR 1045 (28000): Access denied for user 'root'@'localhost'", with
// nothing naming the server or the cause. This starts exactly that container.

const SUFFIX = crypto.randomBytes(4).toString('hex');
const PREFIX = `appcrane-foreigntest-${SUFFIX}`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-foreign-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
process.env.MANAGED_DB_MARIADB_PORT = String(43700 + (parseInt(SUFFIX, 16) % 200));

let dockerOk = false;
try {
  execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' });
  dockerOk = true;
} catch (_) { /* left false */ }
const noDocker = dockerOk ? false : 'no reachable Docker daemon on this host';

const CONTAINER = `${PREFIX}-mariadb`;
after(() => {
  if (dockerOk) { try { execFileSync('docker', ['rm', '-f', CONTAINER], { stdio: 'pipe' }); } catch (_) {} }
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

test('a running MariaDB container that does not take AppCrane\'s password is refused by name', { skip: noDocker, timeout: 240000 }, async () => {
  const { initDb } = await import('../server/db.js');
  initDb();
  const mdb = await import('../server/services/managedDb.js');

  execFileSync('docker', ['run', '-d', '--name', CONTAINER, '-e', 'MARIADB_ROOT_PASSWORD=someone-elses-password',
    '-p', `127.0.0.1:${process.env.MANAGED_DB_MARIADB_PORT}:3306`, 'mariadb:11.4'], { stdio: 'pipe', timeout: 180000 });

  const err = await mdb.ensureServer('mariadb').then(() => null, (e) => e);
  assert.ok(err, 'a foreign MariaDB server was adopted and used');
  assert.match(err.message, new RegExp(`container '${CONTAINER}' refuses the root password AppCrane has on record`), err.message);
  assert.match(err.message, /already running when AppCrane looked for it/, 'the message does not say why');
  assert.match(err.message, /To fix: stop or rename that container/, 'the message does not say what to do');
  assert.match(err.message, /Access denied/, 'the server\'s own words were dropped');
});
