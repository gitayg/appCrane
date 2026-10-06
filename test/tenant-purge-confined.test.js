import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Commit review of v2.97.2 (M3): purgeTenant lstat-checked the tenant path and
// then rmSync'ed it on the HOST. The app is usually running during a purge (it
// happens on revoke), so its code could swap tenants/<org> for a link between
// the check and the delete. When the app has a container, the delete now runs
// inside a throwaway helper container that mounts only the app's shared/data:
// a planted link resolves inside that container, never on the host.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-purge-confined-'));
const SHIM = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify(args) + '\\n');
if (args[0] === 'inspect') {
  if (args[args.length - 1].endsWith('-sandbox')) { process.stderr.write('Error: No such object\\n'); process.exit(1); }
  process.stdout.write('example/app:1\\n'); process.exit(0);
}
process.exit(0);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { purgeTenant } = await import('../server/services/tenants.js');

test('with a container, the purge runs inside a confined helper, never on the host path', async () => {
  const base = join(process.env.DATA_DIR, 'apps', 'mine', 'production', 'shared', 'data');
  const tenant = join(base, 'tenants', 'acme.test', 'u5');
  mkdirSync(tenant, { recursive: true });
  writeFileSync(join(tenant, 'db.sqlite'), 'MINE');

  await purgeTenant('mine', 'dana@acme.test', 5);

  const run = readFileSync(LOG, 'utf8').trim().split('\n').map(JSON.parse).find(a => a[0] === 'run');
  assert.ok(run, 'no helper container was run');
  assert.ok(run.includes('--network') && run[run.indexOf('--network') + 1] === 'none', 'the helper has network access');
  assert.ok(run.includes(`${base}:/target`) || run.some(a => a === `${base}:/target`), `the helper does not mount exactly the app's data: ${run.join(' ')}`);
  assert.deepEqual(run.slice(-3), ['-rf', '--', '/target/tenants/acme.test/u5']);
  assert.ok(existsSync(join(tenant, 'db.sqlite')), 'the host deleted the tree itself instead of leaving it to the helper');
});
