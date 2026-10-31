import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A memory limit changed on the Manage page used to wait in the database for
// the next deploy, and the memory warning kept reporting the old cap (31 Oct
// 2026). It now reaches the running containers with `docker update`. The real
// daemon was checked by hand: 1024 -> 512 -> 2048 MB, memory and swap equal,
// no restart.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-limits-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
const { applyLimitsLive } = await import('../server/services/applyResourceLimits.js');
const MiB = 1024 * 1024;

function fakeDocker(running) {
  const calls = [];
  const docker = async (args) => {
    calls.push(args.join(' '));
    if (args[0] === 'inspect') {
      if (!(args.at(-1) in running)) throw new Error('No such object');
      return running[args.at(-1)] ? 'true' : 'false';
    }
    return '';
  };
  return { docker, calls };
}

test('running containers get memory, equal swap and CPUs in place; stopped or missing ones are skipped', async () => {
  const { docker, calls } = fakeDocker({ 'appcrane-hub-production': true, 'appcrane-hub-sandbox': false });
  const r = await applyLimitsLive({ slug: 'hub', memoryMb: 768, cpus: 0.75 }, { docker, usage: async () => new Map() });
  assert.deepEqual(r, [{ env: 'production', applied: true }, { env: 'sandbox', applied: false, reason: 'not running' }]);
  assert.ok(calls.includes('update --memory=768m --memory-swap=768m --cpus=0.75 appcrane-hub-production'));
  assert.ok(!calls.some((c) => c.startsWith('update') && c.endsWith('sandbox')));
});

test('a container using nearly the new limit is not lowered now (it would be OOM-killed)', async () => {
  const { docker, calls } = fakeDocker({ 'appcrane-hub-production': true });
  const r = await applyLimitsLive({ slug: 'hub', memoryMb: 256, cpus: 0.5 },
    { docker, usage: async () => new Map([['appcrane-hub-production', 240 * MiB]]) });
  assert.equal(r[0].applied, false);
  assert.match(r[0].reason, /uses 240 MB.*next deploy or restart/);
  assert.ok(!calls.some((c) => c.startsWith('update')));
});

test('a refused update says the limit applies at the next deploy', async () => {
  const docker = async (args) => { if (args[0] === 'inspect') return 'true'; throw new Error('Minimum memory limit allowed is 6MB'); };
  const r = await applyLimitsLive({ slug: 'hub', memoryMb: 512, cpus: 1 }, { docker, usage: async () => new Map() });
  assert.match(r[0].reason, /Minimum memory limit.*next deploy or restart/);
});

test('the app update route applies changed limits and returns limits_applied; the Manage pages show it', () => {
  const route = readFileSync(new URL('../server/routes/apps.js', import.meta.url), 'utf8');
  assert.match(route, /if \('resource_limits' in updates\) \{[\s\S]{0,300}applyLimitsLive\(\{ slug: updated\.slug, memoryMb: lim\.max_ram_mb, cpus: lim\.max_cpu_percent \/ 100 \}\)/);
  assert.match(route, /limitsApplied \? \{ limits_applied: limitsApplied \}/);
  const list = readFileSync(new URL('../studio-web/src/pages/Applications.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(list, /\{ max_ram_mb: ram \}\)\.catch\(\(\) => \{\}\)/, 'a refused change must not be swallowed');
  assert.match(list, /limitsAppliedText\(r\?\.limits_applied\)/);
  const card = readFileSync(new URL('../studio-web/src/pages/AppManager.tsx', import.meta.url), 'utf8');
  assert.match(card, /onMsg\(limitsAppliedText\(r\?\.limits_applied\)\)/);
});
