import { test } from 'node:test';
import assert from 'node:assert/strict';

// Runtime advisory matching (PHP2Shell), the Docker Hub digest check, and the
// Dockerfile parsing the fresh-base build relies on. No network: OSV and the
// registry are stubbed with records shaped like the real ones.

const A = await import('../server/services/autoPatch/runtimeAdvisories.js');
const R = await import('../server/services/autoPatch/runtimeRegistry.js');
const I = await import('../server/services/autoPatch/runtimeImages.js');

const EVENTS = [
  { introduced: '0' }, { fixed: '8.2.35' }, { introduced: '8.3.0' }, { fixed: '8.3.36' },
  { introduced: '8.4.0' }, { fixed: '8.4.27' }, { introduced: '8.5.0' }, { fixed: '8.5.12' },
];
// The shape OSV /v1/query returned for {php, Bitnami} on 2026-10-22.
const OSV_PHP2SHELL = [
  { id: 'BIT-php-2026-109618', aliases: ['BIT-libphp-2026-109618', 'CVE-2026-109618'], summary: 'RCE via OOM corruption',
    details: 'Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).',
    affected: [{ package: { name: 'php', ecosystem: 'Bitnami' }, ranges: [{ type: 'SEMVER', events: EVENTS }] }] },
  { id: 'BIT-php-2026-109619', aliases: ['CVE-2026-109619'], summary: 'RCE via stale global state',
    details: 'Multiple strategies can trigger this condition and produce remote code execution (RCE).',
    affected: [{ package: { name: 'php', ecosystem: 'Bitnami' }, ranges: [{ type: 'SEMVER', events: EVENTS }] }] },
  { id: 'BIT-php-2026-6735', aliases: ['CVE-2026-6735'], summary: 'XSS within PHP-FPM status endpoint',
    affected: [{ package: { name: 'php', ecosystem: 'Bitnami' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.0.0' }] }] }] },
];

test('PHP version parsing and ordering', () => {
  assert.deepEqual(A.parseVersion('8.3.36'), [8, 3, 36, 0]);
  assert.deepEqual(A.parseVersion('8.5.0RC2'), [8, 5, 0, 1]);
  assert.equal(A.parseVersion('banana'), null);
  assert.equal(A.compareVersions('8.3.35', '8.3.36'), -1);
  assert.equal(A.compareVersions('8.3.36', '8.3.36'), 0);
  assert.equal(A.compareVersions('8.10.0', '8.9.9'), 1);
  assert.equal(A.compareVersions('8.5.0RC2', '8.5.0'), -1);
  assert.equal(A.branchOf('8.4.27'), '8.4');
});

test('PHP2Shell matching table (OSV records)', async () => {
  const table = [
    ['8.3.35', true, '8.3.36', false],
    ['8.3.36', false, null, false],
    ['8.5.11', true, '8.5.12', false],
    ['8.5.12', false, null, false],
    ['8.4.26', true, '8.4.27', false],
    ['8.2.34', true, '8.2.35', false],
    ['8.1.31', true, null, true],
    ['7.4.33', true, null, true],
  ];
  for (const [v, affected, fixed, unsupported] of table) {
    const r = await A.runtimeAdvisories('php', v, { osvRecords: OSV_PHP2SHELL, bundled: { advisories: [] } });
    assert.equal(r.affected, affected, v);
    assert.equal(r.fixedVersion, fixed, v);
    assert.equal(r.unsupportedBranch, unsupported, v);
    if (affected) assert.deepEqual(r.advisories.map((a) => a.id), ['CVE-2026-109618', 'CVE-2026-109619'], `${v}: the XSS advisory is not code execution`);
  }
});

test('OSV unreachable: the bundled list still knows PHP2Shell', async () => {
  const r = await A.runtimeAdvisories('php', '8.3.35', { fetchFn: async () => { throw new Error('offline'); } });
  assert.equal(r.osv, 'unreachable');
  assert.equal(r.affected, true);
  assert.equal(r.fixedVersion, '8.3.36');
  assert.deepEqual(r.advisories.map((a) => [a.id, a.source]), [['CVE-2026-109618', 'bundled'], ['CVE-2026-109619', 'bundled']]);
  const ok = await A.runtimeAdvisories('php', '8.3.36', { fetchFn: async () => { throw new Error('offline'); } });
  assert.equal(ok.affected, false);
});

test('OSV reachable: its record wins over the bundled copy of the same CVE', async () => {
  let body;
  const fetchFn = async (url, init) => { body = JSON.parse(init.body); return { ok: true, json: async () => ({ vulns: OSV_PHP2SHELL }) }; };
  const r = await A.runtimeAdvisories('php', '8.4.26', { fetchFn });
  assert.deepEqual(body, { package: { ecosystem: 'Bitnami', name: 'php' }, version: '8.4.26' });
  assert.equal(r.osv, 'ok');
  assert.deepEqual(r.advisories.map((a) => a.source), ['osv', 'osv']);
});

test('the bundled list carries sources for every advisory', () => {
  const b = A.loadBundled();
  assert.ok(b.version >= 1);
  for (const a of b.advisories) {
    assert.ok(a.sources.length >= 2, a.id);
    assert.ok(a.sources.some((s) => s.startsWith('https://osv.dev/')), a.id);
  }
});

test('Docker Hub digest: token, then HEAD on the manifest; other registries are not checked', async () => {
  const seen = [];
  const fetchFn = async (url, init = {}) => {
    seen.push([init.method || 'GET', url]);
    if (url.startsWith('https://auth.docker.io/')) return { ok: true, json: async () => ({ token: 'tkn' }) };
    assert.equal(init.headers.Authorization, 'Bearer tkn');
    assert.match(init.headers.Accept, /^application\/vnd\.oci\.image\.index\.v1\+json/);
    return { ok: true, headers: new Map([['docker-content-digest', `sha256:${'ab'.repeat(32)}`]]) };
  };
  assert.equal(await R.currentDigest('php:8.3-apache', fetchFn), `sha256:${'ab'.repeat(32)}`);
  assert.deepEqual(seen, [
    ['GET', 'https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fphp%3Apull'],
    ['HEAD', 'https://registry-1.docker.io/v2/library/php/manifests/8.3-apache'],
  ]);
  await assert.rejects(R.currentDigest('ghcr.io/acme/php:8.3', fetchFn), R.UnsupportedRegistry);
  await assert.rejects(R.currentDigest(`php@sha256:${'cd'.repeat(32)}`, fetchFn), R.UnsupportedRegistry);
});

test('Dockerfile parsing: stages, scratch, ARGs, and the final base', () => {
  const f = I.parseFroms('ARG V\nFROM --platform=linux/amd64 node:22-alpine AS build\nRUN x\nFROM build AS mid\nFROM php:${V}-apache AS other\nFROM mid\n');
  assert.deepEqual(I.pullPlan(f), { pull: ['node:22-alpine'], unreadable: true });
  assert.equal(I.finalBase(f), 'node:22-alpine');
  assert.equal(I.finalBase(I.parseFroms('FROM golang AS b\nFROM scratch\n')), null);
  assert.deepEqual(I.normalizeRef('php:8.3-apache'), { registry: 'docker.io', repo: 'library/php', tag: '8.3-apache', digest: null });
  assert.deepEqual(I.normalizeRef('localhost:5999/x/y:1'), { registry: 'localhost:5999', repo: 'x/y', tag: '1', digest: null });
  assert.equal(I.digestFor('php:8.3-apache', ['other@sha256:00', 'php@sha256:11']), 'sha256:11');
  assert.equal(I.isPullFailure('failed to resolve source metadata for x'), true);
  assert.equal(I.isPullFailure('RUN npm ci returned a non-zero code: 1'), false);
});
