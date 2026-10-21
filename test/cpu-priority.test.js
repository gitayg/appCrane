import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Under CPU contention Caddy, sshd and AppCrane must win over containers: every
// container AppCrane starts carries a low --cpu-shares weight (databases above
// apps, builds lowest), builds are capped, managed databases get a CPU cap, and
// the host services get CPUWeight=1000 through an idempotent systemd drop-in.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-cpu-prio-'));
process.env.ENCRYPTION_KEY = 'p'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const argv = process.argv.slice(2);\n' +
  'require("fs").appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.map(a => a + "\\n").join("") + "\\0");\n' +
  'if (argv[0] === "network" && argv[1] === "inspect") { process.stdout.write("false|172.20.0.0/16\\n"); process.exit(0); }\n' +
  'if (argv[0] === "buildx") { process.stdout.write("github.com/docker/buildx v0.35.0 abc\\n"); process.exit(0); }\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 });
writeFileSync(join(SHIM_DIR, 'nixpacks'),
  '#!/bin/sh\nif [ "$1" = build ] && [ "$2" = --help ]; then echo "      --cpu-quota <CPU_QUOTA>"; echo "      --memory <MEMORY>"; fi\nexit 0\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const prio = await import('../server/services/cpuPriority.js');

function runs(kind) {
  return readFileSync(ARGV_LOG, 'utf8').split('\0').map((r) => r.split('\n').filter(Boolean)).filter((c) => c[0] === kind);
}

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : (p.endsWith('.js') ? [p] : []);
  });
}

test('weights order host services over databases over apps over builds', () => {
  assert.deepEqual(prio.CPU_SHARES, { app: 128, db: 256, build: 2 });
  assert.equal(prio.CPU_APP_FLAG, '--cpu-shares=128');
  assert.equal(prio.CPU_DB_FLAG, '--cpu-shares=256');
  assert.ok(prio.HOST_CPU_WEIGHT >= 1000 && prio.HOST_CPU_WEIGHT <= 10000, 'systemd range 1..10000');
});

test('no `docker run` argv builder in server/ omits the CPU weight flag', () => {
  const builders = [];
  const missing = [];
  for (const file of walk(join(ROOT, 'server'))) {
    const src = readFileSync(file, 'utf8');
    const starts = [...src.matchAll(/\[\s*'run',\s*'(?:-d|-i|--rm)'/g)].map((m) => m.index);
    starts.forEach((at, i) => {
      const where = `${file.slice(ROOT.length + 1)}:${src.slice(0, at).split('\n').length}`;
      builders.push(where);
      const window = src.slice(at, Math.min(at + 2500, starts[i + 1] ?? Infinity));
      if (!/CPU_(APP|DB)_FLAG/.test(window)) missing.push(where);
    });
  }
  assert.ok(builders.length >= 15, `found only ${builders.length} builders: ${builders.join(', ')}`);
  assert.deepEqual(missing, [], `docker run builders without --cpu-shares: ${missing.join(', ')}`);
});

test('managed databases: database weight, and a CPU cap on both server builders', () => {
  for (const f of ['server/services/managedDb.js', 'server/services/managedDbDumpCmd.js']) {
    const src = readFileSync(join(ROOT, f), 'utf8');
    assert.match(src, /CPU_DB_FLAG/, f);
    assert.doesNotMatch(src, /CPU_APP_FLAG/, f);
  }
  const src = readFileSync(join(ROOT, 'server/services/managedDb.js'), 'utf8');
  const shared = /'--label', `appcrane-db=\$\{engine\}`,[\s\S]*?\];/.exec(src)?.[0] || '';
  assert.match(shared, /CPU_DB_FLAG,\s*`--cpus=\$\{cfg\.cpus\}`/, 'shared server argv carries --cpus');
  const redis = /'--label', 'appcrane-db=redis',[\s\S]*?\];/.exec(src)?.[0] || '';
  assert.match(redis, /CPU_DB_FLAG,\s*`--cpus=\$\{ENGINES\.redis\.cpus\}`/, 'redis argv carries --cpus');
  assert.equal((src.match(/cpus: dbCpus\('(postgres|mariadb|mongo|redis)'\)/g) || []).length, 4, 'every engine has a CPU cap');
  assert.doesNotMatch(/function serverConfigLabel[\s\S]*?\n}\n/.exec(src)[0], /cpus/i,
    'the CPU cap is not in the config label, so an upgrade does not recreate live databases');
});

test('argv: app container and helpers carry the weight', async () => {
  const docker = await import('../server/services/docker.js');
  const { initDb, getDb } = await import('../server/db.js');
  initDb();
  getDb().prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off'), ('cpu_admission_mode', 'off')").run();
  await docker.startApp({ slug: 'cpuapp', env: 'production', image: 'nginx:1', hostPort: 39102, memoryMb: 256 });
  const run = runs('run');
  assert.equal(run.length, 1);
  assert.ok(run[0].includes('--cpu-shares=128'), run[0].join(' '));
  assert.ok(run[0].includes('--cpus=0.5'), 'the hard cap is unchanged');

  const { helperRunArgs } = await import('../server/services/builder/workspaceRunner.js');
  const ws = mkdtempSync(join(tmpdir(), 'crane-cpu-ws-'));
  assert.ok(helperRunArgs({ workspaceDir: ws, name: 'x', argv: ['true'], memory: '256m' }).includes('--cpu-shares=128'));
  const { buildDockerArgs } = await import('../server/services/mcpStdioBridge.js');
  assert.ok(buildDockerArgs({ image: 'ghcr.io/x/y:1' }).args.includes('--cpu-shares=128'));
  const { redisSwapArgs } = await import('../server/services/managedDbDumpCmd.js');
  assert.ok(redisSwapArgs({ hostDir: '/tmp/r', image: 'redis:7' }).includes('--cpu-shares=256'));
});

test('build limits: every core but one, at least one; env overrides', () => {
  const GiB = 1024 ** 3;
  assert.deepEqual(prio.buildLimits({ env: {}, cores: 2, totalBytes: 4 * GiB }), { cpus: 1, memoryMb: 3072, cpusSource: 'default' });
  assert.equal(prio.buildLimits({ env: {}, cores: 1, totalBytes: 2 * GiB }).cpus, 1);
  assert.equal(prio.buildLimits({ env: {}, cores: 8, totalBytes: 32 * GiB }).cpus, 7);
  assert.equal(prio.buildLimits({ env: {}, cores: 8, totalBytes: 1 * GiB }).memoryMb, 1024, 'never below 1 GiB');
  const o = prio.buildLimits({ env: { APPCRANE_BUILD_CPUS: '1.5', APPCRANE_BUILD_MEMORY_MB: '2048' }, cores: 8, totalBytes: 32 * GiB });
  assert.deepEqual(o, { cpus: 1.5, memoryMb: 2048, cpusSource: 'env' });
  assert.equal(prio.buildLimits({ env: { APPCRANE_BUILD_CPUS: 'lots' }, cores: 4, totalBytes: 8 * GiB }).cpus, 3, 'junk falls back');
  assert.deepEqual(prio.buildResourceArgs({ cpus: 1.5, memoryMb: 2048 }),
    ['--cpu-period=100000', '--cpu-quota=150000', '--cpu-shares=2', '--memory=2048m', '--memory-swap=2048m']);
  assert.deepEqual(prio.nixpacksResourceArgs({ cpus: 1, memoryMb: 3072 }), ['--cpu-quota', '100000', '--memory', '3072m']);
});

test('argv: docker build carries the CPU and memory cap', async () => {
  process.env.APPCRANE_BUILD_CPUS = '1';
  process.env.APPCRANE_BUILD_MEMORY_MB = '1536';
  const docker = await import('../server/services/docker.js');
  const ctx = mkdtempSync(join(tmpdir(), 'crane-cpu-build-'));
  await docker.buildImage({ slug: 'b', env: 'production', contextDir: ctx, commitHash: 'abc' });
  const build = runs('build').at(-1);
  for (const f of ['--cpu-period=100000', '--cpu-quota=100000', '--cpu-shares=2', '--memory=1536m', '--memory-swap=1536m']) {
    assert.ok(build.includes(f), `${f} missing from ${build.join(' ')}`);
  }
  assert.ok(!build.some((a) => a.startsWith('--resource')), '--resource breaks buildx < 0.35');
  delete process.env.APPCRANE_BUILD_CPUS;
  delete process.env.APPCRANE_BUILD_MEMORY_MB;
});

test('nixpacks: caps only when the binary has the flags', async () => {
  const nix = await import('../server/services/nixpacks.js');
  nix.resetNixpacksProbe();
  assert.equal(await nix.nixpacksSupportsResourceFlags(), true);
  const withCaps = nix.nixpacksArgs({ releaseDir: '/r', tag: 't', slug: 's', env: 'production', withResources: true });
  assert.ok(withCaps.includes('--cpu-quota') && withCaps.includes('--memory'), withCaps.join(' '));
  const without = nix.nixpacksArgs({ releaseDir: '/r', tag: 't', slug: 's', env: 'production', withResources: false });
  assert.ok(!without.includes('--cpu-quota'), 'an old nixpacks would reject the flag');
});

test('build cap status: classic and buildx >= 0.35 enforce, older buildx does not', async () => {
  assert.equal(prio.buildCapStatus({ buildkit: false }).enforced, true);
  assert.equal(prio.buildCapStatus({ buildkit: true, buildxVersion: 'github.com/docker/buildx v0.35.0-desktop.2 b5' }).enforced, true);
  assert.equal(prio.buildCapStatus({ buildkit: true, buildxVersion: 'github.com/docker/buildx v0.29.1 a' }).enforced, false);
  assert.equal(prio.buildCapStatus({ buildkit: true, buildxVersion: 'garbage' }).enforced, null);
  const s = await prio.readBuildCapStatus({ env: {}, exec: async () => 'github.com/docker/buildx v0.17.1 x' });
  assert.equal(s.buildkit, true);
  assert.equal(s.enforced, false);
});

function fakeHost({ uid = 0, units = ['appcrane.service', 'caddy.service', 'ssh.service'] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'crane-systemd-'));
  for (const u of units) writeFileSync(join(dir, u), '[Service]\n');
  const calls = [];
  return {
    dir, calls,
    opts: { unitDir: dir, platform: 'linux', uid, isSystemd: () => true, run: (cmd, args) => calls.push([cmd, ...args].join(' ')) },
  };
}

test('drop-in: written with the right content, daemon-reload once, then idempotent', () => {
  const h = fakeHost();
  const r = prio.ensureHostCpuPriority(h.opts);
  assert.equal(r.status, 'set');
  assert.deepEqual(r.written, ['appcrane.service', 'caddy.service', 'ssh.service'], 'sshd.service absent here, so skipped');
  for (const u of r.written) {
    assert.equal(readFileSync(join(h.dir, `${u}.d`, prio.DROPIN_NAME), 'utf8'), prio.dropInContent());
  }
  assert.match(prio.dropInContent(), /^\[Service\]\nCPUWeight=1000\n$/m);
  assert.equal(h.calls.filter((c) => c === 'systemctl daemon-reload').length, 1);
  assert.ok(h.calls.includes('systemctl set-property --runtime caddy.service CPUWeight=1000'), h.calls.join('; '));

  h.calls.length = 0;
  const again = prio.ensureHostCpuPriority(h.opts);
  assert.equal(again.status, 'already');
  assert.deepEqual(h.calls, [], 'no reload when nothing changed');

  writeFileSync(join(h.dir, 'caddy.service.d', prio.DROPIN_NAME), '[Service]\nCPUWeight=50\n');
  const fixed = prio.ensureHostCpuPriority(h.opts);
  assert.deepEqual(fixed.written, ['caddy.service'], 'only the changed file is rewritten');
  assert.equal(h.calls.filter((c) => c === 'systemctl daemon-reload').length, 1);
});

test('drop-in: not root reports what to do and writes nothing; non-Linux is unsupported; never throws', () => {
  const h = fakeHost({ uid: 1001 });
  const r = prio.ensureHostCpuPriority(h.opts);
  assert.equal(r.status, 'not-permitted');
  assert.match(r.reason, /CPUWeight=1000/);
  assert.ok(!existsSync(join(h.dir, 'caddy.service.d')));
  assert.deepEqual(h.calls, []);
  assert.equal(prio.ensureHostCpuPriority({ ...h.opts, platform: 'darwin' }).status, 'unsupported');
  assert.equal(prio.ensureHostCpuPriority({ ...h.opts, isSystemd: () => false }).status, 'unsupported');
  const broken = prio.ensureHostCpuPriority({ ...fakeHost().opts, run: () => { throw new Error('dbus down'); } });
  assert.equal(broken.status, 'failed');
});

test('install.sh: the appcrane unit gets CPUWeight=1000 and Caddy/SSH get the same drop-in', () => {
  const src = readFileSync(join(ROOT, 'install.sh'), 'utf8');
  const unit = /cat > \/etc\/systemd\/system\/appcrane\.service <<'?UNIT'?\n([\s\S]*?)\nUNIT\n/.exec(src);
  assert.match(unit[1], /\[Service\][\s\S]*\nCPUWeight=1000\n[\s\S]*\[Install\]/);
  assert.match(src, /for unit in caddy\.service ssh\.service sshd\.service; do[\s\S]*50-appcrane-cpu-priority\.conf/);
  assert.match(src, /'\[Service\]' 'CPUWeight=1000'/);
});

test('resource drift: a managed database without the CPU cap or weight is reported, unknown stays unknown', async () => {
  const { managedDbCpuDrift } = await import('../server/services/resourceDrift.js');
  const none = managedDbCpuDrift(1, { nano_cpus: 0, cpu_shares: 0 });
  assert.equal(none.applied, false);
  assert.deepEqual(none.findings.map((f) => `${f.resource}:${f.state}`), ['cpu:not_applied', 'cpu_weight:not_applied']);
  assert.match(none.findings[0].message, /next time the server is created/);
  assert.equal(managedDbCpuDrift(1, { nano_cpus: 1e9, cpu_shares: 256 }).applied, true);
  assert.equal(managedDbCpuDrift(1, { nano_cpus: 2e9, cpu_shares: 256 }).findings[0].state, 'stale');
  assert.deepEqual(managedDbCpuDrift(1, { nano_cpus: null, cpu_shares: null }), { applied: null, findings: [] });
});

test('Job Health: the CPU reservation resource reports a missing drop-in and unweighted containers, without mail', async () => {
  const { sampleCpuPriority } = await import('../server/services/hostResources.js');
  const bad = sampleCpuPriority({
    hostCpuPriority: () => ({ status: 'not-permitted', reason: 'not root', units: ['caddy.service'] }),
    cpuMeasurement: () => ({ error: null, committedCores: 1, capacityCores: 1.5, containers: [{ ours: true, shares: 0, label: 'managed postgres' }, { ours: true, shares: 128, label: 'a (production)' }] }),
  });
  assert.equal(bad.level, 'warning');
  assert.equal(bad.notify, false);
  assert.deepEqual(bad.unweighted, ['managed postgres']);
  assert.match(bad.detail, /not root/);
  const good = sampleCpuPriority({
    hostCpuPriority: () => ({ status: 'already', units: ['caddy.service'] }),
    cpuMeasurement: () => ({ error: null, committedCores: 1, capacityCores: 1.5, containers: [{ ours: true, shares: 256, label: 'db' }] }),
  });
  assert.equal(good.level, 'ok');
  assert.equal(sampleCpuPriority({ hostCpuPriority: () => null, cpuMeasurement: () => null }).level, 'unknown');
});
