import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Under whole-host OOM the kernel must pick app containers before AppCrane,
// sshd or the security agent: every container AppCrane starts carries a
// positive --oom-score-adj (databases lower than apps), and AppCrane itself
// runs with a negative one.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-oom-'));
process.env.ENCRYPTION_KEY = 'o'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const argv = process.argv.slice(2);\n' +
  'require("fs").appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.map(a => a + "\\n").join("") + "\\0");\n' +
  'if (argv[0] === "network" && argv[1] === "inspect") { process.stdout.write("false|172.20.0.0/16\\n"); process.exit(0); }\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { OOM_SCORE_ADJ, OOM_APP_FLAG, OOM_DB_FLAG } = await import('../server/services/oomPriority.js');
const { protectFromOom, APPCRANE_OOM_SCORE_ADJ } = await import('../server/services/oomSelfProtect.js');

test('the adjustments are inside the range docker accepts and order apps before databases before the host', () => {
  assert.ok(OOM_SCORE_ADJ.app > OOM_SCORE_ADJ.db && OOM_SCORE_ADJ.db > 0, 'positive needs no privilege');
  assert.ok(OOM_SCORE_ADJ.app <= 1000);
  assert.ok(APPCRANE_OOM_SCORE_ADJ < 0 && APPCRANE_OOM_SCORE_ADJ >= -1000);
  assert.equal(OOM_APP_FLAG, '--oom-score-adj=500');
  assert.equal(OOM_DB_FLAG, '--oom-score-adj=300');
});

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : (p.endsWith('.js') ? [p] : []);
  });
}

test('no `docker run` argv builder in server/ omits the OOM priority flag', () => {
  const builders = [];
  const missing = [];
  for (const file of walk(join(ROOT, 'server'))) {
    const src = readFileSync(file, 'utf8');
    const re = /\[\s*'run',\s*'(?:-d|-i|--rm)'/g;
    const starts = [...src.matchAll(re)].map((m) => m.index);
    starts.forEach((at, i) => {
      const where = `${file.slice(ROOT.length + 1)}:${src.slice(0, at).split('\n').length}`;
      builders.push(where);
      // Up to 2500 characters (startApp's argv carries long comments), never
      // reaching into the next builder, so one builder's flag cannot vouch for another.
      const window = src.slice(at, Math.min(at + 2500, starts[i + 1] ?? Infinity));
      if (!/OOM_(APP|DB)_FLAG/.test(window)) missing.push(where);
    });
  }
  assert.ok(builders.length >= 15, `found only ${builders.length} builders; the scan is not seeing them: ${builders.join(', ')}`);
  assert.deepEqual(missing, [], `docker run builders without --oom-score-adj: ${missing.join(', ')}`);
});

test('managed databases get the database value, not the app value', () => {
  for (const f of ['server/services/managedDb.js', 'server/services/managedDbDumpCmd.js']) {
    const src = readFileSync(join(ROOT, f), 'utf8');
    assert.match(src, /OOM_DB_FLAG/, f);
    assert.doesNotMatch(src, /OOM_APP_FLAG/, f);
  }
});

test('argv: app container, helper builders and the redis restore helper carry the flag', async () => {
  const docker = await import('../server/services/docker.js');
  const { _resetMemoryAdmissionForTests } = await import('../server/services/memoryAdmission.js');
  const { initDb, getDb } = await import('../server/db.js');
  initDb();
  getDb().prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
  _resetMemoryAdmissionForTests();
  await docker.startApp({ slug: 'oomapp', env: 'production', image: 'nginx:1', hostPort: 39101, memoryMb: 256 });
  const runs = readFileSync(ARGV_LOG, 'utf8').split('\0').map(r => r.split('\n').filter(Boolean)).filter(c => c[0] === 'run');
  assert.equal(runs.length, 1);
  assert.ok(runs[0].includes('--oom-score-adj=500'), runs[0].join(' '));

  const { helperRunArgs } = await import('../server/services/builder/workspaceRunner.js');
  const ws = mkdtempSync(join(tmpdir(), 'crane-oom-ws-'));
  assert.ok(helperRunArgs({ workspaceDir: ws, name: 'x', argv: ['true'], memory: '256m' }).includes('--oom-score-adj=500'));
  const { buildDockerArgs } = await import('../server/services/mcpStdioBridge.js');
  assert.ok(buildDockerArgs({ image: 'ghcr.io/x/y:1' }).args.includes('--oom-score-adj=500'));
  const { redisSwapArgs } = await import('../server/services/managedDbDumpCmd.js');
  assert.ok(redisSwapArgs({ hostDir: '/tmp/r', image: 'redis:7' }).includes('--oom-score-adj=300'));
});

test('install.sh writes OOMScoreAdjust=-500 into the appcrane unit', () => {
  const src = readFileSync(join(ROOT, 'install.sh'), 'utf8');
  const unit = /cat > \/etc\/systemd\/system\/appcrane\.service <<'?UNIT'?\n([\s\S]*?)\nUNIT\n/.exec(src);
  assert.ok(unit, 'unit heredoc found');
  assert.match(unit[1], /\[Service\][\s\S]*\nOOMScoreAdjust=-500\n[\s\S]*\[Install\]/);
});

test('startup self-adjust writes only when permitted and never throws', () => {
  const dir = mkdtempSync(join(tmpdir(), 'crane-oom-proc-'));
  const f = join(dir, 'oom_score_adj');

  writeFileSync(f, '0\n');
  assert.deepEqual(protectFromOom({ procFile: f, platform: 'linux', uid: 0 }), { status: 'set', value: -500, previous: 0 });
  assert.equal(readFileSync(f, 'utf8').trim(), '-500');

  writeFileSync(f, '0\n');
  const nonRoot = protectFromOom({ procFile: f, platform: 'linux', uid: 1001 });
  assert.equal(nonRoot.status, 'not-permitted');
  assert.match(nonRoot.reason, /OOMScoreAdjust=-500/);
  assert.equal(readFileSync(f, 'utf8').trim(), '0', 'not root: untouched');

  writeFileSync(f, '-900\n');
  assert.equal(protectFromOom({ procFile: f, platform: 'linux', uid: 0 }).status, 'already');
  assert.equal(readFileSync(f, 'utf8').trim(), '-900', 'an operator\'s stronger value is kept');

  assert.equal(protectFromOom({ procFile: f, platform: 'darwin', uid: 0 }).status, 'unsupported');
  assert.equal(protectFromOom({ procFile: join(dir, 'missing', 'x'), platform: 'linux', uid: 0 }).status, 'failed');
  assert.ok(existsSync(f));
});
