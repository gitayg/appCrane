import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// The redacting access log goes to a size-rotated file, not the journal.
//
// Through v2.125.19 the `log` block had no `output`, so Caddy wrote every access
// line to stderr, which systemd hands to journald. On one production box that was
// ~19.7k JSON lines a day into a journal that reached 4 GB and helped fill the
// disk. The query-string redaction must survive the move unchanged: the file is
// still a log store, and the token aghook puts in the query must never land in it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-accesslog-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';
delete process.env.CADDY_ACCESS_LOG_FILE;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { seedApps } = await import('./fixtures/edge-hardening.seed.js');
seedApps(db);
const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
const log = (await import('../server/utils/logger.js')).default;
// The real check stats the directory; this machine (or CI) need not have
// /var/log/caddy. Each test states which branch it is on.
const DIR_PRESENT = () => true;
setAccessLogDirCheck(DIR_PRESENT);

const DEFAULT_PATH = '/var/log/caddy/access.log';
const SECRET = 'QUERYSECRET7f3a9c';

/** Every `log { … }` block in the file, as text. */
function logBlocks(text) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*log \{\s*$/.test(lines[i])) continue;
    let depth = 0;
    const buf = [];
    for (let j = i; j < lines.length; j++) {
      depth += (lines[j].match(/\{/g) || []).length - (lines[j].match(/\}/g) || []).length;
      buf.push(lines[j].trim());
      if (depth === 0) break;
    }
    out.push(buf.join('\n'));
  }
  return out;
}

test('every access log writes to a rotated file, with the query redaction intact', () => {
  const blocks = logBlocks(generateCaddyfile());
  assert.ok(blocks.length >= 1, 'no access log emitted for a seed that has a live bypass route');
  for (const b of blocks) {
    assert.match(b, new RegExp(`\\noutput file ${DEFAULT_PATH.replace(/\//g, '\\/')} \\{\\n` +
      'roll_size 50MiB\\nroll_keep 5\\nroll_keep_for 14d\\n\\}'), `log block has no rotated file output:\n${b}`);
    assert.match(b, /request>uri regexp "\\\?\.\*" "\?redacted"/, `the query redaction changed:\n${b}`);
  }
});

test('the access log is defined once: every emitted copy is byte-identical', () => {
  // Isolation on puts the block in each app-host site as well as the platform
  // site; a second hand-written copy is how one of them would lose its output.
  const set = (k, v) => db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
  set('app_isolation_domain', 'apps.example.com');
  try {
    const cf = generateCaddyfile();
    assert.match(cf, /^bypasser\.apps\.example\.com \{$/m, 'isolation did not turn on; this test would compare one copy with itself');
    const blocks = logBlocks(cf);
    assert.ok(blocks.length >= 2, `expected the platform site and an app host to log, got ${blocks.length}`);
    assert.equal(new Set(blocks).size, 1, `access log blocks differ:\n${[...new Set(blocks)].join('\n---\n')}`);
  } finally {
    set('app_isolation_domain', '');
  }
});

test('CADDY_ACCESS_LOG_FILE moves the file; anything that is not a plain absolute path is refused', () => {
  try {
    process.env.CADDY_ACCESS_LOG_FILE = '/srv/logs/caddy-access.log';
    assert.ok(logBlocks(generateCaddyfile()).every(b => b.includes('output file /srv/logs/caddy-access.log {')));
    // The value is written into the Caddyfile, so a space, brace, quote or newline
    // could add directives. Those fall back to the default rather than going in.
    for (const bad of ['relative/access.log', '/var/log/a b.log', '/x {\n}\nimport /etc/passwd', '/x"y', '/a/../b', '']) {
      process.env.CADDY_ACCESS_LOG_FILE = bad;
      const blocks = logBlocks(generateCaddyfile());
      assert.ok(blocks.every(b => b.includes(`output file ${DEFAULT_PATH} {`)), `accepted ${JSON.stringify(bad)}`);
    }
  } finally {
    delete process.env.CADDY_ACCESS_LOG_FILE;
  }
});

test('log directory missing: no file output, stderr keeps the filter, one warning per process naming the directory', () => {
  const asked = [];
  const warns = [];
  const realWarn = log.warn;
  log.warn = (m) => { warns.push(String(m)); };
  setAccessLogDirCheck((d) => { asked.push(d); return false; });
  try {
    const cf = generateCaddyfile();
    generateCaddyfile();
    assert.ok(asked.length && asked.every(d => d === '/var/log/caddy'), `checked ${JSON.stringify([...new Set(asked)])}`);
    assert.doesNotMatch(cf, /output file/, 'a file output was emitted for a directory that does not exist');
    const blocks = logBlocks(cf);
    assert.ok(blocks.length >= 1);
    for (const b of blocks) assert.match(b, /request>uri regexp "\\\?\.\*" "\?redacted"/, `filter lost on the stderr path:\n${b}`);
    // The error stream still goes through the filtered logger, not the default one.
    assert.match(cf, /\{\n    log appcrane_errors \{\n        include http\.log\.error\n        format filter \{/);
    const missing = warns.filter(w => w.includes('does not exist'));
    assert.equal(missing.length, 1, `expected one warning across two generations, got ${missing.length}: ${JSON.stringify(warns)}`);
    assert.match(missing[0], /\/var\/log\/caddy/);
  } finally {
    log.warn = realWarn;
    setAccessLogDirCheck(DIR_PRESENT);
  }
});

test('log directory present: the directory checked is the parent of CADDY_ACCESS_LOG_FILE', () => {
  const asked = new Set();
  setAccessLogDirCheck((d) => { asked.add(d); return d === '/srv/logs'; });
  try {
    process.env.CADDY_ACCESS_LOG_FILE = '/srv/logs/caddy-access.log';
    assert.match(generateCaddyfile(), /output file \/srv\/logs\/caddy-access\.log \{/);
    assert.deepEqual([...asked], ['/srv/logs']);
  } finally {
    delete process.env.CADDY_ACCESS_LOG_FILE;
    setAccessLogDirCheck(DIR_PRESENT);
  }
});

test('the default directory check really stats the directory', async () => {
  // The injectable check must not be a stub that says yes in production. A fresh
  // module instance (query-string import) carries the real statSync check.
  const fresh = await import(`../server/services/caddy.js?real=${process.pid}`);
  const real = mkdtempSync(join(tmpdir(), 'crane-logdir-'));
  try {
    process.env.CADDY_ACCESS_LOG_FILE = join(real, 'access.log');
    assert.ok(fresh.generateCaddyfile().includes(`output file ${real}/access.log {`), 'an existing directory got no file output');
    process.env.CADDY_ACCESS_LOG_FILE = join(real, 'nope', 'access.log');
    assert.doesNotMatch(fresh.generateCaddyfile(), /output file/, 'a missing directory still got a file output');
  } finally {
    delete process.env.CADDY_ACCESS_LOG_FILE;
    rmSync(real, { recursive: true, force: true });
  }
});

// ---- real Caddy ---------------------------------------------------------------

const DOCKER = (() => {
  try {
    execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 });
    execFileSync('docker', ['image', 'inspect', 'caddy:2'], { stdio: 'ignore', timeout: 15000 });
    return true;
  } catch { return false; }
})();
const noDocker = DOCKER ? false : 'docker or the caddy:2 image is not available';
const SCRATCH = mkdtempSync(join(tmpdir(), 'crane-accesslog-caddy-'));
const NAME = `crane-accesslog-${process.pid}`;
after(() => {
  try { execFileSync('docker', ['rm', '-f', NAME], { stdio: 'ignore' }); } catch (_) { /* never started */ }
  rmSync(SCRATCH, { recursive: true, force: true });
});

test('caddy:2 adapts the file writer with the rotation bounds and the unchanged filter', { skip: noDocker }, () => {
  const p = join(SCRATCH, 'Caddyfile.adapt');
  writeFileSync(p, generateCaddyfile());
  const cfg = JSON.parse(execFileSync('docker', ['run', '--rm', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2',
    'caddy', 'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'], { stdio: 'pipe', timeout: 120000 }).toString());
  const name = cfg.apps.http.servers.srv0.logs.logger_names['crane.example.com'][0];
  const lg = cfg.logging.logs[name];
  assert.deepEqual(lg.writer, { output: 'file', filename: DEFAULT_PATH, roll_size_mb: 50, roll_keep: 5, roll_keep_days: 14 });
  assert.deepEqual(lg.encoder.fields['request>uri'], { filter: 'regexp', regexp: '\\?.*', value: '?redacted' });
  assert.equal(lg.encoder.wrap.format, 'json');
  // The error stream: same filter, same file, and out of the default (stderr) logger.
  const el = cfg.logging.logs.appcrane_errors;
  assert.deepEqual(el.include, ['http.log.error']);
  assert.deepEqual(el.writer, lg.writer);
  assert.deepEqual(el.encoder, lg.encoder);
  assert.ok(cfg.logging.logs.default.exclude.includes('http.log.error'), 'error records still reach the default logger');
});

const NAME2 = `${NAME}-stderr`;
after(() => { try { execFileSync('docker', ['rm', '-f', NAME2], { stdio: 'ignore' }); } catch (_) { /* never started */ } });

/** Serve the generated file over plain HTTP in a throwaway caddy:2; returns a GET helper. */
async function startLive(name) {
  // The generated file already opens with a global block (the error logger), so
  // the test-only options go inside it: a second global block is a parse error.
  const gen = generateCaddyfile();
  assert.match(gen, /^# Managed by AppCrane[^\n]*\n\n\{\n    log appcrane_errors \{/, 'no global error logger ahead of the sites');
  const cf = gen.replace('\n\n{\n', '\n\n{\n\tauto_https off\n\tadmin off\n')
    .replace('import /etc/caddy/sites/*.caddy\n', '')
    .replace(/^(crane\.example\.com|custom\.test\.local|old\.test\.local) \{$/gm, 'http://$1:8080 {');
  const p = join(SCRATCH, `Caddyfile.${name}`);
  writeFileSync(p, cf);
  execFileSync('docker', ['run', '-d', '--name', name, '-p', '127.0.0.1::8080', '-v', `${p}:/etc/caddy/Caddyfile:ro`, 'caddy:2'], { stdio: 'pipe' });
  const port = execFileSync('docker', ['port', name, '8080/tcp']).toString().trim().split(':').pop();
  const get = (path) => execFileSync('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', '-H', 'Host: crane.example.com',
    `http://127.0.0.1:${port}${path}`], { timeout: 20000 }).toString().trim();
  let up = false;
  for (let i = 0; i < 40 && !up; i++) {
    try { up = get('/__probe') !== '000'; } catch (_) { /* starting */ }
    if (!up) await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(up, 'caddy:2 never started listening');
  return get;
}

test('live caddy:2: a bypass request with a query token is logged, redacted, to the file and not to stderr', { skip: noDocker }, async () => {
  setAccessLogDirCheck(DIR_PRESENT);
  const get = await startLive(NAME);

  // The upstream is not running, so the proxy answers 502; Caddy logs the request either way.
  get(`/bypasser/ws/runner?token=${SECRET}&x=2`);
  let file = '';
  for (let i = 0; i < 40; i++) {
    try { file = execFileSync('docker', ['exec', NAME, 'cat', DEFAULT_PATH], { stdio: 'pipe' }).toString(); } catch (_) { file = ''; }
    if (file.includes('/bypasser/ws/runner')) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  const both = execFileSync('sh', ['-c', `docker logs ${NAME} 2>&1`]).toString();

  const line = file.split('\n').find(l => l.includes('/bypasser/ws/runner'));
  assert.ok(line, `no access line for the bypass request in ${DEFAULT_PATH}:\n${file}\n--- container output ---\n${both}`);
  assert.equal(JSON.parse(line).request.uri, '/bypasser/ws/runner?redacted');
  // The 502 also produced an error record; it is in the file, redacted, too.
  const errLine = file.split('\n').find(l => l.includes('"logger":"http.log.error') && l.includes('/bypasser/ws/runner'));
  assert.ok(errLine, `no error record for the failed bypass request in ${DEFAULT_PATH}:\n${file}`);
  assert.equal(JSON.parse(errLine).request.uri, '/bypasser/ws/runner?redacted');
  assert.ok(!file.includes(SECRET), 'the query token reached the access log file');
  assert.ok(!both.includes('/bypasser/ws/runner'), `a request record (access or error) for the bypass path still reaches the container's stdout/stderr:\n${both}`);
  assert.ok(!both.includes(SECRET), 'the query token reached the container output');
  // Nowhere else on the box either: no file under / outside proc/sys holds it.
  const hits = execFileSync('docker', ['exec', NAME, 'sh', '-c',
    `grep -rl --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev ${SECRET} / 2>/dev/null; true`], { stdio: 'pipe' }).toString().trim();
  assert.equal(hits, '', `the token was written to: ${hits}`);
});

test('live caddy:2, log directory missing: Caddy starts, and stderr carries both records redacted', { skip: noDocker }, async () => {
  // The fallback branch must be a config Caddy accepts — the reason it exists is
  // that a refused config can take Caddy down — and must leak no more than before.
  setAccessLogDirCheck(() => false);
  let get;
  try { get = await startLive(NAME2); } finally { setAccessLogDirCheck(DIR_PRESENT); }
  get(`/bypasser/ws/runner?token=${SECRET}&x=2`);
  let both = '';
  for (let i = 0; i < 40; i++) {
    both = execFileSync('sh', ['-c', `docker logs ${NAME2} 2>&1`]).toString();
    if ((both.match(/\/bypasser\/ws\/runner\?redacted/g) || []).length >= 2) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  const recs = both.split('\n').filter(l => l.includes('/bypasser/ws/runner')).map(l => JSON.parse(l));
  const kinds = new Set(recs.map(r => r.logger.split('.').slice(0, 3).join('.')));
  assert.deepEqual(kinds, new Set(['http.log.access', 'http.log.error']), `expected an access and an error record on stderr:\n${both}`);
  for (const r of recs) assert.equal(r.request.uri, '/bypasser/ws/runner?redacted');
  assert.ok(!both.includes(SECRET), `the query token reached stderr:\n${both}`);
  const noFile = execFileSync('docker', ['exec', NAME2, 'sh', '-c', `test -e ${DEFAULT_PATH} && echo present || echo absent`]).toString().trim();
  assert.equal(noFile, 'absent');
});
