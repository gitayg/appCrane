import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import { spawnSync } from 'child_process';

// No Claude credential (the platform ANTHROPIC_API_KEY or a user's
// CLAUDE_CODE_OAUTH_TOKEN) is ever on a docker argv (`ps` shows it to every
// local user) or in a container's config (`docker inspect` shows Config.Env,
// Config.Cmd, Args, Entrypoint). `docker run --env-file` is not enough: Docker
// copies those values into Config.Env. So:
//   exec mode — a 0600 --env-file (a `docker exec`'s env is not in the config);
//   run mode  — the value goes on the container's stdin, read by a fixed sh
//               wrapper that exports it and execs the real command.
// The unit part checks the argv shape of every kind in both modes and that
// every caller reaches docker only through runAgent.js. The LIVE part starts
// real containers the way runAgentNew / runAgentExec do, with a fake key and a
// fake token, and searches `docker inspect` and the host's `ps` for them while
// a process in the container proves it received them (sha256 compared).
// Skipped only when docker or the studio image is unavailable.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-cred-inspect-'));
process.env.TMPDIR = join(process.env.DATA_DIR, 'tmp');
mkdirSync(process.env.TMPDIR);
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.ANTHROPIC_API_KEY;

const { initDb } = await import('../server/db.js');
initDb();
const ra = await import('../server/services/llm/runAgent.js');
const { setCredentials } = await import('../server/services/claudeCredentials.js');

const KEY = 'sk-ant-api03-FAKE-KEY-FOR-INSPECT-TEST-5150';
const TOKEN = 'sk-ant-oat01-FAKE-TOKEN-FOR-INSPECT-TEST-8080';
const APP_ACCESS = 'app-access-token-inspect-1212';
const WS = join(process.env.DATA_DIR, 'ws');
mkdirSync(WS, { recursive: true });
const { getDb } = await import('../server/db.js');
getDb().prepare("INSERT INTO apps (id, name, slot, slug, source_type, repo_backend, branch) VALUES (1, 'credapp', 1, 'credapp', 'managed', 'local', 'main')").run();
setCredentials('credapp', { access_token: APP_ACCESS, refresh_token: 'app-refresh-token-inspect-3434' });

const holds = (args, v) => args.some((a) => a.includes(v));
const envNames = (args) => args.filter((a, i) => i > 0 && args[i - 1] === '-e').map((a) => a.slice(0, a.indexOf('=')));
const sha = (v) => createHash('sha256').update(`${v}\n`).digest('hex');

// ---------------------------------------------------------------------------
// Unit: argv shape per mode and kind
// ---------------------------------------------------------------------------

const RUN_CASES = [
  { kind: 'user_oauth', opts: { oauthToken: TOKEN, apiKey: KEY }, name: 'CLAUDE_CODE_OAUTH_TOKEN', value: TOKEN },
  { kind: 'api_key', opts: { apiKey: KEY }, name: 'ANTHROPIC_API_KEY', value: KEY },
];

for (const c of RUN_CASES) {
  test(`docker run, ${c.kind}: the value is on stdin only, read by the wrapper`, () => {
    const { args, stdinCredential } = ra.runAgentNewPlan({ image: 'img', workspaceDir: WS, prompt: 'p', ...c.opts });
    assert.ok(!holds(args, KEY) && !holds(args, TOKEN), 'no credential on the argv');
    assert.ok(!args.includes('--env-file'), 'no --env-file: docker run copies it into Config.Env');
    assert.ok(!envNames(args).includes(c.name), `no -e ${c.name}`);
    assert.deepEqual(stdinCredential, { name: c.name, value: c.value });
    const img = args.indexOf('img');
    assert.ok(args.indexOf('-i') > 0 && args.indexOf('-i') < img, '-i before the image');
    assert.deepEqual(args.slice(img + 1, img + 5), ['sh', '-c', ra.stdinCredentialScript(c.name), 'appcrane-credential']);
    assert.match(args.at(-1), /claude -p/, 'the real command follows the wrapper');
  });
}

test('docker run, app_credentials: a file mount, nothing on stdin, no key or token anywhere', () => {
  const { args, stdinCredential } = ra.runAgentNewPlan({ image: 'img', workspaceDir: WS, prompt: 'p', appSlug: 'credapp', apiKey: KEY });
  assert.equal(stdinCredential, null);
  assert.ok(!args.includes('-i') && !args.includes('--env-file'));
  assert.ok(!holds(args, KEY) && !holds(args, APP_ACCESS));
  assert.ok(!envNames(args).includes('ANTHROPIC_API_KEY') && !envNames(args).includes('CLAUDE_CODE_OAUTH_TOKEN'));
  assert.equal(args.filter((a) => /\.claude\/\.?credentials\.json$/.test(a)).length, 2);
});

test('docker run, no credential: an empty ANTHROPIC_API_KEY and no wrapper', () => {
  const { args, stdinCredential } = ra.runAgentNewPlan({ image: 'img', workspaceDir: WS, prompt: 'p', apiKey: '' });
  assert.equal(stdinCredential, null);
  assert.ok(args.includes('ANTHROPIC_API_KEY=') && !args.includes('-i'));
});

test('runAgentNewArgs is the same argv minus the delivery: no -i, no wrapper', () => {
  for (const c of RUN_CASES) {
    const opts = { image: 'img', workspaceDir: WS, prompt: 'p', ...c.opts };
    const { args } = ra.runAgentNewPlan(opts);
    const bare = ra.runAgentNewArgs(opts);
    assert.ok(!bare.includes('-i') && !bare.some((a) => a.includes('read -r')));
    const img = args.indexOf('img');
    assert.deepEqual(bare, [...args.slice(0, img).filter((x) => x !== '-i'), 'img', ...args.slice(img + 5)]);
  }
});

test('a credential with a line break is refused, never sent', () => {
  assert.throws(() => ra.runAgentNewPlan({ image: 'img', workspaceDir: WS, prompt: 'p', oauthToken: 'a\nb' }), /line break/);
  assert.throws(() => ra.runAgentNewPlan({ image: 'img', workspaceDir: WS, prompt: 'p', apiKey: 'abcdefgh\rX' }), /line break/);
});

test('the wrapper names only the two credentials', () => {
  assert.throws(() => ra.stdinCredentialScript('PATH; rm -rf /'), /unexpected credential name/);
});

for (const c of RUN_CASES) {
  test(`docker exec, ${c.kind}: the value is in a 0600 --env-file only`, () => {
    const agent = ra.runAgentExec({ containerId: 'c1', prompt: 'p', ...c.opts });
    const args = agent.getDockerArgs();
    try {
      assert.ok(!holds(args, KEY) && !holds(args, TOKEN), 'no credential on the argv');
      assert.ok(!envNames(args).includes(c.name));
      const file = args[args.indexOf('--env-file') + 1];
      assert.equal(statSync(file).mode & 0o777, 0o600);
      assert.equal(readFileSync(file, 'utf8'), `${c.name}=${c.value}\n`);
      assert.equal(agent.getStdinCredential(), null);
    } finally {
      agent.stop();
    }
  });
}

test('docker exec: a refused command leaves no env file behind', () => {
  assert.throws(() => ra.runAgentExec({ containerId: 'c1', prompt: 'p', apiKey: KEY, permissionMode: 'bogus' }), /unsupported permission mode/);
  assert.deepEqual(readdirSync(process.env.TMPDIR).filter((f) => f.startsWith('appcrane-env-')), []);
});

test('every caller reaches docker with a credential only through runAgent.js', () => {
  // A literal `-e ANTHROPIC_API_KEY=${...}` / `CLAUDE_CODE_OAUTH_TOKEN=${...}`
  // anywhere else in server/ would bypass both channels.
  const files = spawnSync('git', ['ls-files', 'server'], { encoding: 'utf8' }).stdout.split('\n').filter((f) => f.endsWith('.js'));
  assert.ok(files.length > 100, 'git listed the server tree');
  const bad = /(ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)=\$\{/;
  const hits = files.filter((f) => bad.test(readFileSync(f, 'utf8')));
  assert.deepEqual(hits, []);
  for (const f of ['askClaude.js', 'builder/builderSession.js', 'crewAppCoderRunner.js',
    'appstudio/planner.js', 'appstudio/generator.js', 'appstudio/contextBuilder.js']) {
    assert.match(readFileSync(join('server/services', f), 'utf8'), /runAgent(Exec|New|OneShot)\(/, f);
  }
});

// ---------------------------------------------------------------------------
// LIVE: real containers, real `docker inspect`
// ---------------------------------------------------------------------------

const IMAGE = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
const dockerOk = spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'pipe', timeout: 15000 }).status === 0;
const skip = dockerOk ? false : `docker or the ${IMAGE} image is unavailable`;

// Prints sha256(value + "\n") as a stream-json text event, then stays up so
// the test can inspect it.
const probe = (name) => ['sh', '-c',
  `h=$(printenv ${name} | sha256sum | cut -d' ' -f1); `
  + `printf '{"type":"assistant","message":{"content":[{"type":"text","text":"%s"}]}}\\n' "$h"; sleep 20`];

function firstText(agent) {
  return new Promise((resolve, reject) => {
    agent.on('data', (ev) => { if (ev.type === 'text') resolve(ev.text); });
    agent.on('error', reject);
    agent.on('exit', (code) => reject(new Error(`exited ${code}: ${agent.getStderrTail().join(' | ')}`)));
    agent.start();
  });
}

function inspectAndPs(name) {
  const inspect = spawnSync('docker', ['inspect', name], { encoding: 'utf8', timeout: 15000 });
  assert.equal(inspect.status, 0, inspect.stderr);
  const ps = spawnSync('ps', ['-axww', '-o', 'args'], { encoding: 'utf8' }).stdout;
  return { inspect: inspect.stdout, ps };
}

for (const c of RUN_CASES) {
  test(`LIVE docker run, ${c.kind}: the container gets it, inspect and ps do not show it`, { skip, timeout: 120000 }, async () => {
    const name = `appcrane-credtest-run-${c.kind}-${process.pid}`;
    const CONTROL = `control-value-visible-${c.kind}-777`;
    const agent = ra.runAgentNew({
      image: IMAGE, pull: 'never', containerName: name, workspaceDir: WS, prompt: 'unused', ...c.opts,
      // Positive control: a plain -e value IS in the config, so a clean
      // inspect below is not a search that cannot see anything.
      envVars: { APPCRANE_CONTROL: CONTROL },
      cmd: probe(c.name),
    });
    try {
      const hash = await firstText(agent);
      assert.equal(hash, sha(c.value), 'the process in the container received the value');
      const { inspect, ps } = inspectAndPs(name);
      assert.ok(inspect.includes(CONTROL), 'control: inspect shows a plain -e value');
      assert.ok(!inspect.includes(c.value), `${c.name} in docker inspect`);
      assert.ok(!inspect.includes(KEY) && !inspect.includes(TOKEN));
      assert.ok(!ps.includes(c.value), `${c.name} in the host ps`);
      const cfg = JSON.parse(inspect)[0];
      console.log(`[live run ${c.kind}] hash ok; Config.Env names: ${cfg.Config.Env.map((e) => e.split('=')[0]).join(',')}; Path: ${cfg.Path}; Args[2]: ${cfg.Args[2]}`);
    } finally {
      agent.stop();
      spawnSync('docker', ['rm', '-f', name], { stdio: 'pipe' });
    }
  });

  test(`LIVE docker exec, ${c.kind}: the exec gets it, inspect and ps do not show it`, { skip, timeout: 120000 }, async () => {
    const name = `appcrane-credtest-exec-${c.kind}-${process.pid}`;
    const up = spawnSync('docker', ['run', '-d', '--rm', '--pull', 'never', '--name', name, IMAGE, 'sleep', '60'], { encoding: 'utf8' });
    assert.equal(up.status, 0, up.stderr);
    const agent = ra.runAgentExec({ containerId: name, prompt: 'unused', ...c.opts, cmd: probe(c.name) });
    try {
      const hash = await firstText(agent);
      assert.equal(hash, sha(c.value), 'the exec process received the value');
      const { inspect, ps } = inspectAndPs(name);
      assert.ok(!inspect.includes(c.value), `${c.name} in docker inspect`);
      assert.ok(!ps.includes(c.value), `${c.name} in the host ps`);
      console.log(`[live exec ${c.kind}] hash ok; value absent from inspect and ps`);
    } finally {
      agent.stop();
      spawnSync('docker', ['rm', '-f', name], { stdio: 'pipe' });
    }
  });
}

test('LIVE control: the same value via `docker run --env-file` IS in docker inspect', { skip, timeout: 60000 }, () => {
  // Why run mode does not use an env file: measured here, not assumed.
  const name = `appcrane-credtest-envfile-${process.pid}`;
  const dir = mkdtempSync(join(process.env.DATA_DIR, 'ef-'));
  const file = join(dir, 'env');
  spawnSync('sh', ['-c', `printf 'ANTHROPIC_API_KEY=%s\\n' "$1" > "$2"`, 'sh', KEY, file]);
  const up = spawnSync('docker', ['run', '-d', '--rm', '--pull', 'never', '--name', name, '--env-file', file, IMAGE, 'sleep', '30'], { encoding: 'utf8' });
  try {
    assert.equal(up.status, 0, up.stderr);
    assert.ok(inspectAndPs(name).inspect.includes(KEY), 'docker run --env-file lands in Config.Env');
  } finally {
    spawnSync('docker', ['rm', '-f', name], { stdio: 'pipe' });
  }
});
