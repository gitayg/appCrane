import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import http from 'node:http';

const execFileAsync = promisify(execFile);

// A container COMMAND: what the image is started with.
//
// There was no such thing. `startApp()` ended at `args.push(image)`, so every
// container ran whatever ENTRYPOINT/CMD its image shipped, and an image whose
// entrypoint requires a subcommand had no way to be told one. Measured against
// a real daemon rather than inferred, and this is the failure the whole feature
// exists to remove:
//
//   $ docker run -d quay.io/keycloak/keycloak:26.0        # no argv
//   $ docker inspect --format 'state={{.State.Status}} exit={{.State.ExitCode}}'
//   state=exited exit=0
//   $ docker logs ...
//   Keycloak - Open Source Identity and Access Management
//   Find more information at: https://www.keycloak.org/docs/latest
//
// Exit code ZERO. Nothing in the deploy path can tell that from success except
// the health probe, which then blames the app. Keycloak, Zitadel, MinIO, ntfy
// and Vault are all this shape, which is why none of them is in the catalogue.
//
// Three separate claims are proved here, because each can be true while the
// others are false:
//
//   1. THE SHAPE. The command is an array of argv strings and a shell string is
//      refused — at the storage boundary AND again where the argv is built.
//      This is the security half: a stored string could only be run by splitting
//      it, and the step after "split a stored string into a command" is
//      `sh -c <that string>`, which is this repo's standing prohibition with the
//      app row as the injection point.
//   2. THE ARGV. What lands on `docker run`, measured off a recording shim —
//      both from a direct startApp() call and from a real deployApp() reading a
//      real app row, since a column nothing reads is not a feature.
//   3. THE DAEMON. That the argv does what we think. A shim agrees with whatever
//      the code says; only a real container can show keycloak reaching
//      state=running and answering HTTP, and only a real daemon can settle
//      whether a command spelled like a docker flag becomes one.
//
// (3) is skipped, not failed, where no daemon answers.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-cmd-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

// A daemon that RESPONDS, not a binary that exists — resolved and remembered
// BEFORE the shim goes on PATH, so the live section below can reach the real
// docker while the shim section still intercepts everything.
let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker'],
    { encoding: 'utf8' }).trim() || null;
  if (REAL_DOCKER) execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'],
    { timeout: 15000, stdio: 'pipe' });
} catch (_) {
  REAL_DOCKER = null;
}
const REAL_PATH = process.env.PATH;
const liveSkip = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

// ---------------------------------------------------------------------------
// A `docker` that records its argv and answers from a scriptable rule table.
// Same shim as test/container-port.test.js and test/image-deploy.test.js.
// ---------------------------------------------------------------------------

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });

// CommonJS on purpose: the file is named `docker` with no extension, so Node
// parses it as CJS and an `import` here would be a syntax error at spawn time —
// surfacing as an unexplained docker failure rather than as a test error.
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync, readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.map(a => a + "\\n").join("") + "\\0");\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) {\n' +
  '  if (r.match.every(tok => argv.includes(tok))) {\n' +
  '    process.stdout.write(r.stdout || "");\n' +
  '    process.exit(r.code || 0);\n' +
  '  }\n' +
  '}\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const DIGEST = `sha256:${'c3'.repeat(32)}`;
writeFileSync(RULES, JSON.stringify([
  { match: ['image', 'inspect'], stdout: `kc@${DIGEST}\n` },
  { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
  { match: ['images', '--filter'], stdout: '' },
]));

function dockerCalls() {
  if (!existsSync(ARGV_LOG)) return [];
  return readFileSync(ARGV_LOG, 'utf8')
    .split('\0')
    .filter((rec) => rec.trim() !== '')
    .map((rec) => rec.split('\n').filter((l) => l !== ''));
}
function clearDockerCalls() {
  if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG);
}
function runArgs() {
  const runs = dockerCalls().filter((c) => c[0] === 'run');
  assert.equal(runs.length, 1, `expected exactly one \`docker run\`, saw ${runs.length}`);
  return runs[0];
}
/** Everything after the image argument: the container's own argv. */
function trailingArgv(args, image) {
  const at = args.lastIndexOf(image);
  assert.ok(at >= 0, `image ${image} not present in argv: ${JSON.stringify(args)}`);
  return args.slice(at + 1);
}

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { startApp } = await import('../server/services/docker.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const spec = await import('../server/services/containerRuntimeSpec.js');

let nextSlot = 900;
function mkApp(slug, extra = {}) {
  const slot = ++nextSlot;
  db.prepare('INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,container_command) VALUES (?,?,?,?,?,?,?)')
    .run(slug, slug, slot, extra.source_type || 'managed', extra.image_ref || null,
      extra.container_port ?? null, extra.container_command ?? null);
  return { slug, slot, port: getPortsForSlot(slot).prod_be };
}

const BASE = { env: 'production', image: 'kc:26', hostPort: 4711, memoryMb: 512, cpus: 0.5 };
async function start(slug, extra = {}) {
  clearDockerCalls();
  await startApp({ ...BASE, slug, ...extra });
  return runArgs();
}

// ===========================================================================
// 1. The shape: an array of argv strings, never a shell string
// ===========================================================================

test('a shell string is refused, and the error says why rather than just "invalid"', () => {
  assert.throws(() => spec.validateContainerCommand('start-dev --http-port 8080'), (e) => {
    assert.match(e.message, /array of argument strings, not a shell string/);
    assert.match(e.message, /injection/,
      'the message must say what the rule is FOR — a validator whose reason is invisible is ' +
      'the one a later change relaxes');
    return true;
  });
});

test('an array of argv strings is accepted verbatim, separators and all', () => {
  // Nothing here is escaped, quoted or split. Each element is one argv slot, so
  // a space or a `;` inside one is DATA to the container's process — that is the
  // property the array shape buys and the reason no escaping is needed anywhere.
  assert.deepEqual(spec.validateContainerCommand(['server', '/data', '--console-address', ':9001']),
    ['server', '/data', '--console-address', ':9001']);
  assert.deepEqual(spec.validateContainerCommand(['sh', '-c', 'echo hi; echo there']),
    ['sh', '-c', 'echo hi; echo there'],
    'a deliberate sh -c written BY AN OPERATOR AS TWO ARGV SLOTS is legal and unchanged. What is ' +
    'refused is a single string this code would have to split — that is where the injection is.');
});

test('"no command" has exactly one representation', () => {
  for (const v of [undefined, null, []]) assert.equal(spec.validateContainerCommand(v), null);
});

test('non-strings, empties and control characters are refused element by element', () => {
  assert.throws(() => spec.validateContainerCommand(['ok', 7]), /argument 1 must be a string/);
  assert.throws(() => spec.validateContainerCommand(['ok', null]), /argument 1 must be a string \(got null\)/);
  assert.throws(() => spec.validateContainerCommand(['ok', '']), /argument 1 is empty/);
  assert.throws(() => spec.validateContainerCommand(['ok', 'a\u0000b']), /control character/);
  assert.throws(() => spec.validateContainerCommand(['ok', 'a\nb']), /control character/);
  assert.throws(() => spec.validateContainerCommand(['x'.repeat(spec.MAX_COMMAND_ARG_LENGTH + 1)]), /longer than/);
  assert.throws(() => spec.validateContainerCommand(new Array(spec.MAX_COMMAND_ARGS + 1).fill('x')), /at most/);
  assert.throws(() => spec.validateContainerCommand({ 0: 'sh' }), /must be an array/);
});

test('a malformed COLUMN degrades to "no command" instead of making the app undeployable', () => {
  // The two boundaries are not symmetrical on purpose. A write is refused loudly
  // so the operator fixes it; a stored value that is already broken — a restored
  // backup, a hand-edited row, a column written before this validation existed —
  // must not be able to wedge an app permanently out of deployability.
  for (const stored of ['not json', '"start-dev"', '{"a":1}', '[1,2]', '[""]', null, '', 42]) {
    assert.equal(spec.parseContainerCommand(stored), null, `stored ${JSON.stringify(stored)}`);
  }
  assert.deepEqual(spec.parseContainerCommand('["start-dev"]'), ['start-dev']);
});

// ===========================================================================
// 2. The argv
// ===========================================================================

test('with no command the run argv does not move by a single byte', async () => {
  // The point of the whole parameter being optional. Every app on the platform
  // today has no command, and the strongest way to say "nothing changed for
  // them" is to compare the two argvs directly.
  const withoutParam = await start('cmd-none');
  const withExplicitNull = await start('cmd-none', { command: null });
  assert.deepEqual(withExplicitNull, withoutParam);
  assert.deepEqual(trailingArgv(withoutParam, 'kc:26'), [],
    `nothing may follow the image: ${JSON.stringify(withoutParam)}`);
});

test('a command lands after the image, in order, one argv slot per element', async () => {
  const args = await start('cmd-kc', { command: ['start-dev', '--http-port', '8080'] });
  assert.deepEqual(trailingArgv(args, 'kc:26'), ['start-dev', '--http-port', '8080']);
  assert.equal(args[args.length - 4], 'kc:26',
    'the image must be immediately followed by the command — anything between them would be ' +
    `read by docker as one of ITS options: ${JSON.stringify(args)}`);
});

test('an element containing spaces stays ONE argument', async () => {
  const args = await start('cmd-spaces', { command: ['sh', '-c', 'echo a b c'] });
  assert.deepEqual(trailingArgv(args, 'kc:26'), ['sh', '-c', 'echo a b c'],
    'execFile is exec, not a shell: three elements in, three argv slots out. If this ever ' +
    'becomes four, something started splitting on whitespace.');
});

test('the argv-build boundary refuses what the write boundary refuses', async () => {
  // The second of the two boundaries, and the one that matters for a caller
  // that never went through storage — a route, a scheduler, a test.
  await assert.rejects(() => startApp({ ...BASE, slug: 'cmd-bad', command: 'start-dev' }),
    /array of argument strings, not a shell string/);
  await assert.rejects(() => startApp({ ...BASE, slug: 'cmd-bad', command: ['ok\u0000'] }),
    /control character/);
});

test('a refused command does not stop the app that is already running', async () => {
  // Ordering, and it is load-bearing. startApp's first act used to be
  // stopApp(); validating after that would tear down a healthy container for a
  // start that was never going to happen — the app goes down because of a typo
  // in a field.
  clearDockerCalls();
  await assert.rejects(() => startApp({ ...BASE, slug: 'cmd-order', command: 'oops' }));
  assert.deepEqual(dockerCalls(), [],
    `no docker command may run at all when the command is invalid: ${JSON.stringify(dockerCalls())}`);
});

// ===========================================================================
// 3. The row -> argv path, through a real deployApp
// ===========================================================================

describe('a real deploy reads the column', () => {
  const HEALTH = '/health';
  let userId;
  let slot = null;
  let ports = null;
  const servers = [];

  const startHealthServer = (port) => new Promise((res) => {
    const s = http.createServer((req, out) => {
      out.writeHead(200, { 'content-type': 'application/json' });
      out.end(JSON.stringify({ status: 'ok', version: '26.0' }));
    });
    s.on('error', () => res(null));
    // Loopback explicitly: a hostless listen(0) binds [::] and can collide with
    // a Docker-published port, which reads as a phantom failure of this file.
    s.listen(port, '127.0.0.1', () => res(s));
  });

  before(async () => {
    // Searched for, not hardcoded: deployApp derives the host port from
    // apps.slot, so the health server has to bind the exact port the slot
    // implies, and a fixed slot fails with EADDRINUSE on a second concurrent run.
    for (let s = 13100; s < 13200 && slot === null; s++) {
      const p = getPortsForSlot(s);
      const sand = await startHealthServer(p.sand_be);
      if (!sand) continue;
      const prod = await startHealthServer(p.prod_be);
      if (!prod) { sand.close(); continue; }
      slot = s; ports = p; servers.push(sand, prod);
    }
    assert.ok(slot !== null, 'no slot with both ports free');
    userId = db.prepare(
      "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','cmd@x.io','platform_admin','unused',1,'human')",
    ).run().lastInsertRowid;
  });

  after(() => {
    for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); }
  });

  async function deployWith(slug, containerCommand) {
    db.prepare(
      'INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,health_path,container_command) ' +
      "VALUES (?,?,?,'image','kc:26',3000,?,?)",
    ).run(slug, slug, slot, HEALTH, containerCommand);
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
    const depId = db.prepare(
      "INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)",
    ).run(app.id, userId).lastInsertRowid;
    clearDockerCalls();
    await deployApp(depId, app, 'sandbox', ports, {});
    const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(depId);
    // Freed for the next case in this describe, which reuses the one slot whose
    // ports the health servers hold.
    db.prepare('DELETE FROM apps WHERE id = ?').run(app.id);
    return { args: runArgs(), row };
  }

  test('container_command on the row becomes the container argv', async () => {
    const { args, row } = await deployWith('cmd-row', JSON.stringify(['start-dev']));
    assert.equal(row.status, 'live', row.log);
    assert.deepEqual(trailingArgv(args, `kc@${DIGEST}`), ['start-dev'],
      `a column nothing reads is not a feature. argv: ${JSON.stringify(args)}`);
  });

  test('a NULL column deploys exactly as it did before the column existed', async () => {
    const { args, row } = await deployWith('cmd-row-null', null);
    assert.equal(row.status, 'live', row.log);
    assert.deepEqual(trailingArgv(args, `kc@${DIGEST}`), []);
  });

  test('a corrupt column does not take the app down with it', async () => {
    const { args, row } = await deployWith('cmd-row-junk', 'this is not json');
    assert.equal(row.status, 'live', row.log);
    assert.deepEqual(trailingArgv(args, `kc@${DIGEST}`), []);
  });
});

// ===========================================================================
// 4. The daemon
// ===========================================================================

describe('LIVE', { skip: liveSkip }, () => {
  const KC = 'quay.io/keycloak/keycloak:26.0';
  const SUFFIX = `cmd${process.pid}`;
  const started = [];

  const dk = (args, timeout = 120000) =>
    execFileAsync(REAL_DOCKER, args, { timeout }).then((r) => r.stdout.trim());

  const freePort = () => new Promise((res, rej) => {
    const s = net.createServer();
    s.once('error', rej);
    // Loopback explicitly — see the note on the health server above.
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
  });

  /** Poll until the port answers with something matching `expect`. Waiting on
   *  the ASSERTION rather than on the connection is deliberate: Docker's proxy
   *  accepts before the container listens, so "connected" is not "ready". */
  async function awaitAnswer(port, expect, ms) {
    const deadline = Date.now() + ms;
    let last = '';
    for (;;) {
      last = await new Promise((res) => {
        let buf = '';
        const s = net.connect({ port, host: '127.0.0.1' });
        const done = () => { s.destroy(); res(buf); };
        s.setTimeout(4000, done);
        s.once('error', done);
        s.once('connect', () => s.write('GET / HTTP/1.0\r\nHost: localhost\r\n\r\n'));
        s.on('data', (d) => { buf += d.toString(); });
        s.once('close', done);
      });
      if (expect.test(last)) return last;
      if (Date.now() > deadline) {
        throw new Error(`port ${port} never answered ${expect} in ${ms}ms (last: ${JSON.stringify(last.slice(0, 160))})`);
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }

  const state = (name) => dk(['inspect', name, '--format', '{{.State.Status}}|{{.State.ExitCode}}']);

  // An image that is ALREADY local is not re-pulled. Docker Hub and quay answer
  // 429 to an unauthenticated puller often enough that a mandatory pull turns
  // this file into a rate-limit detector; and a pull that fails with no local
  // copy is an environment fact, so it skips rather than fails.
  let imageProblem = null;
  before(async () => {
    // The shim comes off PATH: from here on `docker` inside startApp is the
    // real binary. This block is last in the file for exactly that reason.
    process.env.PATH = REAL_PATH;
    try {
      await dk(['image', 'inspect', KC], 30000);
    } catch (_) {
      try { await dk(['pull', KC], 600000); }
      catch (e) { imageProblem = `could not obtain ${KC}: ${String(e.message).split('\n')[0].slice(0, 120)}`; }
    }
  });

  after(async () => {
    for (const c of started) await dk(['rm', '-f', c], 30000).catch(() => {});
    // The shared appcrane-apps network is deliberately NOT removed — startApp
    // creates it on demand and other containers on a developer's machine are
    // attached to it.
  });

  // Per-run unique slugs: a fixed container name collides across concurrent runs.
  async function launch(slug, command) {
    const hostPort = await freePort();
    const name = `appcrane-${slug}-production`;
    started.push(name);
    await startApp({
      slug, env: 'production', image: KC, hostPort, containerPort: 8080, command,
      envVars: { KC_BOOTSTRAP_ADMIN_USERNAME: 'admin', KC_BOOTSTRAP_ADMIN_PASSWORD: 'admin' },
      memoryMb: 1024, cpus: 1,
    });
    return { name, hostPort };
  }

  test('CONTROL: with no command keycloak prints its usage banner and exits 0', async (t) => {
    if (imageProblem) return t.skip(imageProblem);
    // The failure this feature exists to remove, reproduced deterministically.
    // Without this control the test below proves only that keycloak can start —
    // not that the command is what makes it start.
    const { name } = await launch(`kc-nocmd-${SUFFIX}`, null);
    let s = '';
    for (let i = 0; i < 40; i++) {
      s = await state(name);
      if (s.startsWith('exited')) break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    assert.equal(s, 'exited|0',
      `expected the no-command container to exit 0. EXIT ZERO is the point: nothing in the ` +
      `deploy path can tell that from success. Got ${s}`);
    const logs = await dk(['logs', name]).catch((e) => String(e.stdout || e.message));
    assert.match(logs, /Keycloak/i);
  });

  test('with ["start-dev"] the same image reaches state=running and answers HTTP', async (t) => {
    if (imageProblem) return t.skip(imageProblem);
    const { name, hostPort } = await launch(`kc-cmd-${SUFFIX}`, ['start-dev']);
    const body = await awaitAnswer(hostPort, /HTTP\/1\.[01] \d\d\d/, 180000);
    assert.match(body, /HTTP\/1\.[01] (200|30\d)/, `keycloak answered: ${body.slice(0, 200)}`);
    const s = await state(name);
    assert.match(s, /^running\|/, `expected a running container, got ${s}`);

    // The daemon's own record of what the container was created with — the one
    // place that cannot be satisfied by the code agreeing with itself.
    const cmd = JSON.parse(await dk(['inspect', name, '--format', '{{json .Config.Cmd}}']));
    assert.deepEqual(cmd, ['start-dev']);
  });

  test('a command spelled like a docker flag is a CONTAINER argument, not a docker option', async (t) => {
    if (imageProblem) return t.skip(imageProblem);
    // The security claim underneath storing an operator-supplied command at all:
    // `docker run` stops parsing its own options at the image name, so nothing
    // appended after it can become a docker flag. Asserted against the daemon
    // because it is a property of docker's parser, not of this repo's code.
    const { name } = await launch(`kc-flag-${SUFFIX}`, ['--privileged']);
    const [priv, cmd] = (await dk(['inspect', name, '--format', '{{.HostConfig.Privileged}}|{{json .Config.Cmd}}'])).split('|');
    assert.equal(priv, 'false',
      'a command of ["--privileged"] must NOT privilege the container — if this ever reads true, ' +
      'every stored command becomes a way to reconfigure the container it runs in');
    assert.deepEqual(JSON.parse(cmd), ['--privileged'],
      'it must reach the container as a literal argument instead');
  });
});
