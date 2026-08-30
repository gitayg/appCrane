import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// A user's GitHub PAT must not be a command-line argument (v2.53.1).
//
// mcpStdioBridge spawned `docker run -i --rm … -e GITHUB_PERSONAL_ACCESS_TOKEN=<pat> <image>`.
// Everything after `spawn('docker', args)` is process argv: readable by any
// local user through the process list, and preserved in `docker inspect` for
// the container's lifetime. The token belongs to a real GitHub account with
// whatever scopes that user granted.
//
// Docker's `-e NAME` form (no `=value`) reads the value from the docker CLI's
// own environment instead, so the secret travels through the child's env block
// and never appears in argv.
//
// Asserted against the built argv rather than a running container: the property
// is "this string is not in that array", and a test that needs Docker to prove
// it would be skipped on every machine that lacks Docker — which is where a
// regression would then land.

const { buildDockerArgs } = await import('../server/services/mcpStdioBridge.js');

const SECRET = 'ghp_averyrealtokenvalue1234567890';

test('the secret value is nowhere in argv', () => {
  const { args } = buildDockerArgs({
    image: 'ghcr.io/example/github-mcp:1',
    env: { GITHUB_PERSONAL_ACCESS_TOKEN: SECRET },
    label: 'user-7',
  });
  const flat = args.join(' ');
  assert.ok(!flat.includes(SECRET),
    `the PAT appears in the docker argv, which is world-readable via the process list:\n  ${flat}`);
});

test('the variable NAME is still passed, so the container receives it', () => {
  const { args, env } = buildDockerArgs({
    image: 'img', env: { GITHUB_PERSONAL_ACCESS_TOKEN: SECRET }, label: 'user-7',
  });
  const i = args.indexOf('-e');
  assert.notEqual(i, -1, 'the -e flag has to survive, or the container gets no token at all');
  assert.equal(args[i + 1], 'GITHUB_PERSONAL_ACCESS_TOKEN',
    'name-only form: docker reads the value from its own environment');
  assert.equal(env.GITHUB_PERSONAL_ACCESS_TOKEN, SECRET,
    'and the value must actually be in the environment handed to spawn, or the name resolves to nothing');
});

test('the spawn environment is not the whole parent environment', () => {
  const { env } = buildDockerArgs({ image: 'img', env: { GITHUB_PERSONAL_ACCESS_TOKEN: SECRET }, label: 'l' });
  assert.equal(env.ENCRYPTION_KEY, undefined,
    "AppCrane's own master key must not be inherited into a container spawn it does not belong to");
});

test('the image is still the last argument', () => {
  const { args } = buildDockerArgs({ image: 'ghcr.io/x/y:2', env: {}, label: 'l' });
  assert.equal(args[args.length - 1], 'ghcr.io/x/y:2',
    'docker run parses the image positionally; anything after it becomes the container command');
});

test('the source no longer contains the interpolated -e KEY=VALUE form', () => {
  const src = readFileSync(new URL('../server/services/mcpStdioBridge.js', import.meta.url), 'utf8');
  assert.ok(!/\$\{k\}=\$\{v\}/.test(src),
    'the old form built `-e NAME=value` directly into argv');
});

test('the hardcoded network name still matches docker.js', () => {
  // The comment in mcpStdioBridge.js promises this test exists. If APP_NETWORK
  // is renamed in docker.js and not here, the container silently returns to the
  // default bridge — where inter-container connectivity is on, which is the
  // condition v2.42.1 removed for every other container on the host.
  const bridge = readFileSync(new URL('../server/services/mcpStdioBridge.js', import.meta.url), 'utf8');
  const docker = readFileSync(new URL('../server/services/docker.js', import.meta.url), 'utf8');
  const a = bridge.match(/const APP_NETWORK = '([^']+)'/)?.[1];
  const b = docker.match(/const APP_NETWORK = '([^']+)'/)?.[1];
  assert.ok(a && b, 'both files must declare APP_NETWORK for this check to mean anything');
  assert.equal(a, b, `network name drifted: bridge='${a}' docker='${b}'`);
});

test('the container is isolated and capped, not just unlabelled', () => {
  const { args } = buildDockerArgs({ image: 'img', env: {}, label: 'l' });
  const flat = args.join(' ');
  for (const flag of ['--network', '--memory', '--cpus', '--pids-limit', '--cap-drop', '--security-opt']) {
    assert.ok(flat.includes(flag), `missing ${flag}: a user-triggered container with no cap is a DoS primitive`);
  }
});

test("the MCP image itself declares a non-root USER", () => {
  // AppCrane REJECTS app-provided Dockerfiles that omit USER
  // (services/dockerfileValidator.js). Its own image had no USER line and ran
  // as root — the platform holding apps to a rule it did not keep.
  const df = readFileSync(new URL('../packages/mcp/Dockerfile', import.meta.url), 'utf8');
  const users = [...df.matchAll(/^USER\s+(\S+)/gm)].map((m) => m[1]);
  assert.ok(users.length > 0, 'no USER line — the container runs as root');
  const last = users[users.length - 1];
  assert.ok(!/^(root|0)(:|$)/.test(last), `last USER is '${last}', which is root`);
});
