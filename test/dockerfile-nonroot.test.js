import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';

import { validateDockerfile } from '../server/services/dockerfileValidator.js';
import { ensureDockerfile } from '../server/services/dockerfileGen.js';

// Non-root enforcement for app-provided Dockerfiles (v2.42.1).
//
// THE BUG: the old check filtered every `USER` line in the file and errored only
// when the LAST one was literally `USER root`. A Dockerfile with NO USER line at
// all therefore passed — and that container runs as root. Root is what you get by
// OMISSION, so the single most common Dockerfile shape was the one that slipped
// through. `USER 0` and `USER root:root` are also root and also passed.
//
// THE COMPATIBILITY DECISION, stated here so a future reader knows it was
// deliberate and not a weakened test:
//
//   * declaring root explicitly (root / root:root / 0 / 0:0) -> HARD ERROR,
//     always. It is a deliberate act by the author, the old check already meant
//     to reject it, and ~no app does it. Widening the match is repairing an
//     existing rule, not creating a new class of failure.
//   * declaring NO user -> WARNING by default (valid:true, deploy proceeds,
//     deployer.js:981 prints it as "⚠ Dockerfile: …" on every deploy), promoted
//     to a HARD ERROR when the operator sets APPCRANE_REQUIRE_NONROOT=1.
//     Most of the fleet omits USER today; erroring on upgrade would fail most
//     apps' next deploy at once, which is an outage wearing a security fix's
//     clothes. The flag is the operator's cutover switch (same opt-in-to-enforce
//     shape as APPCRANE_AUDIT_REQUIRED).
//
// So "rejected" for a missing USER means *surfaced, and fatal on demand* — both
// halves are asserted below, and the default-mode assertion checks the finding is
// NOT silent, which is the property that actually failed before this release.
//
// The tests drive the real exported validateDockerfile() against real files on
// disk (it reads releaseDir/Dockerfile), and the generator coupling test runs
// ensureDockerfile()'s actual output through it rather than pattern-matching the
// generator's source.

delete process.env.APPCRANE_REQUIRE_NONROOT; // default mode must be deterministic

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function scratch(prefix = 'crane-dfnonroot-') {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

function validateSource(source) {
  const dir = scratch();
  writeFileSync(join(dir, 'Dockerfile'), source);
  return validateDockerfile(dir, { expectedPort: 3000 });
}

// A minimal otherwise-valid Dockerfile (FROM + EXPOSE 3000 present) so that any
// error/warning we assert on is about the USER rule and nothing else.
function df(...extra) {
  return ['FROM node:20-alpine', 'WORKDIR /app', 'COPY . .', ...extra, 'EXPOSE 3000', 'CMD ["node", "server.js"]'].join('\n') + '\n';
}

const isUserFinding = s => /USER|root/i.test(s);
const userErrors = r => r.errors.filter(isUserFinding);
const userWarnings = r => r.warnings.filter(isUserFinding);

function enforced(fn) {
  const prev = process.env.APPCRANE_REQUIRE_NONROOT;
  process.env.APPCRANE_REQUIRE_NONROOT = '1';
  try { return fn(); } finally {
    if (prev === undefined) delete process.env.APPCRANE_REQUIRE_NONROOT;
    else process.env.APPCRANE_REQUIRE_NONROOT = prev;
  }
}

// --- the bug: no USER line at all ---------------------------------------

test('a Dockerfile with no USER line is reported (it runs as root) — this passed silently before', () => {
  const res = validateSource(df());

  // The property the old code violated: this Dockerfile produced NOTHING.
  assert.equal(
    userErrors(res).length + userWarnings(res).length, 1,
    'a USER-less Dockerfile must produce exactly one non-root finding, not silence',
  );
  // Deliberate: warning in default mode so an upgrade does not fail the fleet.
  assert.equal(res.valid, true, 'default mode: warn, do not block (see header)');
  assert.equal(userErrors(res).length, 0);
  assert.match(userWarnings(res)[0], /USER/);
  assert.match(userWarnings(res)[0], /root/i);
  // The message must tell the author what to add, not just that they are wrong.
  assert.match(userWarnings(res)[0], /USER <non-root-user>|USER node/);
});

test('a Dockerfile with no USER line is a hard failure under APPCRANE_REQUIRE_NONROOT=1', () => {
  const res = enforced(() => validateSource(df()));

  assert.equal(res.valid, false, 'enforcement mode: missing USER blocks the deploy');
  assert.equal(userErrors(res).length, 1);
  assert.match(userErrors(res)[0], /root/i);
  assert.equal(userWarnings(res).length, 0, 'once it is an error it must not also warn');
});

// --- regression guard: explicit root stays rejected ----------------------

test('USER root at the end is still rejected (pre-existing behaviour must not regress)', () => {
  const res = validateSource(df('USER root'));
  assert.equal(res.valid, false);
  assert.equal(userErrors(res).length, 1);
  assert.match(userErrors(res)[0], /root/i);
});

test('USER root is rejected in default mode too, not only under enforcement', () => {
  // Explicit root is never merely a warning — the enforcement flag must not be
  // load-bearing for the case the old check already caught.
  assert.equal(process.env.APPCRANE_REQUIRE_NONROOT, undefined);
  assert.equal(validateSource(df('USER root')).valid, false);
  assert.equal(enforced(() => validateSource(df('USER root'))).valid, false);
});

test('the other spellings of root are rejected: root:root, 0, 0:0', () => {
  for (const u of ['root:root', '0', '0:0', 'ROOT']) {
    const res = validateSource(df(`USER ${u}`));
    assert.equal(res.valid, false, `USER ${u} must be rejected as root`);
    assert.match(userErrors(res)[0], /root/i, `USER ${u}`);
  }
});

// --- the happy path ------------------------------------------------------

test('a non-root USER passes with no USER finding at all', () => {
  const res = validateSource(df('USER node'));
  assert.equal(res.valid, true);
  assert.deepEqual(res.errors, []);
  assert.deepEqual(userWarnings(res), [], 'a compliant Dockerfile must be silent, not merely valid');
});

test('a non-root USER passes under enforcement too', () => {
  const res = enforced(() => validateSource(df('USER node')));
  assert.equal(res.valid, true);
  assert.deepEqual(res.errors, []);
  assert.deepEqual(userWarnings(res), []);
});

// --- case / whitespace / comment variants --------------------------------

test('case and whitespace variants are recognised as a declared USER', () => {
  for (const line of ['user node', 'USER  node', 'UsEr\tnode', '  USER node  ']) {
    const res = validateSource(df(line));
    assert.equal(res.valid, true, `${JSON.stringify(line)} should be accepted`);
    assert.deepEqual(userWarnings(res), [], `${JSON.stringify(line)} should be silent`);
  }
});

test('case variants of root are still caught (the root check is case-insensitive)', () => {
  for (const line of ['user root', 'USER  Root', 'user 0:0']) {
    assert.equal(validateSource(df(line)).valid, false, `${JSON.stringify(line)} must be rejected`);
  }
});

test('a trailing comment on the USER line does not hide the user', () => {
  assert.equal(validateSource(df('USER node # drop privileges')).valid, true);

  const rooted = validateSource(df('USER root # needed for chown'));
  assert.equal(rooted.valid, false, 'a comment must not launder USER root');
});

test('a commented-out USER line does not count as declaring a user', () => {
  // Proves the USER match is anchored: `# USER node` must not satisfy the rule,
  // and `# USER root` must not trigger the root error.
  const commentedNonRoot = validateSource(df('# USER node'));
  assert.equal(commentedNonRoot.valid, true, 'default mode still warns rather than errors');
  assert.equal(userWarnings(commentedNonRoot).length, 1, 'a commented USER is no USER');

  const commentedRoot = validateSource(df('# USER root'));
  assert.deepEqual(userErrors(commentedRoot), [], 'a commented USER root is not a declared root user');
  assert.equal(userWarnings(commentedRoot).length, 1, 'but it is still a Dockerfile with no USER');
});

test('USER followed by later instructions still counts — the declaration is not required to be last', () => {
  const res = validateSource([
    'FROM node:20-alpine',
    'WORKDIR /app',
    'COPY . .',
    'USER node',
    'ENV NODE_ENV=production',
    'EXPOSE 3000',
    'HEALTHCHECK CMD wget -q -O- http://localhost:3000/health || exit 1',
    'CMD ["node", "server.js"]',
  ].join('\n') + '\n');
  assert.equal(res.valid, true);
  assert.deepEqual(userWarnings(res), []);
});

test('last-USER-wins semantics hold within a stage, in both directions', () => {
  // root then dropped -> the container runs as node -> accepted.
  assert.equal(validateSource(df('USER root', 'RUN chown -R node:node /app', 'USER node')).valid, true);
  // dropped then re-escalated -> the container runs as root -> rejected.
  const escalated = validateSource(df('USER node', 'USER root'));
  assert.equal(escalated.valid, false);
  assert.match(userErrors(escalated)[0], /root/i);
});

// --- falsification: the root regex must be able to NOT match --------------

test('near-misses of the root pattern are NOT treated as root', () => {
  // If these matched, the rule would be a rubber stamp that rejects everything
  // and the tests above would pass for the wrong reason.
  for (const u of ['rootless', 'root-user', 'rootuser', 'toor', '1000', '0user', '01000', 'node']) {
    const res = validateSource(df(`USER ${u}`));
    assert.equal(res.valid, true, `USER ${u} is not root and must be accepted`);
    assert.deepEqual(userErrors(res), [], `USER ${u} must not raise a root error`);
    assert.deepEqual(userWarnings(res), [], `USER ${u} is a declared user, so no missing-USER warning`);
  }
});

// --- multi-stage: USER is scoped to its stage -----------------------------

test('a USER set only in a build stage does not protect the final stage', () => {
  // The final stage inherits from node:20-alpine, i.e. root. The old
  // "last USER line in the file" reading called this safe — a false negative
  // that merely "must have a USER line somewhere" would not have caught either.
  const src = [
    'FROM node:20-alpine AS build',
    'WORKDIR /app',
    'USER node',
    'RUN npm run build',
    '',
    'FROM node:20-alpine',
    'WORKDIR /app',
    'COPY --from=build /app/dist ./dist',
    'EXPOSE 3000',
    'CMD ["node", "server.js"]',
  ].join('\n') + '\n';

  const res = validateSource(src);
  assert.equal(userWarnings(res).length, 1, 'the final stage runs as root and must be flagged');
  assert.equal(res.valid, true, 'default mode: warn');
  assert.equal(enforced(() => validateSource(src)).valid, false, 'enforcement mode: block');
});

test('a final stage that sets its own USER passes even when an earlier stage ran as root', () => {
  const res = validateSource([
    'FROM node:20-alpine AS build',
    'USER root',
    'RUN npm run build',
    '',
    'FROM node:20-alpine',
    'COPY --from=build /app/dist ./dist',
    'USER node',
    'EXPOSE 3000',
    'CMD ["node", "server.js"]',
  ].join('\n') + '\n');
  assert.equal(res.valid, true, 'root in a discarded build stage is not what the container runs as');
  assert.deepEqual(userWarnings(res), []);
});

test('a final stage built FROM a named non-root stage inherits that USER', () => {
  const res = validateSource([
    'FROM node:20-alpine AS base',
    'WORKDIR /app',
    'USER node',
    '',
    'FROM base',
    'COPY . .',
    'EXPOSE 3000',
    'CMD ["node", "server.js"]',
  ].join('\n') + '\n');
  assert.equal(res.valid, true);
  assert.deepEqual(userWarnings(res), [], 'inheriting a non-root stage is a declared non-root user');
});

test('a --platform flag on FROM does not break stage parsing', () => {
  const res = validateSource([
    'FROM --platform=linux/amd64 node:20-alpine AS build',
    'RUN npm run build',
    '',
    'FROM --platform=linux/amd64 node:20-alpine',
    'COPY --from=build /app/dist ./dist',
    'USER node',
    'EXPOSE 3000',
    'CMD ["node", "server.js"]',
  ].join('\n') + '\n');
  assert.equal(res.valid, true);
  assert.deepEqual(userWarnings(res), [], 'the final USER must still be found past the platform flag');
});

// --- the coupling that is the point: AppCrane's own output must pass -------

function generatedDockerfile(setup) {
  const dir = scratch('crane-dfgen-');
  const manifest = setup(dir) || {};
  const { path, userProvided } = ensureDockerfile({
    releaseDir: dir,
    manifest,
    appBasePath: '/apps/demo',
    craneUrl: 'https://crane.example',
    craneInternalUrl: 'http://127.0.0.1:3000',
  });
  assert.equal(userProvided, undefined, 'the generator must have written the Dockerfile, not reused one');
  return { dir, source: readFileSync(path, 'utf8') };
}

test('the generated flat-layout Dockerfile passes AppCrane\'s own validator', () => {
  const { dir, source } = generatedDockerfile((d) => {
    writeFileSync(join(d, 'package.json'), JSON.stringify({ name: 'demo', scripts: { start: 'node server.js' } }));
    return {};
  });

  assert.match(source, /^USER\s+(?!root\b|0(:|$))\S+/mi, 'generated Dockerfile must declare a non-root USER');

  const res = validateDockerfile(dir, { expectedPort: 3000 });
  assert.deepEqual(res.errors, []);
  assert.deepEqual(userWarnings(res), [], 'AppCrane must not generate a Dockerfile its own validator complains about');
  assert.equal(res.valid, true);
});

test('the generated monorepo Dockerfile passes AppCrane\'s own validator', () => {
  const { dir, source } = generatedDockerfile((d) => {
    mkdirSync(join(d, 'server'));
    mkdirSync(join(d, 'client'));
    writeFileSync(join(d, 'server', 'package.json'), JSON.stringify({ name: 'be', scripts: { start: 'node index.js' } }));
    writeFileSync(join(d, 'client', 'package.json'), JSON.stringify({
      name: 'fe', scripts: { build: 'vite build' }, devDependencies: { vite: '^5' },
    }));
    return { be: { workdir: 'server' }, fe: { workdir: 'client' } };
  });

  assert.match(source, /^USER\s+(?!root\b|0(:|$))\S+/mi);

  const res = validateDockerfile(dir, { expectedPort: 3000 });
  assert.deepEqual(res.errors, []);
  assert.deepEqual(userWarnings(res), []);
  assert.equal(res.valid, true);
});

test('the generated Dockerfile passes even under APPCRANE_REQUIRE_NONROOT=1', () => {
  // If AppCrane's own output could not survive its own enforcement mode, the
  // operator could never flip the flag.
  const { dir } = generatedDockerfile((d) => {
    writeFileSync(join(d, 'package.json'), JSON.stringify({ name: 'demo', scripts: { start: 'node server.js' } }));
    return {};
  });
  const res = enforced(() => validateDockerfile(dir, { expectedPort: 3000 }));
  assert.equal(res.valid, true);
  assert.deepEqual(res.errors, []);
});

// ---------------------------------------------------------------------------
// Post-review hardening: three shapes the final-stage rule alone got wrong.
// ---------------------------------------------------------------------------

test('root in a NON-final stage still BLOCKS, exactly as it did before this release', () => {
  // The regression the graduated policy created. Scoping the check to the final
  // stage is correct analysis, but combined with warn-by-default it made this
  // shape WEAKER than the rule it replaced: the file's last USER line is
  // `USER root`, so the old check blocked the deploy — and the final-stage rule
  // alone would merely warn, shipping a container that really does run as uid 0
  // where the author was previously forced to fix it. A security release must
  // not unblock something the previous version refused.
  const res = validateSource([
    'FROM node:20-alpine AS build', 'WORKDIR /app', 'USER root', 'RUN echo build-step', '',
    'FROM node:20-alpine', 'WORKDIR /app', 'COPY --from=build /app /app',
    'EXPOSE 3000', 'CMD ["node", "x.js"]',
  ].join('\n') + '\n');
  assert.equal(res.valid, false);
  assert.equal(userErrors(res).length, 1);

  // Control: the same root/non-root dance with the final stage declaring a user
  // must still pass. The guard re-applies the OLD rule verbatim, so it can only
  // block what already failed to deploy today — never more.
  const ok = validateSource([
    'FROM node:20-alpine AS build', 'USER root', 'RUN apk add curl', 'USER node', '',
    'FROM node:20-alpine', 'COPY --from=build /app /app',
    'EXPOSE 3000', 'USER node', 'CMD ["node", "x.js"]',
  ].join('\n') + '\n');
  assert.equal(ok.valid, true);
  assert.deepEqual(userWarnings(ok), []);
});

test('a USER built from a variable counts as undeclared, not as a non-root name', () => {
  // `ARG U=root` + `USER ${U}` is root, and no build runs at validation time —
  // so treating the literal "${U}" as a declared user silenced the finding for a
  // root container and let it through even under enforcement.
  const res = validateSource(df('ARG APP_USER=root', 'USER ${APP_USER}'));
  assert.equal(userWarnings(res).length, 1, 'an unresolvable USER was accepted as a declared user');
  assert.equal(res.valid, true, 'still only a warning by default — same policy as omitting USER');
  assert.equal(enforced(() => validateSource(df('ARG U=root', 'USER ${U}'))).valid, false);
});

test('padded numeric root is root', () => {
  // ROOT_USER matched a single 0; `USER 00` is also uid 0 and passed clean.
  assert.equal(validateSource(df('USER 00')).valid, false);
  // Control: the match must still be anchored and able to FAIL, or a rule that
  // rejects everything would satisfy the assertion above for the wrong reason.
  for (const u of ['01000', '0user', '1000', 'node']) {
    const ok = validateSource(df(`USER ${u}`));
    assert.equal(ok.valid, true, `USER ${u} was wrongly treated as root`);
    assert.deepEqual(userWarnings(ok), []);
  }
});

test('heredoc CONTENT is not parsed as instructions', () => {
  // `COPY <<CONF /etc/nginx.conf` inlines a config whose first line is
  // `user nginx;` — the standard opening of nginx.conf. Split naively into
  // lines, that reads as a declared non-root USER and silences the finding for
  // a container that is root. An accidental false negative, in exactly the
  // population this release exists to surface.
  const res = validateSource([
    '# syntax=docker/dockerfile:1.4', 'FROM node:20-alpine',
    'COPY <<CONF /etc/nginx.conf', 'user nginx;', 'worker_processes auto;', 'CONF',
    'EXPOSE 3000', 'CMD ["node", "x.js"]',
  ].join('\n') + '\n');
  assert.equal(userWarnings(res).length, 1, 'heredoc content was read as a USER instruction');

  // The stripper fails OPEN: a `<<` inside a shell string with no terminator
  // must not swallow the rest of the file and turn a passing Dockerfile into a
  // failing one.
  const open = validateSource(df('RUN echo "a<<b" > /tmp/x', 'USER node'));
  assert.equal(open.valid, true);
  assert.deepEqual(userWarnings(open), []);

  // And a real heredoc must not hide a real USER that follows it.
  const after = validateSource([
    'FROM node:20-alpine', 'RUN <<EOF', 'echo hi', 'EOF',
    'EXPOSE 3000', 'USER node', 'CMD ["node", "x.js"]',
  ].join('\n') + '\n');
  assert.equal(after.valid, true);
  assert.deepEqual(userWarnings(after), []);
});

// ---------------------------------------------------------------------------
// Ownership is established by construction, not by a recursive walk.
//
// The generator used to end every image with `RUN chown -R node:node /app`,
// placed AFTER the install and the build — so `npm ci`, the lifecycle scripts
// and `npm run build` all ran as root, produced a root-owned tree, and the
// chown then rewrote every one of those inodes into a fresh layer to hand them
// to uid 1000.
//
// Both halves of that were measured on real images before this change, with
// the control in each case being the identical Dockerfile minus the chown:
//
//   * CORRECTNESS. A non-root app that opens a SQLite file in its own workdir
//     fails without the chown -- `SQLITE_FAIL ERR_SQLITE_ERROR unable to open
//     database file`, exit 3, `/app` owned root:root -- and succeeds with the
//     shape asserted below, exit 0, `/app` owned node:node. So the chown was
//     never decorative, and deleting it outright would have broken these apps.
//     A postinstall-created directory behaves the same way: EACCES then, ok
//     now. (The docker-gated test at the bottom re-runs the SQLite half
//     against a real image, break and fix.)
//   * COST. 81 MB / 9,462 files under /app, 3 `--no-cache` builds each:
//     the recursive chown took 5.40 / 4.80 / 5.30 s of a 12.1 / 10.8 / 13.0 s
//     build and left a 451 MB image. The non-recursive form takes 0.10 s flat
//     and leaves 356 MB -- the 95 MB being the recursive chown copying every
//     file it touched into a new layer above the one already holding it.
//
// So the rule is: chown the ONE directory the image itself creates, drop to
// `node` before anything the app brings runs, and let `COPY --chown` carry the
// ownership of everything else.

const RECURSIVE_CHOWN = /chown\s+(-[a-zA-Z]*R[a-zA-Z]*\s+|--recursive\s+)/;

function genSource(setup) {
  return generatedDockerfile(setup).source;
}

const flatApp = (d) => {
  writeFileSync(join(d, 'package.json'), JSON.stringify({
    name: 'demo', scripts: { start: 'node server.js', build: 'node build.js' },
  }));
  writeFileSync(join(d, 'package-lock.json'), JSON.stringify({ name: 'demo', lockfileVersion: 3 }));
  return {};
};

const monoApp = (d) => {
  mkdirSync(join(d, 'server'));
  mkdirSync(join(d, 'client'));
  writeFileSync(join(d, 'server', 'package.json'), JSON.stringify({ name: 'be', scripts: { start: 'node index.js' } }));
  writeFileSync(join(d, 'client', 'package.json'), JSON.stringify({
    name: 'fe', scripts: { build: 'vite build' }, devDependencies: { vite: '^5' },
  }));
  return { be: { workdir: 'server' }, fe: { workdir: 'client' } };
};

const LAYOUTS = [['flat', flatApp], ['monorepo', monoApp]];

test('the generated Dockerfile contains no recursive chown, in either layout', () => {
  // Control first: the regex must be able to MATCH, or "no recursive chown" is
  // satisfied by a pattern that never fires and asserts nothing at all.
  assert.match('RUN chown -R node:node /app', RECURSIVE_CHOWN);
  assert.match('RUN chown --recursive node:node /app', RECURSIVE_CHOWN);
  assert.doesNotMatch('RUN chown node:node /app', RECURSIVE_CHOWN, 'the non-recursive form must NOT match');

  for (const [name, setup] of LAYOUTS) {
    assert.doesNotMatch(genSource(setup), RECURSIVE_CHOWN, `${name}: a recursive chown is back`);
  }
});

test('/app itself is chowned to node — the app must be able to create files in its own workdir', () => {
  // This is the line the SQLite app depends on. WORKDIR creates /app as root;
  // without it uid 1000 cannot create data.db there, and no amount of
  // COPY --chown helps, because the failure is on the DIRECTORY not the files.
  for (const [name, setup] of LAYOUTS) {
    assert.match(genSource(setup), /^RUN chown node:node \/app$/m, `${name}: /app ownership is not established`);
  }
});

test('USER node comes before every install, lifecycle script and build step', () => {
  // The property that makes the recursive chown unnecessary: nothing the app
  // brings runs as root, so nothing it creates is root-owned to begin with.
  for (const [name, setup] of LAYOUTS) {
    const lines = genSource(setup).split('\n');
    const userAt = lines.findIndex((l) => /^USER\s+node$/.test(l));
    assert.notEqual(userAt, -1, `${name}: no USER node line`);

    const appRuns = lines
      .map((l, i) => [l, i])
      .filter(([l]) => /^RUN /.test(l) && !/^RUN (apk|apt-get|chown) /.test(l));
    assert.ok(appRuns.length > 0, `${name}: no app RUN steps found — the assertion would be vacuous`);
    for (const [line, i] of appRuns) {
      assert.ok(i > userAt, `${name}: still runs as root: ${line.slice(0, 70)}`);
    }

    // ...and exactly one USER line, so the drop cannot be undone later.
    assert.equal(lines.filter((l) => /^USER\s/.test(l)).length, 1, `${name}: more than one USER line`);
  }
});

test('apk stays root — package installation still happens before the drop', () => {
  for (const [name, setup] of LAYOUTS) {
    const lines = genSource(setup).split('\n');
    const apkAt = lines.findIndex((l) => /^RUN apk /.test(l));
    const userAt = lines.findIndex((l) => /^USER\s/.test(l));
    assert.notEqual(apkAt, -1, `${name}: the apk step vanished`);
    assert.ok(apkAt < userAt, `${name}: apk would run unprivileged and fail`);
  }
});

test('every COPY carries --chown=node:node, so copied trees are never root-owned', () => {
  for (const [name, setup] of LAYOUTS) {
    const copies = genSource(setup).split('\n').filter((l) => /^COPY /.test(l));
    assert.ok(copies.length >= 2, `${name}: expected at least two COPY lines, got ${copies.length}`);
    for (const c of copies) assert.match(c, /^COPY --chown=node:node /, `${name}: unowned copy: ${c}`);
  }
});

test('npm global installs still work after the drop (NPM_CONFIG_PREFIX)', () => {
  // Measured: as `node`, `npm i -g left-pad` fails EACCES with npm rc=243,
  // because /usr/local/lib/node_modules is root-owned in the official image;
  // with the prefix pointed at the node user's own HOME it returns rc=0. A
  // manifest-supplied install command may legitimately open with
  // `npm i -g pnpm && pnpm i`, so without this the privilege drop would turn
  // into a build failure for those apps.
  for (const [name, setup] of LAYOUTS) {
    const lines = genSource(setup).split('\n');
    const prefixAt = lines.indexOf('ENV NPM_CONFIG_PREFIX=/home/node/.npm-global');
    const pathAt = lines.indexOf('ENV PATH=/home/node/.npm-global/bin:$PATH');
    const userAt = lines.findIndex((l) => /^USER\s/.test(l));
    assert.notEqual(prefixAt, -1, `${name}: no NPM_CONFIG_PREFIX`);
    assert.notEqual(pathAt, -1, `${name}: the global bin dir is not on PATH`);
    assert.ok(prefixAt < userAt && pathAt < userAt, `${name}: the prefix must be set before the drop`);
  }
});

test('the runtime workdir is unchanged by the reorder', () => {
  // Moving USER and the chown to the top must not change where the container
  // actually starts.
  assert.match(genSource(monoApp), /^WORKDIR \/app\/server$/m);
  assert.match(genSource(flatApp), /^WORKDIR \/app$/m);
});

test('an app-provided Dockerfile is still used byte-for-byte, untouched by any of this', () => {
  // The ownership rules are the GENERATOR's. An app that ships its own
  // Dockerfile owns its own build and must come back unmodified — including
  // its own recursive chown. We do not rewrite other people's builds.
  const dir = scratch('crane-dfown-');
  const authored = [
    'FROM node:20-alpine',
    'WORKDIR /app',
    'COPY . .',
    'RUN chown -R node:node /app',
    'USER node',
    'EXPOSE 3000',
    'CMD ["node", "server.js"]',
  ].join('\n') + '\n';
  writeFileSync(join(dir, 'Dockerfile'), authored);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'own' }));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ name: 'own', lockfileVersion: 3 }));

  const res = ensureDockerfile({
    releaseDir: dir,
    manifest: {},
    appBasePath: '/apps/demo',
    craneUrl: 'https://crane.example',
    craneInternalUrl: 'http://127.0.0.1:3000',
  });

  assert.equal(res.userProvided, true, 'the generator must not have overwritten it');
  assert.equal(readFileSync(res.path, 'utf8'), authored, 'an authored Dockerfile must come back byte-identical');
  assert.match(readFileSync(res.path, 'utf8'), RECURSIVE_CHOWN);
});

// --- the real thing ------------------------------------------------------

test('a real image: the non-root app can write a SQLite file in /app, and cannot without the chown', {
  skip: process.env.APPCRANE_DOCKERFILE_DOCKER_TEST === '1'
    ? false
    : 'set APPCRANE_DOCKERFILE_DOCKER_TEST=1 (needs docker + network)',
}, () => {
  // Break-and-fix in one test. The CONTROL is this generator's own output with
  // the /app chown deleted — the ownership mistake the recursive chown used to
  // paper over — and it must FAIL, or the passing half proves nothing.
  const dir = scratch('crane-dfsqlite-');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: 'sqlite-probe', version: '1.0.0', private: true, scripts: { start: 'node server.js' },
  }));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
    name: 'sqlite-probe', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: { '': { name: 'sqlite-probe', version: '1.0.0' } },
  }));
  writeFileSync(join(dir, 'server.js'), [
    "const { DatabaseSync } = require('node:sqlite');",
    "console.log('uid=' + process.getuid());",
    'try {',
    "  const db = new DatabaseSync('./data.db');",
    "  db.exec('CREATE TABLE IF NOT EXISTS t (v TEXT)');",
    "  db.prepare('INSERT INTO t (v) VALUES (?)').run('hello');",
    "  console.log('SQLITE_OK ' + JSON.stringify(db.prepare('SELECT v FROM t').get()));",
    '} catch (e) {',
    "  console.log('SQLITE_FAIL ' + e.message);",
    '  process.exit(3);',
    '}',
  ].join('\n') + '\n');

  // node:sqlite is built in from Node 22; the generator honours node_version.
  ensureDockerfile({
    releaseDir: dir,
    manifest: { node_version: '22' },
    appBasePath: '/apps/demo',
    craneUrl: 'https://crane.example',
    craneInternalUrl: 'http://127.0.0.1:3000',
  });
  const generated = readFileSync(join(dir, 'Dockerfile'), 'utf8');
  assert.match(generated, /^RUN chown node:node \/app$/m, 'the line under test must be present to be removable');

  const sh = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const tag = `appcrane-own-suite-${process.pid}`;
  const brokenTag = `${tag}-broken`;
  const run = (t) => {
    try { return { out: sh('docker', ['run', '--rm', t]), code: 0 }; } catch (e) {
      return { out: `${e.stdout || ''}${e.stderr || ''}`, code: e.status };
    }
  };

  try {
    // 1. The control: same Dockerfile, /app left root-owned.
    writeFileSync(join(dir, 'Dockerfile'), generated.replace(/^RUN chown node:node \/app\n/m, ''));
    sh('docker', ['build', '-q', '-t', brokenTag, dir]);
    const broken = run(brokenTag);
    assert.match(broken.out, /SQLITE_FAIL/, 'without the /app chown the write must FAIL — it did not, so the fix is untested');
    assert.equal(broken.code, 3);

    // 2. The generator's actual output.
    writeFileSync(join(dir, 'Dockerfile'), generated);
    sh('docker', ['build', '-q', '-t', tag, dir]);
    const fixed = run(tag);
    assert.match(fixed.out, /SQLITE_OK/, 'the generated image must be able to write in its own workdir');
    assert.match(fixed.out, /uid=1000/, 'and must still be running as non-root while doing it');
    assert.equal(fixed.code, 0);

    // 3. Nothing under /app is root-owned, which is the property the recursive
    //    chown used to buy and this shape must provide without it.
    //    (busybox find has no -printf, so this just lists the offending paths.)
    const owners = sh('docker', ['run', '--rm', '--entrypoint', 'find', tag, '/app', '-not', '-user', 'node']);
    assert.equal(owners.trim(), '', `not owned by node under /app: ${owners}`);

    // Control for that find: it must be able to REPORT something, or an empty
    // result would pass for a broken invocation rather than a clean tree.
    const control = sh('docker', ['run', '--rm', '--entrypoint', 'find', tag, '/app', '-not', '-user', 'root']);
    assert.notEqual(control.trim(), '', 'the ownership probe found nothing at all — it is not working');
  } finally {
    for (const t of [tag, brokenTag]) { try { sh('docker', ['rmi', '-f', t]); } catch (_) {} }
  }
});
