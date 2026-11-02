import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { cloneGitRelease } from '../server/services/gitDeployClone.js';

// A stand-in `git` on PATH that sleeps, records its argv and fails on demand.
function fakeGit({ sleep = '1', failOn = '' } = {}) {
  const bin = mkdtempSync(join(tmpdir(), 'perf-deploy-git-'));
  const script = join(bin, 'git');
  writeFileSync(script, [
    '#!/bin/sh',
    `echo "$@" >> "${bin}/calls"`,
    `sleep ${sleep}`,
    failOn ? `case "$*" in *${failOn}*) echo "fatal: no such ref token-SECRET" >&2; exit 128;; esac` : '',
    'exit 0',
  ].join('\n'));
  chmodSync(script, 0o755);
  return bin;
}

async function withPath(bin, fn) {
  const old = process.env.PATH;
  process.env.PATH = `${bin}:${old}`;
  try { return await fn(); } finally { process.env.PATH = old; }
}

const gitOpts = (ms) => ({ timeout: ms, stdio: 'pipe' });
const scrubGit = (m) => String(m).replace(/SECRET/g, '***');

test('the event loop keeps running while git clone runs', async () => {
  const bin = fakeGit({ sleep: '1' });
  try {
    let ticks = 0;
    const timer = setInterval(() => { ticks++; }, 50);
    await withPath(bin, () => cloneGitRelease({
      cloneUrl: 'https://example.invalid/r.git', branch: 'main', releaseDir: join(bin, 'rel'),
      targetCommit: null, gitOpts, scrubGit, appendLog: () => {},
    }));
    clearInterval(timer);
    assert.ok(ticks >= 10, `only ${ticks} timer ticks during a 1 s clone`);
    assert.equal(readFileSync(join(bin, 'calls'), 'utf8').trim(), `clone --depth 1 --branch main https://example.invalid/r.git ${join(bin, 'rel')}`);
  } finally { rmSync(bin, { recursive: true, force: true }); }
});

test('promote pin: same fetch/deepen/checkout argv, and the same error text with credentials scrubbed', async () => {
  const bin = fakeGit({ sleep: '0', failOn: 'checkout' });
  try {
    const logs = [];
    await assert.rejects(
      withPath(bin, () => cloneGitRelease({
        cloneUrl: 'u', branch: 'dev', releaseDir: 'd', targetCommit: 'abc123',
        gitOpts, scrubGit, appendLog: (l) => logs.push(l),
      })),
      (e) => {
        assert.match(e.message, /^Failed to check out commit abc123 for promotion \(is it on branch 'dev' within the last 200 commits\?\): Command failed: git -C d checkout --detach abc123/);
        assert.ok(e.message.includes('token-***') && !e.message.includes('SECRET'));
        return true;
      },
    );
    assert.deepEqual(readFileSync(join(bin, 'calls'), 'utf8').trim().split('\n'), [
      'clone --depth 1 --branch dev u d',
      '-C d fetch --depth 1 origin abc123',
      '-C d checkout --detach abc123',
    ]);
    assert.deepEqual(logs, ['Pinning to commit abc123 (exact sandbox release)…']);
  } finally { rmSync(bin, { recursive: true, force: true }); }
});

test('a failed clone throws the scrubbed git error', async () => {
  const bin = fakeGit({ sleep: '0', failOn: 'clone' });
  try {
    await assert.rejects(
      withPath(bin, () => cloneGitRelease({ cloneUrl: 'u', branch: 'main', releaseDir: 'd', gitOpts, scrubGit, appendLog: () => {} })),
      /^Error: Command failed: git clone --depth 1 --branch main u d\nfatal: no such ref token-\*\*\*/,
    );
  } finally { rmSync(bin, { recursive: true, force: true }); }
});
