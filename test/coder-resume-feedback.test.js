import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// "Resume doesn't work", reported on a real instance, with nothing on screen.
//
// Resume recreates the container and, after an upgrade, rebuilds the agent
// image first -- a minute or more. The request had no in-progress state and no
// timeout, so a slow resume and a dead button looked identical. And when the
// rebuild DID fail, the whole message was "docker build failed (exit 1)",
// which reads the same whether npm could not reach the registry or the disk
// was full.
//
// This file brings its own docker, so it asserts the same thing on every host
// -- see test/coder-availability.test.js for what happens when a test quietly
// depends on the machine running it having no Docker.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-resumefb-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const BIN = join(ROOT, 'bin');
mkdirSync(BIN, { recursive: true });
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
case "$1" in image) exit 1 ;; esac
echo "Step 3/8 : RUN npm install -g @anthropic-ai/claude-code"
echo "npm ERR! code ENOTFOUND" >&2
echo "npm ERR! network request to https://registry.npmjs.org failed" >&2
exit 1
`, { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { ensureStudioImage } = await import('../server/services/appstudio/generator.js');

test('a failed agent-image build says WHY, not just the exit code', async () => {
  const err = await ensureStudioImage(() => {}).then(() => null, (e) => e);
  assert.ok(err, 'the build did not fail');
  assert.match(err.message, /Could not build the coder's agent image/, err.message);
  assert.match(
    err.message, /npm ERR! network request to https:\/\/registry\.npmjs\.org failed/,
    'the build output was dropped: the user sees an exit code and nothing they can act on',
  );
  assert.doesNotMatch(err.message, /^docker build failed \(exit \d+\)$/,
    'back to the bare exit-code message');
});

const web = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');
const hook  = web('components/coder/useCoderSession.ts');
const panel = web('components/coder/CoderPanel.tsx');
const css   = web('admin.css');

test('resume has an in-progress state that the panel shows', () => {
  assert.match(hook, /setResumingSince\(Date\.now\(\)\)/, 'resume records no start time');
  assert.match(hook, /finally \{\s*setResumingSince\(null\)/, 'a resume that throws leaves the progress stuck on');
  assert.match(panel, /s\.resumingSince\s*\?\s*<ResumeProgress/,
    'the paused banner shows no progress while resume runs — a slow resume looks like a dead button');
});

test('resume is bounded, so a stalled server becomes a visible failure', () => {
  assert.match(hook, /Promise\.race\(\[\s*coderApi\.resume/, 'resume can wait forever with a counter running');
  assert.match(hook, /did not finish within 10 minutes/, 'the timeout gives no explanation');
});

test('a double-click cannot start two resumes', () => {
  assert.match(hook, /const resume = useCallback\(async \(\) => \{\s*if \(resumingSince\) return/, 'a second click fires a second resume');
  assert.match(hook, /const send = useCallback\(async \(text: string, chosen\?: string\) => \{\s*if \(!sessionId \|\| !text\.trim\(\) \|\| resumingSince\) return/,
    'a message sent during a resume starts a second one');
});

test('multi-line server messages keep their lines', () => {
  assert.match(css, /\.coder-refusal-body \{ white-space: pre-wrap/,
    'a build-log tail collapses onto one unreadable line');
});
