import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The codebase summary built before a coder's first turn (and Ask, and
// AppStudio) runs through runAgentOneShot. With a rejected key the CLI retries
// ten times over about three minutes (measured); all of that was a silent
// wait. It must reject at the first 401 retry.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-oneshot401-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
const BIN = join(ROOT, 'bin');
mkdirSync(BIN, { recursive: true });
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
printf '%s\\n' '{"type":"system","subtype":"api_retry","attempt":1,"max_retries":10,"error_status":401,"error":"authentication_failed"}'
exec sleep 30
`, { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { runAgentOneShot } = await import('../server/services/llm/runAgent.js');

test('a one-shot agent rejects at the first 401 retry instead of waiting out the loop', async () => {
  const ws = mkdtempSync(join(ROOT, 'ws-'));
  const started = Date.now();
  const err = await runAgentOneShot({ image: 'appcrane-studio:latest', workspaceDir: ws, prompt: 'p', apiKey: 'sk-ant-bad' })
    .then(() => null, (e) => e);
  const took = Date.now() - started;
  assert.ok(err, 'resolved despite a rejected credential');
  assert.match(err.message, /rejected the credential \(HTTP 401/, err.message);
  assert.ok(took < 10000, `waited ${took} ms on a credential that will never work`);
});
