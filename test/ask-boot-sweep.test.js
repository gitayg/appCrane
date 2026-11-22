import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'fs';
import net from 'net';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Earlier versions left the tokenized clone URL in ask-sessions/<id>/clone_url
// when a clone failed. The real server/index.js removes it at boot, whether or
// not anyone ever asks Ask anything again.

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = mkdtempSync(join(tmpdir(), 'crane-askbootsweep-'));
let child;
after(() => {
  try { child?.kill('SIGKILL'); } catch (_) {}
  rmSync(DATA, { recursive: true, force: true });
});

const freePort = () => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

test('a clone_url left on disk is gone once the real server has booted, and nothing else went with it', async () => {
  const leftover = join(DATA, 'ask-sessions', '42', 'clone_url');
  mkdirSync(dirname(leftover), { recursive: true });
  writeFileSync(leftover, 'https://ghp_CANARYboot0000@example.invalid/o/r.git', { mode: 0o644 });
  const keep = join(DATA, 'apps', 'keep', 'marker.txt');
  mkdirSync(dirname(keep), { recursive: true });
  writeFileSync(keep, 'keep\n');

  const port = await freePort();
  let out = '';
  child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO,
    env: { ...process.env, DATA_DIR: DATA, ENCRYPTION_KEY: 'd'.repeat(64), LOG_LEVEL: 'info', PORT: String(port), HOST: '127.0.0.1', APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { out += c; });
  let up = false;
  for (let i = 0; i < 240 && !up && child.exitCode === null; i++) {
    try { up = (await fetch(`http://127.0.0.1:${port}/api/info`)).ok; } catch (_) { /* booting */ }
    if (!up) await new Promise((r) => setTimeout(r, 250));
  }
  child.kill('SIGKILL');
  assert.ok(up, `the server did not come up:\n${out.slice(-1500)}`);
  assert.equal(existsSync(leftover), false, 'the token file survived boot');
  assert.equal(existsSync(join(DATA, 'ask-sessions')), false, 'the old session directory survived boot');
  assert.equal(readFileSync(keep, 'utf8'), 'keep\n');
  assert.ok(!out.includes('ghp_CANARYboot0000'), 'the token reached the log');
});
