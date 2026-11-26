import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// v2.147.0: /api/config refuses API keys (403 SESSION_REQUIRED), and the CLI
// only has an API key. `crane config export|import` stay listed and say where
// the snapshot is taken now, exiting 1 before any request, old flags included.

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli', 'index.js');

test('crane config export and import name the dashboard, exit 1, and send no request', () => {
  const home = mkdtempSync(join(tmpdir(), 'crane-cli-config-'));
  try {
    const env = { ...process.env, HOME: home, CC_API_URL: 'http://127.0.0.1:9', CC_API_KEY: 'dhk_unused' };
    for (const args of [['export'], ['export', '--out', 'x.json'], ['import', 'f.json'], ['import', '--old-key', 'ab', 'f.json']]) {
      const r = spawnSync(process.execPath, [CLI, 'config', ...args], { env, encoding: 'utf8', timeout: 30_000 });
      assert.equal(r.status, 1, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
      const text = r.stdout + r.stderr;
      assert.match(text, new RegExp(`crane config ${args[0]} no longer works with an API key`), args.join(' '));
      assert.match(text, /Settings -> Backup & Restore/, args.join(' '));
      assert.doesNotMatch(text, /Connection failed/, `${args.join(' ')} still called the API`);
    }
    const help = spawnSync(process.execPath, [CLI, 'config', '--help'], { env, encoding: 'utf8', timeout: 30_000 });
    assert.match(help.stdout, /^\s+export\b/m);
    assert.match(help.stdout, /^\s+import\b/m);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
