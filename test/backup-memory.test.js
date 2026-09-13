import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync, mkdirSync, createWriteStream, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { randomBytes, createHash } from 'crypto';

// No backup is held in memory. Measured as peak RSS of a child process that
// exports, then imports, a data archive of an incompressible fixture several
// times larger than the allowed growth. Before v2.74.0 both directions held the
// whole archive (and on export the source files too) in the heap.

const MB = 1024 * 1024;
const FIXTURE_MB = Number(process.env.BACKUP_RSS_FIXTURE_MB || 256);
const MAX_GROWTH_MB = 80;
const here = dirname(fileURLToPath(import.meta.url));
const CHILD = join(here, 'backup-memory.child.mjs');

const ROOT = mkdtempSync(join(tmpdir(), 'crane-rss-'));
after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

const child = (mode, extra = []) => JSON.parse(execFileSync(process.execPath, [CHILD, mode, ROOT, ...extra], {
  env: { ...process.env, DATA_DIR: ROOT, ENCRYPTION_KEY: '7'.repeat(64), LOG_LEVEL: 'error' },
  maxBuffer: 1024 * 1024, timeout: 600000,
}).toString().trim().split('\n').pop());

async function writeRandom(path, bytes, hash) {
  await new Promise((resolve, reject) => {
    const ws = createWriteStream(path);
    ws.on('error', reject);
    ws.on('finish', resolve);
    let left = bytes;
    const pump = () => {
      while (left > 0) {
        const chunk = randomBytes(Math.min(4 * MB, left));
        hash.update(chunk);
        left -= chunk.length;
        if (!ws.write(chunk)) return ws.once('drain', pump);
      }
      ws.end();
    };
    pump();
  });
}

test(`peak RSS of export and import stays flat for a ${FIXTURE_MB} MB incompressible fixture`, async () => {
  const dataDir = join(ROOT, 'apps', 'big', 'production', 'shared', 'data');
  mkdirSync(dataDir, { recursive: true });
  const hash = createHash('sha256');
  const files = FIXTURE_MB / 16;
  for (let i = 0; i < files; i++) await writeRandom(join(dataDir, `blob-${String(i).padStart(3, '0')}.bin`), 16 * MB, hash);
  const fixtureSha = hash.digest('hex');

  const base = child('baseline');
  const exp = child('export');
  rmSync(join(ROOT, 'apps'), { recursive: true, force: true });
  const imp = child('import', [exp.path]);

  const rehash = createHash('sha256');
  const { readFileSync } = await import('fs');
  for (const f of readdirSync(dataDir).sort()) rehash.update(readFileSync(join(dataDir, f)));

  const mb = (kb) => (kb / 1024).toFixed(1);
  console.log(`# peak RSS: baseline=${mb(base.maxRSS)} MB export=${mb(exp.maxRSS)} MB import=${mb(imp.maxRSS)} MB; fixture=${FIXTURE_MB} MB, archive=${(exp.bytes / MB).toFixed(1)} MB`);
  assert.equal(rehash.digest('hex'), fixtureSha, 'the fixture did not round-trip byte-identical');
  assert.ok(exp.bytes > FIXTURE_MB * MB * 0.9, 'fixture: the archive must actually be large');
  assert.ok((exp.maxRSS - base.maxRSS) / 1024 < MAX_GROWTH_MB, `export grew RSS by ${mb(exp.maxRSS - base.maxRSS)} MB`);
  assert.ok((imp.maxRSS - base.maxRSS) / 1024 < MAX_GROWTH_MB, `import grew RSS by ${mb(imp.maxRSS - base.maxRSS)} MB`);
});
