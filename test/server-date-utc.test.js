import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Reported from the request queue: a deploy made a moment ago showed as "4h ago".
// SQLite's datetime('now') is UTC with no zone marker, and new Date() reads a
// zone-less string as the browser's LOCAL time, shifting every time by the
// viewer's UTC offset. studio-web/src/utils/serverDate.ts reads it as UTC.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'studio-web', 'src');
const src = readFileSync(join(ROOT, 'utils/serverDate.ts'), 'utf8');
// Evaluate the helper without a TS toolchain: strip the type annotations.
const js = src.replace(/export function serverDate\(v: [^)]*\): Date/, 'function serverDate(v)').replace(/^\/\*\*[\s\S]*?\*\/\n/, '');
const serverDate = new Function(`${js}; return serverDate;`)();

test('a SQLite timestamp (no zone) is read as UTC', () => {
  assert.equal(serverDate('2026-10-13 08:00:00').toISOString(), '2026-10-13T08:00:00.000Z');
  assert.equal(serverDate('2026-10-13T08:00:00').toISOString(), '2026-10-13T08:00:00.000Z');
});

test('a value that already has a zone is left alone', () => {
  assert.equal(serverDate('2026-10-13T08:00:00Z').toISOString(), '2026-10-13T08:00:00.000Z');
  assert.equal(serverDate('2026-10-13T10:00:00+02:00').toISOString(), '2026-10-13T08:00:00.000Z');
  assert.ok(Number.isNaN(serverDate(null).getTime()));
});

test('no page parses a server *_at timestamp with a bare new Date()', () => {
  const offenders = [];
  const walk = (d) => {
    for (const f of readdirSync(d)) {
      const p = join(d, f);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.tsx?$/.test(f)) {
        readFileSync(p, 'utf8').split('\n').forEach((l, i) => {
          if (/new Date\([^)]*(_at|At)\b[^)]*\)/.test(l)) offenders.push(`${p.slice(ROOT.length + 1)}:${i + 1}`);
        });
      }
    }
  };
  walk(ROOT);
  assert.deepEqual(offenders, [], 'use serverDate() for API timestamps');
});

test('the audit page shows whether an agent or a person acted', () => {
  const audit = readFileSync(join(ROOT, 'pages/Audit.tsx'), 'utf8');
  assert.match(audit, /e\.actor_kind === 'agent' \|\| e\.actor_kind === 'human'/);
});
