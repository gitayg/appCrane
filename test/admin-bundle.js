import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// The admin SPA as production serves it: index.html's entry script plus every
// chunk reachable from it by import. The build is code-split, so the UI strings
// live across many chunks; a test that reads only the entry misses most of them,
// and one that reads every .js on disk would also read a stale chunk an older
// build left behind. `stale` lists .js files nothing reachable references.

const ADMIN_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs/admin-app');
const ASSETS_DIR = join(ADMIN_DIR, 'assets');

export function shippedBundle() {
  const indexHtml = readFileSync(join(ADMIN_DIR, 'index.html'), 'utf8');
  const entry = indexHtml.match(/<script[^>]+type="module"[^>]+src="[^"]*\/assets\/([^"/]+\.js)"/)?.[1] ?? null;
  const onDisk = readdirSync(ASSETS_DIR).filter((f) => f.endsWith('.js'));
  const reachable = [];
  const missing = [];
  const queue = entry ? [entry] : [];
  const seen = new Set();
  while (queue.length) {
    const f = queue.shift();
    if (seen.has(f)) continue;
    seen.add(f);
    if (!existsSync(join(ASSETS_DIR, f))) { missing.push(f); continue; }
    reachable.push(f);
    const src = readFileSync(join(ASSETS_DIR, f), 'utf8');
    for (const m of src.matchAll(/["'`](?:\.\/|\/docs\/admin-app\/assets\/|assets\/)([\w.-]+\.js)["'`]/g)) queue.push(m[1]);
  }
  const stale = onDisk.filter((f) => !seen.has(f));
  const text = reachable.map((f) => readFileSync(join(ASSETS_DIR, f), 'utf8')).join('\n');
  return { indexHtml, entry, reachable, missing, stale, text };
}
