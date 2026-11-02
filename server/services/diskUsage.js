import { execFile, execFileSync } from 'child_process';
import { existsSync, lstatSync, readdirSync } from 'fs';
import { lstat, readdir } from 'fs/promises';
import { join } from 'path';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * Total size in bytes of everything under `path` (a directory), following no
 * symlinks. Uses `du -sb` when available (fast, one syscall tree-walk) and
 * falls back to a manual walk if `du` isn't GNU-compatible or errors. Returns 0
 * for a missing path. Symlinks are counted as their own (tiny) size, never
 * followed — the per-app /data volume contains a symlink back to shared/data on
 * some layouts and we must not double-count or escape the tree.
 */
export function dirSizeBytes(path) {
  if (!path || !existsSync(path)) return 0;
  try {
    const out = execFileSync('du', ['-sb', path], { timeout: 20000, stdio: ['ignore', 'pipe', 'ignore'] }).toString();
    const n = parseInt(out.split('\t')[0], 10);
    if (Number.isFinite(n)) return n;
  } catch (_) { /* du missing / non-GNU (macOS) / error — walk in JS */ }

  let total = 0;
  const stack = [path];
  while (stack.length) {
    const p = stack.pop();
    let st;
    try { st = lstatSync(p); } catch (_) { continue; }
    if (st.isSymbolicLink()) { total += st.size; continue; }
    if (st.isDirectory()) {
      let entries;
      try { entries = readdirSync(p); } catch (_) { continue; }
      for (const e of entries) stack.push(join(p, e));
    } else {
      total += st.size;
    }
  }
  return total;
}

// dirSizeBytes without holding the event loop: `du` runs as a child process and
// the fallback walk awaits each stat, so a request path (and the forward_auth
// check every hosted app waits on) keeps being served while a big tree is sized.
export async function dirSizeBytesAsync(path) {
  if (!path || !existsSync(path)) return 0;
  try {
    const { stdout } = await execFileAsync('du', ['-sb', path], { timeout: 20000 });
    const n = parseInt(stdout.split('\t')[0], 10);
    if (Number.isFinite(n)) return n;
  } catch (_) { /* du missing / non-GNU (macOS) / error — walk in JS */ }

  let total = 0;
  const stack = [path];
  while (stack.length) {
    const p = stack.pop();
    let st;
    try { st = await lstat(p); } catch (_) { continue; }
    if (st.isSymbolicLink()) { total += st.size; continue; }
    if (st.isDirectory()) {
      let entries;
      try { entries = await readdir(p); } catch (_) { continue; }
      for (const e of entries) stack.push(join(p, e));
    } else {
      total += st.size;
    }
  }
  return total;
}

// Runs fn over items with at most `limit` in flight; results keep input order.
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
