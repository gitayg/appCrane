import { execFileSync } from 'child_process';
import { existsSync, lstatSync, readdirSync } from 'fs';
import { join } from 'path';

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
