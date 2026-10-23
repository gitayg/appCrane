import { readFileSync, openSync, writeSync, fsyncSync, closeSync, chmodSync, renameSync, rmSync } from 'fs';
import { dirname } from 'path';

const LINE_RE = /^(\s*)ENCRYPTION_KEY\s*=(.*)$/;

/** The key the server would load from this .env (first ENCRYPTION_KEY line, first 64 chars), or null. */
export function readEnvKey(text) {
  for (const line of text.split('\n')) {
    const m = LINE_RE.exec(line);
    if (m) {
      const v = m[2].trim();
      return /^[0-9a-fA-F]{64}/.test(v) ? v.slice(0, 64).toLowerCase() : null;
    }
  }
  return null;
}

/** The .env text with every ENCRYPTION_KEY line set to newKey; nothing else changes. */
export function replaceEnvKey(text, newKey) {
  let n = 0;
  const out = text.split('\n').map((line) => {
    const m = LINE_RE.exec(line);
    if (!m) return line;
    n++;
    return `${m[1]}ENCRYPTION_KEY=${newKey}`;
  }).join('\n');
  if (!n) throw new Error('no ENCRYPTION_KEY line in .env');
  return out;
}

export function readEnv(envPath) {
  return readFileSync(envPath, 'utf8');
}

/**
 * Write `text` next to envPath as a 0600 temp file, fsynced. Returns
 * { commit(), discard() }: commit renames it over envPath (atomic on one
 * filesystem) and fsyncs the directory.
 */
export function stageEnv(envPath, text) {
  const tmp = `${envPath}.rotate-${process.pid}.tmp`;
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  return {
    path: tmp,
    commit() {
      renameSync(tmp, envPath);
      try {
        const dfd = openSync(dirname(envPath), 'r');
        try { fsyncSync(dfd); } finally { closeSync(dfd); }
      } catch (_) { /* directory fsync is best effort on platforms that refuse it */ }
    },
    discard() { rmSync(tmp, { force: true }); },
  };
}
