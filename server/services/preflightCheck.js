// v2.6.16: pre-flight entry-exists check.
// Verify that deployhub.json's declared be.entry actually resolves in
// the just-built image, before we stop the old container or hand off
// to the 30s health probe. Catches the class of failure where a
// monorepo build puts the entry at /app/packages/server/dist/server.js
// but the manifest says "node server.js" — converts a 30s mystery
// timeout (whose docker logs only show wrapper info) into a 1s deploy
// failure with the missing path + suggested candidates spelled out.

// The checks read the image's files without running any of its code: `docker
// create` plus `docker cp` from the never-started container. They used to run
// `sh -c` from the image under execFileSync, so an image whose /bin/sh ignored
// SIGTERM blocked the event loop, and with it forward_auth for every app, until
// someone removed the container (measured: 73 s).

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import log from '../utils/logger.js';

// Marks the never-started containers below, for services/preflightSweep.js.
export const PREFLIGHT_LABEL = 'appcrane-preflight=true';
const DOCKER_TIMEOUT_MS = 15000;
const MAX_PACKAGE_JSON_TAR_BYTES = 4 * 1024 * 1024;
const MAX_TAR_META_BYTES = 1024 * 1024;
const MAX_RAW_CANDIDATES = 30;
const MAX_CANDIDATE_DEPTH = 6;
const TAR_BLOCK = 512;

// Docker did not answer in time. Not evidence about the file, so it must not
// read as "not found".
class ImageUnreadable extends Error {}

const COMMON_ENTRY_NAMES = [
  'server.js', 'server.mjs',
  'index.js', 'index.mjs',
  'app.js', 'app.mjs',
  'main.js', 'main.mjs',
];

export async function preflightEntryCheck({ image, entry, timeoutMs = DOCKER_TIMEOUT_MS }) {
  const trimmed = (entry || '').trim();
  if (!trimmed) return { ok: true, skipped: 'empty entry' };

  // entryToCmd routes shell-metacharacter entries through `sh -c`. Skip
  // pre-flight for those — too varied to validate generically.
  if (/[;&|<>$`]/.test(trimmed)) {
    return { ok: true, skipped: 'shell-piped entry' };
  }

  const parts = trimmed.split(/\s+/);
  const exe = parts[0];
  const isNode = exe === 'node' && parts.length >= 2 && !parts[1].startsWith('-');
  const isNpm = exe === 'npm' && (parts[1] === 'start' || parts[1] === 'run');
  if (!isNode && !isNpm) return { ok: true, skipped: `unrecognized entry pattern: ${exe}` };

  const name = `appcrane-preflight-${randomBytes(9).toString('hex')}`;
  try {
    // Never started, so the entrypoint only has to be a string. Given anyway
    // because create refuses an image that names no command.
    const created = await docker(['create', '--pull', 'never', '--network', 'none', '--name', name, '--label', PREFLIGHT_LABEL, '--entrypoint', '/appcrane-preflight-never-started', image], { timeoutMs });
    if (created !== 0) throw new ImageUnreadable(`docker create exited ${created}`);

    if (isNode) {
      const relPath = parts[1].replace(/^\.?\/+/, '');
      if (await imageFileExists(name, `/app/${relPath}`, timeoutMs)) {
        return { ok: true };
      }
      const candidates = await findCandidates(name, timeoutMs);
      return {
        ok: false,
        shortReason: `declared entry "${entry}" — /app/${relPath} not found in built image`,
        message: buildNodeEntryNotFoundMessage(entry, relPath, candidates),
      };
    }

    const startScript = await readNpmStartScript(name, timeoutMs);
    if (startScript) return { ok: true };
    const candidates = await findCandidates(name, timeoutMs);
    return {
      ok: false,
      shortReason: `declared entry "${entry}" — /app/package.json has no scripts.start`,
      message: buildNpmStartMissingMessage(entry, candidates),
    };
  } catch (e) {
    if (!(e instanceof ImageUnreadable)) throw e;
    return {
      ok: false,
      shortReason: `could not read the built image to check entry "${entry}"`,
      message: `Pre-flight check failed: could not read the built image (${e.message}). This says nothing about the entry itself; redeploy to retry.`,
    };
  } finally {
    // -v: an image that declares VOLUME gets an anonymous volume at create.
    await docker(['rm', '-f', '-v', name], { timeoutMs }).catch((e) => {
      log.warn(`pre-flight: could not remove container ${name}: ${e.message}`);
    });
  }
}

/**
 * Run docker without blocking the event loop. Resolves with the exit code, and
 * rejects with ImageUnreadable when it could not be started or outlives
 * timeoutMs. The client gets SIGKILL and the promise settles there and then,
 * whatever holds its pipes. `onData(chunk, stop)` sees stdout; stop() ends the
 * command early and resolves with code 0.
 */
function docker(args, { timeoutMs, onData = null }) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: ['ignore', onData ? 'pipe' : 'ignore', 'ignore'] });
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdout?.destroy();
      try { child.kill('SIGKILL'); } catch (_) {}
      fn(value);
    };
    const timer = setTimeout(() => finish(reject, new ImageUnreadable(`docker ${args[0]} did not finish in ${timeoutMs} ms`)), timeoutMs);
    child.on('error', (e) => finish(reject, new ImageUnreadable(`docker ${args[0]}: ${e.message}`)));
    child.on('close', (code) => finish(resolve, code));
    if (onData) child.stdout.on('data', (chunk) => onData(chunk, () => finish(resolve, 0)));
  });
}

// `-L` because `test -e` followed links: a dangling one is "missing" either way.
// The daemon resolves it inside the container's filesystem.
async function imageFileExists(container, absPath, timeoutMs) {
  const code = await docker(['cp', '-L', `${container}:${absPath}`, '-'], {
    timeoutMs,
    onData: (_chunk, stop) => stop(),
  });
  return code === 0;
}

async function readNpmStartScript(container, timeoutMs) {
  let size = 0;
  const chunks = [];
  const code = await docker(['cp', '-L', `${container}:/app/package.json`, '-'], {
    timeoutMs,
    onData: (chunk, stop) => {
      size += chunk.length;
      if (size > MAX_PACKAGE_JSON_TAR_BYTES) { chunks.length = 0; stop(); return; }
      chunks.push(chunk);
    },
  });
  if (code !== 0 || !chunks.length) return null;
  let body = null;
  const walk = tarWalker((entry) => { if (entry.regular && body === null) body = entry.body; }, { keepBodies: true });
  walk(Buffer.concat(chunks));
  if (body === null) return null;
  try {
    return JSON.parse(body.toString('utf8'))?.scripts?.start || null;
  } catch {
    return null;
  }
}

async function findCandidates(container, timeoutMs) {
  // Common entry-file names anywhere under /app (skipping node_modules), capped
  // at 30 raw hits, then ranked + trimmed to 5. Only tar headers are looked at;
  // file bodies stream past. A timeout just means no suggestions.
  const hits = [];
  const walk = tarWalker((entry) => {
    if (!entry.regular || hits.length >= MAX_RAW_CANDIDATES) return;
    const rel = entry.path.split('/').filter(Boolean).slice(1);
    if (rel.length === 0 || rel.length > MAX_CANDIDATE_DEPTH) return;
    if (rel.includes('node_modules') || !COMMON_ENTRY_NAMES.includes(rel[rel.length - 1])) return;
    hits.push(`/app/${rel.join('/')}`);
  });
  try {
    await docker(['cp', '-L', `${container}:/app`, '-'], {
      timeoutMs,
      onData: (chunk, stop) => {
        walk(chunk);
        if (hits.length >= MAX_RAW_CANDIDATES) stop();
      },
    });
  } catch (e) {
    if (!(e instanceof ImageUnreadable)) throw e;
  }
  return rankCandidates(hits);
}

function tarNumber(buf, offset, length) {
  // GNU base-256 for values too big for the octal field.
  if (buf[offset] & 0x80) {
    let n = buf[offset] & 0x7f;
    for (let i = offset + 1; i < offset + length; i++) n = n * 256 + buf[i];
    return n;
  }
  const text = buf.toString('latin1', offset, offset + length).replace(/\0.*$/, '').trim();
  return text ? parseInt(text, 8) : 0;
}

function tarString(buf, offset, length) {
  const end = buf.indexOf(0, offset);
  return buf.toString('utf8', offset, end === -1 || end > offset + length ? offset + length : end);
}

function paxRecords(body) {
  const out = {};
  let at = 0;
  while (at < body.length) {
    const space = body.indexOf(0x20, at);
    if (space === -1) break;
    const len = parseInt(body.toString('latin1', at, space), 10);
    if (!(len > 0)) break;
    const record = body.toString('utf8', space + 1, at + len - 1);
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    at += len;
  }
  return out;
}

/**
 * A push parser for the tar stream `docker cp` writes. Calls onEntry({ path,
 * regular, body }) per member; body is null unless keepBodies. The stream comes
 * from dockerd but the names in it are the image author's, so they are only
 * ever compared and printed. Handles PAX and GNU long names, which is how a path
 * past 100 characters arrives. A malformed header stops the walk.
 */
function tarWalker(onEntry, { keepBodies = false } = {}) {
  let pending = Buffer.alloc(0);
  let skip = 0;
  let collect = null;
  let override = {};
  let done = false;

  const settleBody = (body) => {
    const c = collect;
    collect = null;
    if (c.kind === 'x') override = { ...override, ...paxRecords(body) };
    else if (c.kind === 'L') override.path = body.toString('utf8').replace(/\0+$/, '');
    else onEntry({ path: c.path, regular: true, body });
  };

  return (chunk) => {
    if (done) return;
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    for (;;) {
      if (skip > 0) {
        const n = Math.min(skip, pending.length);
        pending = pending.subarray(n);
        skip -= n;
        if (skip > 0) return;
      }
      if (collect) {
        if (pending.length < collect.size) return;
        const consumed = collect.size;
        settleBody(pending.subarray(0, collect.bodySize));
        pending = pending.subarray(consumed);
        continue;
      }
      if (pending.length < TAR_BLOCK) return;
      const header = pending.subarray(0, TAR_BLOCK);
      pending = pending.subarray(TAR_BLOCK);
      if (header.every((b) => b === 0)) continue;

      let sum = 0;
      for (let i = 0; i < TAR_BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i];
      if (sum !== tarNumber(header, 148, 8)) { done = true; return; }

      const type = String.fromCharCode(header[156] || 0x30);
      const size = Number(override.size ?? tarNumber(header, 124, 12));
      const padded = Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;

      if (type === 'x' || type === 'L') {
        if (size > MAX_TAR_META_BYTES) { done = true; return; }
        collect = { kind: type, size: padded, bodySize: size };
        continue;
      }
      if (type === 'g') { skip = padded; continue; }

      const prefix = header.toString('latin1', 257, 262) === 'ustar' ? tarString(header, 345, 155) : '';
      const name = tarString(header, 0, 100);
      const path = override.path ?? (prefix ? `${prefix}/${name}` : name);
      override = {};
      const regular = type === '0' || type === '7';
      if (regular && keepBodies) {
        collect = { kind: 'file', path, size: padded, bodySize: size };
        continue;
      }
      onEntry({ path, regular, body: null });
      if (regular) skip = padded;
    }
  };
}

function rankCandidates(paths) {
  const score = (p) => {
    let s = 0;
    if (/\b(dist|build|out|lib)\b/.test(p)) s += 10;
    if (/\bserver\b/.test(p)) s += 5;
    if (/\b(test|tests|spec|specs|example|examples|fixture|fixtures|__tests__)\b/.test(p)) s -= 20;
    s -= p.split('/').length;
    return s;
  };
  return paths.sort((a, b) => score(b) - score(a)).slice(0, 5);
}

function buildNodeEntryNotFoundMessage(entry, relPath, candidates) {
  const out = [
    `Pre-flight check failed: deployhub.json declares be.entry: "${entry}", ` +
    `but /app/${relPath} does not exist in the built image.`,
  ];

  if (candidates.length === 0) {
    out.push(
      '',
      `No common entry-file names (${COMMON_ENTRY_NAMES.join(', ')}) ` +
      'were found under /app outside node_modules.',
      '',
      'Likely causes:',
      '  • The Dockerfile build stage failed silently and the entry was never produced.',
      '  • The entry file uses a non-standard name AppCrane could not auto-detect.',
      '',
      'Open the Dockerfile and verify it copies (or builds) your entry file into /app/.',
    );
    return out.join('\n');
  }

  const best = candidates[0];
  const bestRel = best.replace(/^\/app\//, '');

  out.push(
    '',
    'Candidate entry files found in the built image:',
    ...candidates.map((c) => `  • ${c}`),
    '',
    'Recommended fix — layout-agnostic (survives future build-path changes):',
    '  1. Add to your root package.json:',
    `       "scripts": { "start": "node ${bestRel}" }`,
    '  2. Update deployhub.json:',
    '       "be": { "entry": "npm start", "health": "<your health path>" }',
    '',
    'Or, minimal one-line change in deployhub.json:',
    `       "be": { "entry": "node ${bestRel}", "health": "<your health path>" }`,
    '',
    'Commit + push to your repo, then redeploy.',
  );
  return out.join('\n');
}

function buildNpmStartMissingMessage(entry, candidates) {
  const out = [
    `Pre-flight check failed: deployhub.json declares be.entry: "${entry}", ` +
    'but /app/package.json has no "scripts.start" field in the built image.',
  ];

  if (candidates.length > 0) {
    const best = candidates[0];
    const bestRel = best.replace(/^\/app\//, '');
    out.push(
      '',
      'Candidate entry files found in the built image:',
      ...candidates.map((c) => `  • ${c}`),
      '',
      'Recommended fix — add a start script to your root package.json:',
      `  "scripts": { "start": "node ${bestRel}" }`,
      '',
      'Commit + push, then redeploy.',
    );
  } else {
    out.push(
      '',
      'Add a start script to your root package.json, e.g.:',
      '  "scripts": { "start": "node <path/to/your/entry.js>" }',
      '',
      'Commit + push, then redeploy.',
    );
  }
  return out.join('\n');
}
