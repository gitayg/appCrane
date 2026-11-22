/**
 * git smart-HTTP for Crane-hosted apps: `git upload-pack` (clone/fetch) and
 * `git receive-pack` (push) run by AppCrane against the bare repo it owns.
 *
 * PROTOCOL v0 ONLY. The client's Git-Protocol header is never forwarded, so
 * upload-pack never speaks v2. Measured with git 2.54: under v2 a `fetch` of an
 * object id that is only reachable from a hidden ref succeeds, while v0 refuses
 * it ("Server does not allow request for unadvertised object"). The hidden refs
 * below are other users' agent branches, so v2 would turn "hidden" into
 * "unlisted". Every git client falls back to v0 on its own.
 *
 * REFS. agent/<userId>/<sessionId> is one person's unreleased coder work,
 * rescued at eviction. A member who is not that person cannot see it through
 * the coder UI, so they cannot see it here either: every refs/heads/agent ref
 * is hidden, then the caller's own agent/<id> is un-hidden. Later hideRefs
 * entries win, and `-c` is read after the repo's own config, so a repo config
 * cannot re-expose another user's branch. Matching is per path component:
 * `!refs/heads/agent/5` exposes agent/5/* and not agent/50/*.
 *
 * Config the server did not write: uploadpack.packObjectsHook is honoured only
 * from protected config (system / global / -c), and all three are ours. The
 * want-by-id switches are pinned off on the command line for the same reason.
 */

import { spawn } from 'child_process';
import { createGunzip } from 'zlib';
import { createReadStream, createWriteStream, mkdirSync, mkdtempSync, rmSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { hardenedGitInvocation, repoPath } from './localGit.js';
import log from '../utils/logger.js';

export const GIT_HTTP_LIMITS = Object.freeze({
  maxBodyBytes: 32 * 1024 * 1024,
  maxPushBytes: 100 * 1024 * 1024,
  timeoutMs: 10 * 60_000,
  maxConcurrent: 16,
});

let active = 0;
export const activeUploadPacks = () => active;

export function uploadPackArgs(slug, { userId, advertiseRefs }) {
  const uid = String(userId);
  if (!/^[1-9][0-9]*$/.test(uid)) throw new Error(`gitHttp: refusing user id ${JSON.stringify(uid)}`);
  return hardenedGitInvocation([
    '-c', 'uploadpack.hideRefs=refs/heads/agent',
    '-c', `uploadpack.hideRefs=!refs/heads/agent/${uid}`,
    // A tip displaced from an agent branch is parked under refs/dropped/<branch>
    // (localGit.js): the same commit, so hidden from everyone like the branch.
    '-c', 'uploadpack.hideRefs=refs/dropped/agent',
    '-c', 'uploadpack.allowTipSHA1InWant=false',
    '-c', 'uploadpack.allowReachableSHA1InWant=false',
    '-c', 'uploadpack.allowAnySHA1InWant=false',
    'upload-pack', '--strict', '--stateless-rpc',
    ...(advertiseRefs ? ['--advertise-refs'] : []),
    repoPath(slug),
  ]);
}

export function plain(res, status, message, headers = {}) {
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-cache', ...headers });
  res.end(`${message}\n`);
}

const pktLine = (s) => `${(s.length + 4).toString(16).padStart(4, '0')}${s}`;

/**
 * GET info/refs (advertise) or POST git-upload-pack. Headers are written on the
 * first byte git produces, so a git that fails before saying anything becomes a
 * 500 instead of a truncated 200.
 */
export function serveUploadPack(req, res, { slug, userId, advertise, limits = GIT_HTTP_LIMITS }) {
  let src = null;
  if (!advertise) {
    const enc = String(req.headers['content-encoding'] || 'identity').toLowerCase();
    if (enc === 'gzip' || enc === 'x-gzip') src = req.pipe(createGunzip());
    else if (enc === 'identity') src = req;
    else return plain(res, 415, `Unsupported Content-Encoding: ${enc}`);
    if (Number(req.headers['content-length']) > limits.maxBodyBytes) return plain(res, 413, 'Request body too large');
  }
  if (active >= limits.maxConcurrent) return plain(res, 503, 'Too many git transfers in progress; try again shortly', { 'Retry-After': '10' });

  const { args, env } = uploadPackArgs(slug, { userId, advertiseRefs: advertise });
  const child = spawn('git', args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
  active++;
  let settled = false;
  let refused = false;
  let stderr = '';
  const settle = () => { if (!settled) { settled = true; active--; clearTimeout(timer); } };
  const kill = () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); };
  const timer = setTimeout(() => { kill(); res.destroy(); }, limits.timeoutMs);
  res.on('close', kill);

  const type = advertise ? 'application/x-git-upload-pack-advertisement' : 'application/x-git-upload-pack-result';
  const start = () => {
    if (res.headersSent) return;
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache', Expires: 'Fri, 01 Jan 1980 00:00:00 GMT', Pragma: 'no-cache' });
    if (advertise) res.write(`${pktLine('# service=git-upload-pack\n')}0000`);
  };

  child.stdin.on('error', () => {});
  child.stderr.on('data', (d) => { if (stderr.length < 4096) stderr += d; });
  child.stdout.on('data', (chunk) => {
    if (refused) return;
    start();
    if (!res.write(chunk)) { child.stdout.pause(); res.once('drain', () => child.stdout.resume()); }
  });
  child.on('error', (err) => {
    settle();
    log.warn(`git upload-pack for ${slug} could not start: ${err.message}`);
    if (!refused) plain(res, 500, 'git upload-pack failed');
  });
  child.on('close', (code, signal) => {
    settle();
    if (refused || res.writableEnded || res.destroyed) return;
    if (code !== 0) log.warn(`git upload-pack for ${slug} exited ${code ?? signal}: ${stderr.trim().slice(0, 500)}`);
    if (res.headersSent) return res.end();
    if (code === 0) { start(); return res.end(); }
    plain(res, 500, 'git upload-pack failed');
  });

  if (advertise) { child.stdin.end(); return; }

  let bytes = 0;
  src.on('data', (chunk) => {
    bytes += chunk.length;
    if (bytes > limits.maxBodyBytes) {
      refused = true;
      kill();
      src.destroy();
      return plain(res, 413, 'Request body too large');
    }
    if (!child.stdin.write(chunk)) { src.pause(); child.stdin.once('drain', () => src.resume()); }
  });
  src.on('end', () => child.stdin.end());
  src.on('error', () => {
    if (refused) return;
    refused = true;
    kill();
    plain(res, 400, 'Malformed request body');
  });
}

/*
 * PUSH (receive-pack). Who may push is the route's decision; what a push may do
 * is decided here, twice:
 *
 *   1. AppCrane reads the command list (old new ref) at the head of the request
 *      and refuses deletions, tag moves, refs outside refs/heads and refs/tags,
 *      and another user's agent branch. A branch update is a fast-forward only:
 *      the pack is indexed into a quarantine object directory (the repo's own
 *      objects as an alternate, so nothing lands in the repo) and
 *      `merge-base --is-ancestor old new` must hold. Any refusal refuses the
 *      whole push before receive-pack ever runs.
 *   2. receive-pack itself runs with denyNonFastForwards / denyDeletes /
 *      fsckObjects / maxInputSize pinned on the command line, where repo config
 *      cannot undo them. git applies denyNonFastForwards to refs/heads only, so
 *      a tag move is refused by (1) alone.
 *
 * No hooks: core.hooksPath=/dev/null (hardenedGitInvocation) is read after the
 * repo's config, so neither hooks/ in the bare repo nor a core.hooksPath there
 * can run, and gc is off. The request body is spooled to a temp file outside
 * the repo, capped at maxPushBytes, so memory stays bounded.
 */

const ZERO_SHA = '0'.repeat(40);
const PUSH_HEAD_MAX = 1024 * 1024;

let activeReceive = 0;
export const activeReceivePacks = () => activeReceive;

const checkUid = (userId) => {
  const uid = String(userId);
  if (!/^[1-9][0-9]*$/.test(uid)) throw new Error(`gitHttp: refusing user id ${JSON.stringify(uid)}`);
  return uid;
};

export function receivePackArgs(slug, { userId, advertiseRefs, maxPushBytes = GIT_HTTP_LIMITS.maxPushBytes }) {
  const uid = checkUid(userId);
  return hardenedGitInvocation([
    '-c', 'receive.hideRefs=refs/heads/agent',
    '-c', `receive.hideRefs=!refs/heads/agent/${uid}`,
    '-c', 'receive.hideRefs=refs/dropped',
    '-c', 'receive.denyNonFastForwards=true',
    '-c', 'receive.denyDeletes=true',
    '-c', 'receive.denyCurrentBranch=refuse',
    '-c', 'receive.fsckObjects=true',
    '-c', 'receive.advertisePushOptions=false',
    '-c', 'receive.shallowUpdate=false',
    '-c', 'receive.autogc=false',
    '-c', 'receive.updateServerInfo=false',
    '-c', `receive.maxInputSize=${Number(maxPushBytes)}`,
    'receive-pack', '--stateless-rpc',
    ...(advertiseRefs ? ['--advertise-refs'] : []),
    repoPath(slug),
  ]);
}

/**
 * The command list at the head of a receive-pack request: pkt-lines of
 * `<old> <new> <ref>` (the first carries `\0<capabilities>`), then a flush.
 * Returns null when the head is not complete yet; throws when it is malformed.
 */
export function parsePushCommands(buf) {
  const commands = [];
  let caps = new Set();
  let off = 0;
  for (;;) {
    if (off + 4 > buf.length) return null;
    const hex = buf.toString('latin1', off, off + 4);
    if (!/^[0-9a-f]{4}$/.test(hex)) throw new Error('malformed pkt-line');
    const len = parseInt(hex, 16);
    if (len === 0) { off += 4; break; }
    if (len < 5) throw new Error('malformed pkt-line');
    if (off + len > buf.length) return null;
    let line = buf.toString('latin1', off + 4, off + len);
    off += len;
    if (line.endsWith('\n')) line = line.slice(0, -1);
    const nul = line.indexOf('\0');
    if (nul >= 0) {
      if (commands.length === 0) caps = new Set(line.slice(nul + 1).split(' ').filter(Boolean));
      line = line.slice(0, nul);
    }
    if (line.startsWith('shallow ')) continue;
    if (line.startsWith('push-cert')) throw new Error('signed pushes are not accepted');
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (refs\/\S+)$/.exec(line);
    if (!m) throw new Error('malformed ref update command');
    commands.push({ old: m[1], new: m[2], ref: m[3] });
  }
  if (caps.has('push-options')) throw new Error('push options are not accepted');
  return { commands, caps, packOffset: off };
}

/** Why AppCrane refuses one ref update on its face, or null. */
export function pushCommandRefusal(cmd, userId) {
  const uid = checkUid(userId);
  if (cmd.new === ZERO_SHA) return 'AppCrane does not allow deleting a ref';
  if (cmd.ref.startsWith('refs/tags/')) return cmd.old === ZERO_SHA ? null : 'AppCrane does not allow moving or replacing an existing tag';
  if (!cmd.ref.startsWith('refs/heads/')) return 'AppCrane accepts pushes to branches (refs/heads/*) and new tags (refs/tags/*) only';
  if ((cmd.ref === 'refs/heads/agent' || cmd.ref.startsWith('refs/heads/agent/'))
      && cmd.ref !== `refs/heads/agent/${uid}` && !cmd.ref.startsWith(`refs/heads/agent/${uid}/`)) {
    return 'agent branches belong to the user they were rescued for';
  }
  return null;
}

const NON_FF = 'non-fast-forward: AppCrane refuses force pushes and history rewrites';
const NOT_APPLIED = 'not applied: another ref in this push was refused';

function pushStatus(caps, results, { unpack = 'ok', message = '' } = {}) {
  const inner = Buffer.from(pktLine(`unpack ${unpack}\n`)
    + results.map((r) => pktLine(r.error ? `ng ${r.ref} ${r.error}\n` : `ok ${r.ref}\n`)).join('')
    + '0000');
  const band = caps.has('side-band-64k') ? 65515 : caps.has('side-band') ? 995 : 0;
  if (!band) return inner;
  const parts = [];
  const frame = (ch, data) => {
    const head = Buffer.from((data.length + 5).toString(16).padStart(4, '0'));
    parts.push(head, Buffer.from([ch]), data);
  };
  if (message && !caps.has('quiet')) frame(2, Buffer.from(`${message}\n`));
  for (let i = 0; i < inner.length; i += band) frame(1, inner.subarray(i, i + band));
  parts.push(Buffer.from('0000'));
  return Buffer.concat(parts);
}

/** ng reasons from receive-pack's (possibly side-band) report-status. */
export function parseReportStatus(buf) {
  const read = (b, onPkt) => {
    let off = 0;
    while (off + 4 <= b.length) {
      const len = parseInt(b.toString('latin1', off, off + 4), 16);
      if (!(len >= 4) || off + len > b.length) break;
      onPkt(b.subarray(off + 4, off + len));
      off += len;
    }
  };
  let status = Buffer.alloc(0);
  let banded = false;
  read(buf, (p) => { if (p[0] === 1) { banded = true; status = Buffer.concat([status, p.subarray(1)]); } });
  if (!banded) status = buf;
  const out = { unpack: null, refs: {} };
  read(status, (p) => {
    const line = p.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('unpack ')) out.unpack = line.slice(7);
    else if (line.startsWith('ok ')) out.refs[line.slice(3)] = { ok: true };
    else if (line.startsWith('ng ')) {
      const sp = line.indexOf(' ', 3);
      out.refs[sp < 0 ? line.slice(3) : line.slice(3, sp)] = { ok: false, reason: sp < 0 ? '' : line.slice(sp + 1) };
    }
  });
  return out;
}

function runGit(args, env, { input, children, capture = 0 } = {}) {
  return new Promise((resolveP) => {
    const child = spawn('git', args, { env, stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    children.add(child);
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { if (out.length < capture) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 4096) err += d; });
    if (input) { child.stdin.on('error', () => {}); input.on('error', () => child.kill('SIGKILL')); input.pipe(child.stdin); }
    child.on('error', (e) => { children.delete(child); resolveP({ code: -1, out, err: e.message }); });
    child.on('close', (code) => { children.delete(child); resolveP({ code, out, err }); });
  });
}

async function refTips(slug, refs, children) {
  if (!refs.length) return {};
  const { args, env } = hardenedGitInvocation([`--git-dir=${repoPath(slug)}`, 'for-each-ref', '--format=%(objectname) %(refname)', ...refs]);
  const r = await runGit(args, env, { children, capture: 1024 * 1024 });
  const tips = {};
  for (const line of r.out.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp > 0) tips[line.slice(sp + 1)] = line.slice(0, sp);
  }
  return tips;
}

/**
 * The fast-forward check, against a quarantine copy of the pushed objects.
 * Returns { error } for a pack AppCrane cannot index, else { refused: Map }.
 */
async function quarantineAncestry(slug, file, packOffset, candidates, { maxPushBytes, children, dir }) {
  const repo = repoPath(slug);
  const objects = join(dir, 'objects');
  mkdirSync(join(objects, 'pack'), { recursive: true });
  const base = hardenedGitInvocation([]);
  const env = { ...base.env, GIT_OBJECT_DIRECTORY: objects, GIT_ALTERNATE_OBJECT_DIRECTORIES: join(repo, 'objects') };
  if (statSync(file).size > packOffset) {
    const idx = hardenedGitInvocation([`--git-dir=${repo}`, 'index-pack', '--stdin', '--fix-thin', '--strict', `--max-input-size=${Number(maxPushBytes)}`]);
    const r = await runGit(idx.args, env, { input: createReadStream(file, { start: packOffset }), children });
    if (r.code !== 0) return { error: `pack rejected: ${r.err.trim().split('\n').pop() || `index-pack exited ${r.code}`}` };
  }
  const refused = new Map();
  for (const cmd of candidates) {
    const mb = hardenedGitInvocation([`--git-dir=${repo}`, 'merge-base', '--is-ancestor', cmd.old, cmd.new]);
    const r = await runGit(mb.args, env, { children });
    if (r.code === 1) refused.set(cmd.ref, NON_FF);
    else if (r.code !== 0) refused.set(cmd.ref, 'AppCrane could not verify this update is a fast-forward');
  }
  return { refused };
}

/**
 * GET info/refs?service=git-receive-pack (advertise) or POST git-receive-pack.
 * onDone(outcome) is called exactly once for a POST that got past the first
 * checks: { status: 'updated'|'refused'|'aborted', reason?, bytes, refs: [{ ref,
 * old, new, updated, reason? }] }.
 */
export function serveReceivePack(req, res, { slug, userId, advertise, limits = GIT_HTTP_LIMITS, onDone = () => {} }) {
  const maxPushBytes = limits.maxPushBytes ?? GIT_HTTP_LIMITS.maxPushBytes;
  if (advertise) {
    if (activeReceive >= limits.maxConcurrent) return plain(res, 503, 'Too many git transfers in progress; try again shortly', { 'Retry-After': '10' });
    const { args, env } = receivePackArgs(slug, { userId, advertiseRefs: true, maxPushBytes });
    const child = spawn('git', args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    activeReceive++;
    let done = false;
    const settle = () => { if (!done) { done = true; activeReceive--; clearTimeout(timer); } };
    const timer = setTimeout(() => { child.kill('SIGKILL'); res.destroy(); }, limits.timeoutMs);
    res.on('close', () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
    const chunks = [];
    let stderr = '';
    child.stdout.on('data', (d) => chunks.push(d));
    child.stderr.on('data', (d) => { if (stderr.length < 4096) stderr += d; });
    child.on('error', (err) => { settle(); log.warn(`git receive-pack for ${slug} could not start: ${err.message}`); plain(res, 500, 'git receive-pack failed'); });
    child.on('close', (code) => {
      settle();
      if (res.writableEnded || res.destroyed) return;
      if (code !== 0) { log.warn(`git receive-pack --advertise-refs for ${slug} exited ${code}: ${stderr.trim().slice(0, 500)}`); return plain(res, 500, 'git receive-pack failed'); }
      res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-advertisement', 'Cache-Control': 'no-cache', Expires: 'Fri, 01 Jan 1980 00:00:00 GMT', Pragma: 'no-cache' });
      res.write(`${pktLine('# service=git-receive-pack\n')}0000`);
      res.end(Buffer.concat(chunks));
    });
    return;
  }

  const enc = String(req.headers['content-encoding'] || 'identity').toLowerCase();
  let src;
  if (enc === 'gzip' || enc === 'x-gzip') src = req.pipe(createGunzip());
  else if (enc === 'identity') src = req;
  else return plain(res, 415, `Unsupported Content-Encoding: ${enc}`);
  const tooLarge = `Push refused: the pack is larger than AppCrane's ${Math.floor(maxPushBytes / (1024 * 1024))} MiB push limit`;
  if (Number(req.headers['content-length']) > maxPushBytes) {
    onDone({ status: 'refused', reason: 'too large', bytes: Number(req.headers['content-length']), refs: [] });
    return plain(res, 413, tooLarge);
  }
  if (activeReceive >= limits.maxConcurrent) return plain(res, 503, 'Too many git transfers in progress; try again shortly', { 'Retry-After': '10' });

  activeReceive++;
  const children = new Set();
  const dir = mkdtempSync(join(tmpdir(), 'appcrane-receive-'));
  const file = join(dir, 'request');
  const ws = createWriteStream(file);
  let head = Buffer.alloc(0);
  let over = false;
  let parsed = null;
  let bytes = 0;
  let finished = false;
  let receiving = false;
  const killAll = () => { for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill('SIGTERM'); };
  const report = (outcome) => {
    if (finished) return;
    finished = true;
    activeReceive--;
    clearTimeout(timer);
    killAll();
    ws.destroy();
    rmSync(dir, { recursive: true, force: true });
    try { onDone({ bytes, ...outcome }); } catch (e) { log.warn(`git push outcome for ${slug} not recorded: ${e.message}`); }
  };
  ws.on('error', (e) => {
    if (finished || over) return;
    log.warn(`git push spool for ${slug} failed: ${e.message}`);
    plain(res, 500, 'git receive-pack failed');
    report({ status: 'refused', reason: 'spool write failed', refs: [] });
  });
  const refsOf = (results) => results.map((r) => ({ ref: r.ref, old: r.old.slice(0, 12), new: r.new.slice(0, 12), updated: !!r.updated, ...(r.error ? { reason: r.error } : {}) }));
  const timer = setTimeout(() => { report({ status: 'aborted', reason: 'timeout', refs: parsed ? refsOf(parsed.commands) : [] }); res.destroy(); }, limits.timeoutMs);
  // Once receive-pack has its input (the spooled file, not the client) it is
  // left to finish: a ref update cut off mid-way is worse than one completed
  // for a client that went away, and its outcome is still audited.
  res.on('close', () => { if (!finished && !receiving) report({ status: 'aborted', reason: 'client disconnected', refs: parsed ? refsOf(parsed.commands) : [] }); });

  const refuseAll = (results, opts) => {
    if (!parsed.caps.has('report-status') && !parsed.caps.has('report-status-v2')) {
      plain(res, 403, results.filter((r) => r.error && r.error !== NOT_APPLIED).map((r) => `${r.ref}: ${r.error}`).join('\n'));
    } else {
      res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-result', 'Cache-Control': 'no-cache' });
      res.end(pushStatus(parsed.caps, results, opts));
    }
    report({ status: 'refused', reason: opts?.reason || 'policy', refs: refsOf(results) });
  };

  const proceed = async () => {
    try {
      if (!parsed) parsed = parsePushCommands(head);
    } catch (e) {
      parsed = null;
      plain(res, 400, `Malformed push: ${e.message}`);
      return report({ status: 'refused', reason: `malformed: ${e.message}`, refs: [] });
    }
    if (!parsed) {
      plain(res, 400, 'Malformed push: the ref update list is incomplete or too long');
      return report({ status: 'refused', reason: 'malformed: incomplete command list', refs: [] });
    }
    const { commands } = parsed;
    let results = commands.map((c) => ({ ...c, error: pushCommandRefusal(c, userId) }));
    const message = 'AppCrane: push refused. Deletions, tag moves and non-fast-forward updates are not accepted.';
    if (results.some((r) => r.error)) {
      return refuseAll(results.map((r) => ({ ...r, error: r.error || NOT_APPLIED })), { message });
    }
    const candidates = commands.filter((c) => c.old !== ZERO_SHA && c.ref.startsWith('refs/heads/'));
    if (candidates.length) {
      const q = await quarantineAncestry(slug, file, parsed.packOffset, candidates, { maxPushBytes, children, dir: join(dir, 'q') });
      if (finished) return;
      if (q.error) return refuseAll(results.map((r) => ({ ...r, error: 'unpacker error' })), { unpack: q.error.replace(/\n/g, ' '), message: `AppCrane: ${q.error}`, reason: q.error });
      results = results.map((r) => ({ ...r, error: q.refused.get(r.ref) || null }));
      if (results.some((r) => r.error)) {
        return refuseAll(results.map((r) => ({ ...r, error: r.error || NOT_APPLIED })), { message });
      }
    }

    const { args, env } = receivePackArgs(slug, { userId, advertiseRefs: false, maxPushBytes });
    const child = spawn('git', args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    children.add(child);
    receiving = true;
    res.on('close', () => child.stdout.resume());
    let stdout = Buffer.alloc(0);
    let stderr = '';
    child.stdin.on('error', () => {});
    child.stderr.on('data', (d) => { if (stderr.length < 4096) stderr += d; });
    child.stdout.on('data', (chunk) => {
      if (stdout.length < 256 * 1024) stdout = Buffer.concat([stdout, chunk]);
      if (res.destroyed || res.writableEnded) return;
      if (!res.headersSent) res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-result', 'Cache-Control': 'no-cache', Expires: 'Fri, 01 Jan 1980 00:00:00 GMT', Pragma: 'no-cache' });
      if (!res.write(chunk)) { child.stdout.pause(); res.once('drain', () => child.stdout.resume()); }
    });
    const input = createReadStream(file);
    input.on('error', () => child.kill('SIGKILL'));
    input.pipe(child.stdin);
    child.on('error', (err) => {
      log.warn(`git receive-pack for ${slug} could not start: ${err.message}`);
      plain(res, 500, 'git receive-pack failed');
      report({ status: 'refused', reason: 'receive-pack failed to start', refs: refsOf(results) });
    });
    child.on('close', async (code, signal) => {
      children.delete(child);
      if (finished) return;
      if (code !== 0) log.warn(`git receive-pack for ${slug} exited ${code ?? signal}: ${stderr.trim().slice(0, 500)}`);
      // Recorded before the response ends, so the audit row exists by the time
      // the client sees its push complete.
      const status = parseReportStatus(stdout);
      let tips = {};
      try { tips = await refTips(slug, commands.map((c) => c.ref), children); } catch (_) { tips = {}; }
      if (finished) return;
      const final = results.map((r) => ({
        ...r,
        updated: tips[r.ref] === r.new,
        error: tips[r.ref] === r.new ? null : (status.refs[r.ref]?.reason || (status.unpack && status.unpack !== 'ok' ? `unpack ${status.unpack}` : 'not updated')),
      }));
      if (!commands.length) report({ status: 'empty', refs: [] });
      else report({ status: final.some((r) => r.updated) ? 'updated' : 'refused', reason: final.some((r) => r.updated) ? undefined : 'git', refs: refsOf(final), updated: final.filter((r) => r.updated).map((r) => ({ ref: r.ref, sha: r.new })) });
      if (res.destroyed || res.writableEnded) return;
      if (res.headersSent) return res.end();
      if (code === 0) { res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-result', 'Cache-Control': 'no-cache' }); return res.end(); }
      plain(res, 500, 'git receive-pack failed');
    });
  };

  // Over the cap the rest of the body is read and discarded (never stored), so
  // git is still listening when the refusal arrives and prints it per ref; the
  // timeout bounds how long that can take.
  const refuseTooLarge = () => {
    let p = null;
    try { p = parsePushCommands(head); } catch (_) { p = null; }
    if (!p || !p.commands.length || (!p.caps.has('report-status') && !p.caps.has('report-status-v2'))) {
      plain(res, 413, tooLarge);
      return report({ status: 'refused', reason: 'too large', refs: p ? refsOf(p.commands) : [] });
    }
    parsed = p;
    const msg = tooLarge.replace(/^Push refused: /, '');
    refuseAll(p.commands.map((c) => ({ ...c, error: msg })), { unpack: msg, message: `AppCrane: ${tooLarge}`, reason: 'too large' });
  };
  src.on('data', (chunk) => {
    if (finished) return;
    bytes += chunk.length;
    if (over) return;
    if (head.length < PUSH_HEAD_MAX) head = Buffer.concat([head, chunk.subarray(0, PUSH_HEAD_MAX - head.length)]);
    if (bytes > maxPushBytes) {
      over = true;
      ws.destroy();
      rmSync(file, { force: true });
      return;
    }
    if (!ws.write(chunk)) { src.pause(); ws.once('drain', () => src.resume()); }
  });
  src.on('end', () => {
    if (finished) return;
    if (over) return refuseTooLarge();
    ws.end(() => { if (!finished) proceed(); });
  });
  src.on('error', () => {
    if (finished) return;
    plain(res, 400, 'Malformed request body');
    report({ status: 'refused', reason: 'malformed body', refs: [] });
  });
}
