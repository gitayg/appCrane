/**
 * Read-only git smart-HTTP for Crane-hosted apps: `git upload-pack` run by
 * AppCrane against the bare repo it owns, streamed to the client.
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
import { hardenedGitInvocation, repoPath } from './localGit.js';
import log from '../utils/logger.js';

export const GIT_HTTP_LIMITS = Object.freeze({
  maxBodyBytes: 32 * 1024 * 1024,
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
