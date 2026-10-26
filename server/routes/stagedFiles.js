// Chunked, resumable staged uploads. POST /api/files/staged (routes/files.js)
// takes a whole file in one multipart request; this takes it in pieces:
//
//   POST /api/files/staged/chunked          { slug, filename }   -> { handle, max_bytes, expires_at }
//   PUT  /api/files/staged/:handle?offset=N  raw bytes            -> { received_bytes }
//   POST /api/files/staged/:handle/finalize  { sha256 }           -> { token, sha256, size_bytes, expires_at }
//
// Finalize checks the caller's SHA-256 against the bytes on disk and only then
// writes a staged_files row (token = handle), so the existing consumers take it
// unchanged: appcrane_push_staged_file (docker cp into a container),
// appcrane_push_to_managed_app { staged_token } (commit into a Crane-hosted
// repo) and appcrane_deploy_artifact.
//
// Until finalize the upload lives only on disk: DATA_DIR/staged/<handle>/ holds
// upload.json (owner, app, expiry) and the bytes. sweepChunkedUploads removes
// expired ones; after finalize sweepStagedFiles owns the directory.

import { Router } from 'express';
import express from 'express';
import crypto from 'crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, truncateSync, writeFileSync, chmodSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { resolveMcpApp, assertWriteCaller } from '../services/mcpGaps/access.js';
import log from '../utils/logger.js';

const HANDLE_RE = /^[A-Za-z0-9_-]{22}$/;
const META = 'upload.json';

export function stagedMaxBytes() {
  return parseInt(process.env.STAGED_MAX_BYTES || String(200 * 1024 * 1024), 10);
}
function ttlMs() {
  return parseInt(process.env.STAGED_TTL_MIN || '10', 10) * 60 * 1000;
}
function stagedRoot() {
  return join(resolve(process.env.DATA_DIR || './data'), 'staged');
}
function sqlTime(ms) {
  return new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
}
function sanitizeFilename(name) {
  const s = String(name || 'file').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 200);
  return s && s !== '.' && s !== '..' ? s : 'file';
}
function fail(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}
function callerOf(req) {
  return req.user_mcp_key ? { ...req.user, _mcpUserKey: req.user_mcp_key } : req.user;
}

function readMeta(handle) {
  if (!HANDLE_RE.test(handle)) return null;
  const dir = join(stagedRoot(), handle);
  try {
    const meta = JSON.parse(readFileSync(join(dir, META), 'utf8'));
    return { ...meta, dir, file: join(dir, meta.filename) };
  } catch (_) {
    return null;
  }
}

// One handle per user: anyone else, an unknown handle, an expired one or a
// finalized one all answer 404, so a handle cannot be probed.
function ownedUpload(req, res) {
  const meta = readMeta(req.params.handle);
  if (!meta || meta.user_id !== req.user.id || meta.expires_ms <= Date.now()) {
    fail(res, 404, 'NOT_FOUND', 'staged upload not found (unknown, expired, finalized, or not yours)');
    return null;
  }
  return meta;
}

const inFlight = new Set();
const router = Router();
router.use(requireAuth);
const smallJson = express.json({ limit: '16kb' });

router.post('/chunked', smallJson, (req, res) => {
  const caller = callerOf(req);
  try { assertWriteCaller(caller, 'stage uploads'); } catch (e) { return fail(res, 403, 'FORBIDDEN', e.message); }
  const { slug, filename } = req.body || {};
  let app;
  try { app = resolveMcpApp(caller, slug); } catch (e) {
    return fail(res, /not found|required/.test(e.message) ? 404 : 403, 'FORBIDDEN', e.message);
  }
  const name = sanitizeFilename(filename);
  if (/^\.env/i.test(name)) return fail(res, 400, 'ENV_FILE_REFUSED', '.env files are not staged; set env vars with appcrane_set_env or the env-files tools.');

  const handle = crypto.randomBytes(16).toString('base64url');
  const root = stagedRoot();
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const dir = join(root, handle);
  mkdirSync(dir, { mode: 0o700 });
  const expires = Date.now() + ttlMs();
  writeFileSync(join(dir, name), '', { mode: 0o600 });
  writeFileSync(join(dir, META), JSON.stringify({ user_id: req.user.id, app_id: app.id, slug: app.slug, filename: name, expires_ms: expires }), { mode: 0o600 });
  logAudit(req.user.id, app.id, 'file-stage-chunked-start', { filename: name });
  res.status(201).json({
    handle, filename: name, max_bytes: stagedMaxBytes(), expires_at: sqlTime(expires),
    upload: `PUT /api/files/staged/${handle}?offset=<bytes already sent> with Content-Type: application/octet-stream`,
    finalize: `POST /api/files/staged/${handle}/finalize with {"sha256":"<hex>"}`,
  });
});

router.put('/:handle', (req, res) => {
  const meta = ownedUpload(req, res);
  if (!meta) return;
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/octet-stream')) {
    return fail(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'send the chunk as Content-Type: application/octet-stream');
  }
  const offset = Number(req.query.offset);
  if (!Number.isInteger(offset) || offset < 0) return fail(res, 400, 'BAD_OFFSET', 'offset must be a non-negative integer');
  if (inFlight.has(req.params.handle)) return fail(res, 409, 'UPLOAD_BUSY', 'another chunk for this handle is still being written');
  const have = statSync(meta.file).size;
  if (offset !== have) {
    return res.status(409).json({ error: { code: 'OFFSET_MISMATCH', message: `offset ${offset} does not match the ${have} bytes received so far; resend from ${have}` }, received_bytes: have });
  }
  const max = stagedMaxBytes();
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && have + declared > max) {
    return fail(res, 413, 'TOO_LARGE', `upload would exceed the ${max}-byte limit`);
  }

  inFlight.add(req.params.handle);
  const out = createWriteStream(meta.file, { flags: 'a' });
  let total = have;
  let done = false;
  const finish = (status, body) => {
    if (done) return;
    done = true;
    inFlight.delete(req.params.handle);
    if (status !== 200) { try { truncateSync(meta.file, have); } catch (_) {} }
    if (!res.headersSent) res.status(status).json(body);
  };
  let refusal = null;
  req.on('data', (chunk) => {
    if (refusal) return;
    total += chunk.length;
    if (total > max) {
      refusal = [413, { error: { code: 'TOO_LARGE', message: `upload exceeds the ${max}-byte limit` } }];
      out.end();
      return;
    }
    if (!out.write(chunk)) {
      req.pause();
      out.once('drain', () => req.resume());
    }
  });
  req.on('end', () => { if (!refusal) out.end(); });
  req.on('aborted', () => {
    refusal = refusal || [400, { error: { code: 'ABORTED', message: 'chunk upload aborted' } }];
    out.end();
  });
  out.on('error', (e) => finish(500, { error: { code: 'WRITE_FAILED', message: e.message } }));
  out.on('finish', () => (refusal ? finish(...refusal) : finish(200, { handle: req.params.handle, received_bytes: total })));
});

router.post('/:handle/finalize', smallJson, async (req, res) => {
  const meta = ownedUpload(req, res);
  if (!meta) return;
  if (inFlight.has(req.params.handle)) return fail(res, 409, 'UPLOAD_BUSY', 'a chunk is still being written');
  const want = String((req.body || {}).sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(want)) return fail(res, 400, 'SHA256_REQUIRED', 'pass the SHA-256 (hex) of the whole file you sent');
  const size = statSync(meta.file).size;
  if (size === 0) return fail(res, 400, 'EMPTY', 'nothing was uploaded');
  const got = await new Promise((ok, ko) => {
    const h = crypto.createHash('sha256');
    createReadStream(meta.file).on('data', (c) => h.update(c)).on('end', () => ok(h.digest('hex'))).on('error', ko);
  });
  if (got !== want) {
    return res.status(422).json({ error: { code: 'SHA256_MISMATCH', message: `the ${size} bytes received hash to ${got}, not ${want}; nothing was staged` }, received_bytes: size });
  }
  const expiresAt = sqlTime(Date.now() + ttlMs());
  getDb().prepare(`
    INSERT INTO staged_files (token, user_id, filename, size_bytes, sha256, scratch_path, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(req.params.handle, req.user.id, meta.filename, size, got, meta.file, expiresAt);
  rmSync(join(meta.dir, META), { force: true });
  logAudit(req.user.id, meta.app_id, 'file-stage', { filename: meta.filename, bytes: size, sha256: got, chunked: true });
  res.json({ token: req.params.handle, filename: meta.filename, size_bytes: size, sha256: got, expires_at: expiresAt });
});

export function sweepChunkedUploads(now = Date.now()) {
  const root = stagedRoot();
  if (!existsSync(root)) return 0;
  let removed = 0;
  for (const name of readdirSync(root)) {
    if (!HANDLE_RE.test(name) || inFlight.has(name)) continue;
    const metaPath = join(root, name, META);
    if (!existsSync(metaPath)) continue;
    let expired = true;
    try { expired = JSON.parse(readFileSync(metaPath, 'utf8')).expires_ms <= now; } catch (_) {}
    if (!expired) continue;
    try { rmSync(join(root, name), { recursive: true, force: true }); removed++; } catch (e) { log.warn(`staged chunk sweep: ${e.message}`); }
  }
  if (removed > 0) log.info(`staged chunk sweep: reaped ${removed} expired upload(s)`);
  return removed;
}

export default router;
