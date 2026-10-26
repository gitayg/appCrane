/**
 * Off-site backup SETS in the bucket: naming, listing, retention, fetch with
 * verification, and restore through the existing importers.
 *
 * One run uploads one set under the configured prefix:
 *   appcrane-backup-<host>-<stamp>/data.tar.gz[.enc]           data archive
 *   appcrane-backup-<host>-<stamp>/repos/appcrane-repo-….tar[.enc]  one per repo
 *   appcrane-backup-<host>-<stamp>/manifest.json               written LAST
 * A set without manifest.json is incomplete (the upload died part-way).
 * Until v2.113 a run uploaded one object, appcrane-backup-<host>-<stamp>.tar.gz;
 * those are listed as "legacy" sets, downloadable but unverified.
 *
 * Object names are NOT trusted: anyone with write access to the bucket can
 * create them. A set is genuine only when its manifest carries a valid HMAC
 * (backupCrypto.signManifest) and names this very set; only genuine sets are
 * restorable, count toward retention, or are ever deleted by it, and their age
 * is the signed created_at, never the timestamp in the name.
 *
 * Every function takes `conn` (s3.js) and the normalized prefix; nothing here
 * reads settings, so tests drive it against a fake bucket directly.
 */
import { join, basename } from 'path';
import { rename, rm, mkdir } from 'fs/promises';
import { s3ListObjects, s3DeleteObjects, s3GetObject, s3GetObjectToFile } from './s3.js';
import { planRetention } from './backupRetention.js';
import { decryptFile, ENC_SUFFIX, manifestMacKey, manifestSignatureValid } from './backupCrypto.js';
import { newWorkDir, readHead } from './backupFiles.js';

export const MANIFEST_NAME = 'manifest.json';
export const MANIFEST_KIND = 'appcrane-s3-backup';
const STAMP = '(\\d{4}-\\d{2}-\\d{2})T(\\d{2})-(\\d{2})-(\\d{2})-(\\d{3})Z';
const SET_OBJ_RE = new RegExp(`^(appcrane-backup-([a-z0-9.-]+)-${STAMP})/(.+)$`, 'i');
const LEGACY_RE = new RegExp(`^(appcrane-backup-([a-z0-9.-]+)-${STAMP})\\.tar\\.gz$`, 'i');
export const SET_ID_RE = new RegExp(`^appcrane-backup-[a-z0-9.-]+-${STAMP}$`, 'i');
const ARTIFACT_RE = /^(data\.tar\.gz|repos\/appcrane-repo-[a-z0-9][a-z0-9-]{0,99}-[0-9a-f]{12}-\d{4}-\d{2}-\d{2}\.tar)(\.enc)?$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;
const HOST_RE = /^[a-z0-9.-]+$/i;
const VERIFY_CONCURRENCY = 8;

export function hostLabel() {
  return (process.env.CRANE_DOMAIN || 'appcrane').replace(/[^a-z0-9.-]/gi, '') || 'appcrane';
}

export function normalizePrefix(p) {
  const s = String(p || '').replace(/^\/+|\/+$/g, '');
  return s ? `${s}/` : '';
}

export function setIdFor(at, host = hostLabel()) {
  return `appcrane-backup-${host}-${at.toISOString().replace(/[:.]/g, '-')}`;
}

const atOf = (m) => `${m[3]}T${m[4]}:${m[5]}:${m[6]}.${m[7]}Z`;

/** Group a prefix listing into backup sets. `others` counts objects that are not AppCrane's. */
export function groupSets(objects, prefix) {
  const sets = new Map();
  let others = 0;
  for (const o of objects) {
    if (!o.key.startsWith(prefix)) { others++; continue; }
    const rel = o.key.slice(prefix.length);
    let m = SET_OBJ_RE.exec(rel);
    if (m) {
      const id = m[1];
      if (!sets.has(id)) sets.set(id, { id, host: m[2], at: atOf(m), legacy: false, complete: false, objects: [], bytes: 0 });
      const s = sets.get(id);
      s.objects.push({ key: o.key, rel: m[8], size: o.size });
      s.bytes += o.size;
      if (m[8] === MANIFEST_NAME) s.complete = true;
      continue;
    }
    m = LEGACY_RE.exec(rel);
    if (m) {
      sets.set(`${m[1]}.tar.gz`, { id: m[1], host: m[2], at: atOf(m), legacy: true, complete: true, objects: [{ key: o.key, rel: basename(o.key), size: o.size }], bytes: o.size });
      continue;
    }
    others++;
  }
  const list = [...sets.values()].sort((a, b) => (a.at < b.at ? 1 : -1));
  return { sets: list, others };
}

export async function listSets(conn, prefix) {
  const { objects, truncated } = await s3ListObjects(conn, prefix);
  return { ...groupSets(objects, prefix), truncated };
}

const refused = (reason, extra = {}) => ({ applied: false, refused: reason, kept: [], removed_sets: [], deleted_objects: 0, errors: [], ...extra });

/**
 * Read and authenticate every complete, non-legacy set's manifest. Each set
 * gains `verified`, and when verified `signed_at` / `signed_host` (from the
 * signed manifest); otherwise `verify_error`. Never throws for one bad set.
 */
export async function verifySets(conn, prefix, sets, key = manifestMacKey()) {
  const todo = sets.filter((s) => !s.legacy && s.complete);
  for (const s of sets) {
    if (s.legacy) Object.assign(s, { verified: false, verify_error: 'legacy single-object backup, no manifest' });
    else if (!s.complete) Object.assign(s, { verified: false, verify_error: 'incomplete: no manifest' });
  }
  for (let i = 0; i < todo.length; i += VERIFY_CONCURRENCY) {
    await Promise.all(todo.slice(i, i + VERIFY_CONCURRENCY).map(async (s) => {
      try {
        const m = await readManifest(conn, prefix, s.id, { key });
        Object.assign(s, { verified: true, signed_at: m.created_at, signed_host: m.host, verify_error: null });
      } catch (e) {
        Object.assign(s, { verified: false, verify_error: e.message });
      }
    }));
  }
  return sets;
}

/**
 * Apply retention to THIS host's sets under the prefix. Refuses — deletes
 * nothing — when the listing cannot be trusted: truncated, no own sets at
 * all, or not showing the set that was just uploaded.
 */
export async function applyRetention(conn, prefix, policy, { host = hostLabel(), justUploaded = null, key = manifestMacKey() } = {}) {
  const { sets, others, truncated } = await listSets(conn, prefix);
  if (truncated) return refused('the bucket listing was truncated, so it cannot be trusted for deletion');
  const named = sets.filter((s) => s.host === host);
  if (!named.length) {
    return refused(`no AppCrane backups for this host were found under the prefix${others ? ` (it holds ${others} other object${others === 1 ? '' : 's'})` : ''}`);
  }
  await verifySets(conn, prefix, named, key);
  const own = named.filter((s) => s.verified && s.signed_host === host);
  const ignored = named.length - own.length;
  if (!own.length) return refused('no backup for this host has a valid signature, so none is counted or deleted', { unverified_ignored: ignored });
  if (justUploaded && !own.some((s) => s.id === justUploaded)) {
    return refused('the bucket listing does not show the backup that was just uploaded, with a valid signature', { unverified_ignored: ignored });
  }
  const plan = planRetention(own.map((s) => ({ id: s.id, at: s.signed_at, complete: true })), policy);
  const byId = new Map(own.map((s) => [s.id, s]));
  const keys = [];
  for (const id of plan.remove) {
    const s = byId.get(id);
    for (const o of s.objects) {
      if (!o.key.startsWith(prefix + s.id)) return refused(`refusing to delete ${o.key}: it is not under a set this host owns`);
      keys.push(o.key);
    }
  }
  const r = keys.length ? await s3DeleteObjects(conn, keys) : { deleted: [], errors: [] };
  return {
    applied: true, refused: null,
    kept: plan.keep, removed_sets: plan.remove, deleted_objects: r.deleted.length, errors: r.errors,
    unverified_ignored: ignored,
  };
}

const unverified = (msg) => Object.assign(new Error(msg), { status: 409, code: 'BACKUP_UNVERIFIED' });

function validateManifest(m, setId) {
  if (!m || typeof m !== 'object' || m.kind !== MANIFEST_KIND || m.format !== 1 || m.set !== setId || !Array.isArray(m.artifacts)) {
    throw unverified(`manifest for ${setId} is not an AppCrane backup manifest`);
  }
  const at = typeof m.created_at === 'string' ? new Date(m.created_at) : null;
  if (typeof m.host !== 'string' || !HOST_RE.test(m.host) || !at || Number.isNaN(at.getTime()) || at.toISOString() !== m.created_at
      || setIdFor(at, m.host) !== setId) {
    throw unverified(`manifest for ${setId}: its host and created_at do not name this set`);
  }
  const names = new Set();
  let data = 0;
  for (const a of m.artifacts) {
    const name = String(a?.name);
    if (!ARTIFACT_RE.test(name) || !SHA_RE.test(String(a.sha256)) || !Number.isInteger(a.bytes) || a.bytes < 0 || names.has(name)) {
      throw unverified(`manifest for ${setId} lists an artifact it should not: ${JSON.stringify(name).slice(0, 120)}`);
    }
    names.add(name);
    if (a.kind === 'data') {
      if (!/^data\.tar\.gz(\.enc)?$/.test(name) || a.slug != null) throw unverified(`manifest for ${setId}: ${name} is not a data archive`);
      data++;
    } else if (a.kind === 'repo') {
      if (typeof a.slug !== 'string' || !SLUG_RE.test(a.slug) || !name.startsWith(`repos/appcrane-repo-${a.slug}-`)) {
        throw unverified(`manifest for ${setId}: ${name} does not belong to repository ${JSON.stringify(String(a.slug)).slice(0, 60)}`);
      }
    } else {
      throw unverified(`manifest for ${setId}: ${name} has an unknown kind ${JSON.stringify(String(a.kind)).slice(0, 30)}`);
    }
    if (a.encrypted !== name.endsWith(ENC_SUFFIX)) throw unverified(`manifest for ${setId}: ${name} encryption flag does not match its name`);
    if (a.encrypted && !SHA_RE.test(String(a.plain_sha256))) throw unverified(`manifest for ${setId}: ${name} has no plaintext hash`);
  }
  if (data !== 1) throw unverified(`manifest for ${setId} must list exactly one data archive (it lists ${data})`);
  return m;
}

/**
 * The set's manifest, shape-checked and authenticated. Throws (status 409,
 * BACKUP_UNVERIFIED) unless the signature verifies under this host's
 * ENCRYPTION_KEY: an unsigned, forged or edited manifest is never used.
 */
export async function readManifest(conn, prefix, setId, { key = manifestMacKey() } = {}) {
  if (!SET_ID_RE.test(setId)) throw Object.assign(new Error('invalid backup id'), { status: 400 });
  const buf = await s3GetObject(conn, `${prefix}${setId}/${MANIFEST_NAME}`);
  let m;
  try { m = JSON.parse(buf.toString('utf8')); } catch (_) { throw unverified(`manifest for ${setId} is not valid JSON`); }
  if (!manifestSignatureValid(m, key)) {
    throw unverified(`manifest for ${setId} has no valid signature: it was not written by an AppCrane holding this ENCRYPTION_KEY, or it was changed`);
  }
  return validateManifest(m, setId);
}

/** The local file name an artifact is restored under (inside DATA_DIR/backups). */
export function localNameFor(setId, artifact) {
  const plain = artifact.name.endsWith(ENC_SUFFIX) ? artifact.name.slice(0, -ENC_SUFFIX.length) : artifact.name;
  return artifact.kind === 'data' ? `${setId}.tar.gz` : basename(plain);
}

/**
 * Download artifacts of one set into `dir`, each verified against the
 * manifest (size + SHA-256 of the stored object) and, when encrypted,
 * decrypted and checked again (GCM tag + plaintext SHA-256). A file only lands
 * in `dir` after every check passed.
 *
 * @param opts.only  artifact names to fetch (default: all)
 * @param opts.key   decryption key (backupCrypto.archiveKey()) — required for encrypted sets
 */
export async function fetchSet(conn, prefix, setId, dir, { only = null, key = null } = {}) {
  const manifest = await readManifest(conn, prefix, setId);
  const wanted = manifest.artifacts.filter((a) => !only || only.includes(a.name));
  if (only && wanted.length !== only.length) throw Object.assign(new Error('no such artifact in this backup'), { status: 404 });
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const work = await newWorkDir('s3-fetch');
  const files = [];
  try {
    for (const a of wanted) {
      const raw = join(work, 'object');
      const got = await s3GetObjectToFile(conn, `${prefix}${setId}/${a.name}`, raw);
      if (got.bytes !== a.bytes || got.sha256 !== a.sha256) {
        throw new Error(`${a.name} failed verification: expected ${a.bytes} bytes sha256 ${a.sha256.slice(0, 12)}…, got ${got.bytes} bytes sha256 ${got.sha256.slice(0, 12)}…`);
      }
      let src = raw;
      if (a.encrypted) {
        if (!key) throw new Error(`${a.name} is encrypted and no key was given`);
        const plain = join(work, 'plain');
        const p = await decryptFile(raw, plain, key);
        if (p.sha256 !== a.plain_sha256) throw new Error(`${a.name} decrypted, but its content does not match the manifest`);
        await rm(raw, { force: true });
        src = plain;
      }
      const name = localNameFor(setId, a);
      const dest = join(dir, name);
      await rename(src, dest);
      files.push({ kind: a.kind, slug: a.slug || null, name: a.name, local_file: name, path: dest, bytes: a.encrypted ? a.plain_bytes : a.bytes, verified: true });
    }
  } catch (e) {
    for (const f of files) await rm(f.path, { force: true });
    throw e;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
  return { set: setId, manifest, files };
}

/** A pre-manifest single-object backup: fetched, checked to be gzip, but NOT hash-verified. */
export async function fetchLegacy(conn, prefix, setId, dir) {
  if (!SET_ID_RE.test(setId)) throw Object.assign(new Error('invalid backup id'), { status: 400 });
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const dest = join(dir, `${setId}.tar.gz`);
  const got = await s3GetObjectToFile(conn, `${prefix}${setId}.tar.gz`, dest);
  const head = await readHead(dest, 2);
  if (head[0] !== 0x1f || head[1] !== 0x8b) {
    await rm(dest, { force: true });
    throw new Error(`${setId}.tar.gz is not a gzip archive`);
  }
  return { set: setId, manifest: null, files: [{ kind: 'data', slug: null, name: `${setId}.tar.gz`, local_file: basename(dest), path: dest, bytes: got.bytes, verified: false }] };
}
