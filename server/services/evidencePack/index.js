import { join, resolve, sep } from 'path';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile, rename } from 'fs/promises';
import { existsSync } from 'fs';
import { randomBytes } from 'crypto';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { dataDir, repoRoot, createTar, extractTar, walk, sha256File, privateFile } from '../backupFiles.js';
import { CONTROLS, FRAMEWORK, DISCLAIMER, controlsForFile } from './controls.js';
import * as C from './collect.js';
import { renderReadme, renderIndexHtml } from './render.js';
import { forbiddenValues, scanFiles } from './secretScan.js';
import { signManifest, sha256, verifyFiles, MANIFEST_FILE, SIG_FILE } from './sign.js';

// Compliance evidence packs: a tar.gz for a chosen period holding, per SOC 2
// criterion, how AppCrane implements it and the evidence files, plus a
// manifest of SHA-256 hashes signed with an HMAC (sign.js). Built in the
// background, one at a time, under DATA_DIR/evidence; every file is scanned
// for secrets before anything is written (secretScan.js).

export const MAX_PERIOD_DAYS = 400;
export const DEFAULT_PERIOD_DAYS = 90;
const DAY = 86_400_000;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export const evidenceRoot = () => resolve(join(dataDir(), 'evidence'));
export const packsDir = () => join(evidenceRoot(), 'packs');

const active = new Set();
let extraForbidden = [];
/** Tests: literal values that must also never appear in a pack. */
export function _setExtraForbiddenForTests(values) { extraForbidden = values || []; }

const fail = (msg, status = 400, code = 'VALIDATION') => Object.assign(new Error(msg), { status, code });

export function normalizePeriod({ from, to } = {}, now = Date.now()) {
  const today = new Date(now).toISOString().slice(0, 10);
  const t = to || today;
  const f = from || new Date(Date.parse(`${t}T00:00:00Z`) - (DEFAULT_PERIOD_DAYS - 1) * DAY).toISOString().slice(0, 10);
  for (const [k, v] of [['from', f], ['to', t]]) {
    if (!DATE_RE.test(v) || !Number.isFinite(Date.parse(`${v}T00:00:00Z`)) || new Date(`${v}T00:00:00Z`).toISOString().slice(0, 10) !== v) {
      throw fail(`${k} must be a date as YYYY-MM-DD`);
    }
  }
  if (f > t) throw fail('from must not be after to');
  if (t > today) throw fail('to must not be in the future');
  const span = (Date.parse(`${t}T00:00:00Z`) - Date.parse(`${f}T00:00:00Z`)) / DAY + 1;
  if (span > MAX_PERIOD_DAYS) throw fail(`the period may be at most ${MAX_PERIOD_DAYS} days`);
  return { from: f, to: t };
}

const view = (r) => r && ({
  id: r.token, status: r.status, progress: r.progress, step: r.step,
  period: { from: r.period_from, to: r.period_to }, file_name: r.file_name, bytes: r.bytes, sha256: r.sha256,
  manifest_sha256: r.manifest_sha256, degraded: r.degraded_json ? JSON.parse(r.degraded_json) : [], error: r.error,
  requested_by: r.requested_by, created_at: r.created_at, finished_at: r.finished_at,
});

function closeInterrupted(db) {
  for (const r of db.prepare("SELECT token FROM evidence_packs WHERE status = 'running'").all()) {
    if (!active.has(r.token)) {
      db.prepare("UPDATE evidence_packs SET status = 'failed', error = 'Interrupted (the server stopped while building)', finished_at = datetime('now') WHERE token = ?").run(r.token);
    }
  }
}

export function listPacks(limit = 50) {
  const db = getDb();
  closeInterrupted(db);
  return db.prepare('SELECT * FROM evidence_packs ORDER BY id DESC LIMIT ?').all(Math.min(200, Math.max(1, limit))).map(view);
}

export function getPack(token) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(token)) return null;
  const db = getDb();
  closeInterrupted(db);
  return view(db.prepare('SELECT * FROM evidence_packs WHERE token = ?').get(token));
}

/** Absolute path of a ready pack's archive, confined to the packs directory. */
export function packFilePath(token) {
  const p = getPack(token);
  if (!p || p.status !== 'ready' || !p.file_name) return null;
  const root = resolve(packsDir());
  const abs = resolve(join(root, p.file_name));
  if (!abs.startsWith(root + sep) || !existsSync(abs)) return null;
  return abs;
}

function progress(db, token, pct, step) {
  db.prepare('UPDATE evidence_packs SET progress = ?, step = ? WHERE token = ?').run(pct, step, token);
}

/**
 * Start building a pack. Returns the new row at once; the build runs in the
 * background. Throws 409 while another pack is building.
 */
export function startEvidencePack({ from, to, user }) {
  const period = normalizePeriod({ from, to });
  if (active.size) throw fail('An evidence pack is already being built', 409, 'ALREADY_RUNNING');
  const db = getDb();
  const token = randomBytes(16).toString('base64url');
  db.prepare(`INSERT INTO evidence_packs (token, status, progress, step, period_from, period_to, requested_by)
              VALUES (?, 'running', 0, 'queued', ?, ?, ?)`).run(token, period.from, period.to, user?.id ?? null);
  active.add(token);
  const done = buildPack(token, period, user)
    .catch((e) => {
      log.warn(`[evidence-pack] ${token} failed: ${e.message}`);
      db.prepare("UPDATE evidence_packs SET status = 'failed', error = ?, finished_at = datetime('now') WHERE token = ?").run(String(e.message).slice(0, 500), token);
    })
    .finally(() => active.delete(token));
  return { pack: getPack(token), done };
}

async function buildPack(token, period, user) {
  const db = getDb();
  const now = Date.now();
  const files = {};
  const degraded = [];
  const notes = [];
  const put = (path, content) => { files[path] = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8'); };
  const steps = [
    ['CC6 logical access', async () => {
      put('CC6/users-and-roles.csv', C.usersAndRoles(db));
      put('CC6/app-role-assignments.csv', C.appRoleAssignments(db));
      put('CC6/authentication-settings.json', C.authenticationSettings(db));
      put('CC6/api-key-policy.json', C.apiKeyPolicy(db));
      put('CC6/api-key-ages.csv', C.apiKeyAges(db, now));
      put('CC6/access-reviews.json', await C.accessReviews(period, degraded));
    }],
    ['CC7 operations and monitoring', async () => {
      put('CC7/audit-log.csv', C.auditLog(db, period, notes).csv);
      put('CC7/audit-chain-verification.json', await C.auditChain(db, period, degraded));
      put('CC7/events-summary.json', C.eventsSummary(db, period));
      put('CC7/critical-events.csv', C.criticalEvents(db, period));
      put('CC7/siem-sinks.json', await C.siemSinks(db, degraded));
      put('CC7/job-health.json', await C.jobHealthEvidence(db));
      put('CC7/dependency-scans.csv', C.dependencyScans(db, period));
    }],
    ['CC8 change management', async () => {
      put('CC8/deployments.csv', C.deployments(db, period));
      put('CC8/release-checks.json', await C.releaseChecks(db, period, degraded));
    }],
    ['A1 availability', async () => {
      put('A1/backup-configuration.json', await C.backupConfiguration());
      put('A1/backup-history.json', await C.backupHistory(db, period));
      put('A1/restore-drills.csv', C.restoreDrills(period));
    }],
    ['C1 confidentiality', async () => {
      put('C1/encryption.json', await C.encryption(db));
    }],
  ];
  for (let i = 0; i < steps.length; i++) {
    progress(db, token, Math.round((i / (steps.length + 2)) * 100), steps[i][0]);
    await steps[i][1]();
  }
  for (const c of CONTROLS) for (const f of c.evidence) if (!files[f]) throw new Error(`evidence file ${f} was not produced`);

  const generatedBy = { id: user?.id ?? null, username: user?.username || user?.name || null };
  const ctx = { period, packId: token, generatedAt: new Date(now).toISOString(), generatedBy, version: C.appVersion(repoRoot), degraded, notes };
  put('README.md', renderReadme(ctx));
  put('index.html', renderIndexHtml(ctx));

  progress(db, token, Math.round((steps.length / (steps.length + 2)) * 100), 'secret scan');
  const hits = scanFiles(files, forbiddenValues(db, extraForbidden));
  if (hits.length) {
    throw new Error(`Refused: the secret scan found ${hits.length} hit(s) (${[...new Set(hits.map((h) => `${h.file}: ${h.kind}`))].slice(0, 5).join('; ')}). No pack was written.`);
  }

  const manifest = {
    kind: 'appcrane-evidence-pack', format: 1, pack_id: token, framework: FRAMEWORK, disclaimer: DISCLAIMER,
    generated_at: ctx.generatedAt, generated_by: generatedBy, period, appcrane_version: ctx.version,
    controls: CONTROLS.map((c) => ({ id: c.id, family: c.family, title: c.title, evidence: c.evidence })),
    files: Object.keys(files).sort().map((p) => ({ path: p, bytes: files[p].length, sha256: sha256(files[p]), controls: controlsForFile(p) })),
    degraded, notes,
    signature: { file: SIG_FILE, algorithm: 'HMAC-SHA256', key: 'derived from the instance ENCRYPTION_KEY (label appcrane-evidence-pack-manifest-v1)' },
  };
  const mBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  files[MANIFEST_FILE] = mBytes;
  files[SIG_FILE] = Buffer.from(signManifest(mBytes) + '\n', 'utf8');

  progress(db, token, Math.round(((steps.length + 1) / (steps.length + 2)) * 100), 'writing archive');
  await mkdir(packsDir(), { recursive: true, mode: 0o700 });
  const work = await mkdtemp(join(evidenceRoot(), '.build-'));
  try {
    for (const [p, buf] of Object.entries(files)) {
      const dest = join(work, p);
      await mkdir(join(dest, '..'), { recursive: true, mode: 0o700 });
      await writeFile(dest, buf, { mode: 0o600 });
    }
    const name = `appcrane-evidence-${period.from}-to-${period.to}-${token.slice(0, 8)}.tar.gz`;
    const dest = join(packsDir(), name);
    const partial = `${dest}.partial`;
    const top = [...new Set(Object.keys(files).map((p) => p.split('/')[0]))].sort();
    await createTar(partial, [{ cwd: work, paths: top }], { gzip: true });
    await privateFile(partial);
    await rename(partial, dest);
    const bytes = (await stat(dest)).size;
    db.prepare(`UPDATE evidence_packs SET status = 'ready', progress = 100, step = 'ready', file_name = ?, bytes = ?, sha256 = ?,
                manifest_sha256 = ?, degraded_json = ?, finished_at = datetime('now') WHERE token = ?`)
      .run(name, bytes, await sha256File(dest), sha256(mBytes), JSON.stringify(degraded), token);
    log.info(`[evidence-pack] ${token} ready: ${name} (${bytes} bytes, ${manifest.files.length} files, ${degraded.length} degraded)`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/** Read every regular file of an extracted pack into { relPath: Buffer }; symlinks and others are listed as unexpected. */
async function readTree(dir) {
  const out = {};
  const odd = [];
  for await (const e of walk(dir)) {
    if (e.type === 'file') out[e.rel] = await readFile(e.abs);
    else if (e.type !== 'dir') odd.push(e.rel);
  }
  return { files: out, odd };
}

/** Verify a pack archive on disk (a stored pack or an upload). Never throws for a bad pack. */
export async function verifyPackFile(archivePath) {
  await mkdir(evidenceRoot(), { recursive: true, mode: 0o700 });
  const work = await mkdtemp(join(evidenceRoot(), '.verify-'));
  try {
    try {
      await extractTar(archivePath, work, { gzip: true });
    } catch (e) {
      return { ok: false, signature_ok: false, manifest_ok: false, files: [], missing: [], unexpected: [], errors: ['not a readable tar.gz evidence pack'] };
    }
    const { files, odd } = await readTree(work);
    const r = verifyFiles(files);
    if (odd.length) {
      r.unexpected.push(...odd);
      r.ok = false;
      r.errors.push(`${odd.length} entr${odd.length === 1 ? 'y is' : 'ies are'} not a regular file`);
    }
    return r;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

export async function verifyUploadedPack(buffer) {
  await mkdir(evidenceRoot(), { recursive: true, mode: 0o700 });
  const dir = await mkdtemp(join(evidenceRoot(), '.upload-'));
  try {
    const file = join(dir, 'pack.tar.gz');
    await writeFile(file, buffer, { mode: 0o600 });
    return await verifyPackFile(file);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
