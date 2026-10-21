import { createHash, createHmac, timingSafeEqual } from 'crypto';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { deriveSecret } from './encryption.js';
import { jobStarted, trackJob } from './jobHealth.js';
import { recordEvent } from './eventStore.js';
import { getRetention } from './eventRetention.js';

// Tamper-evident audit (migration 146). The sealer appends every new audit_log
// and events row, in id order, to a per-table hash chain, and signs a
// checkpoint of each chain's head with an HMAC key derived from ENCRYPTION_KEY.
// The verifier recomputes everything and reports the first row that does not
// match. Limits: anyone holding the database AND ENCRYPTION_KEY can rebuild
// the chain and re-sign it; only checkpoints held outside AppCrane (the SIEM
// stream, an exported copy) catch that. Rows changed before they were first
// sealed cannot be detected.

export const JOB_ID = 'audit-chain';
export const SOURCES = Object.freeze(['audit_log', 'events']);
export const GENESIS = '0'.repeat(64);
export const SEAL_MS = 5 * 60_000;
export const CHECKPOINT_MS = 15 * 60_000;
export const VERIFY_MS = 6 * 60 * 60_000;
export const COMPACT_MIN = 1000;
export const FINGERPRINT_LEN = 24;
const BATCH = 2000;
const MAX_BATCHES = 200;
const KEY_LABEL = 'appcrane-audit-chain-checkpoint-v1';
const MAIL_SOURCE = 'audit-chain';
const DAY = 86_400_000;

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const yieldTurn = () => new Promise(r => setImmediate(r));
const nowSql = (ms = Date.now()) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
const sqlMs = (ts) => Date.parse(String(ts).replace(' ', 'T') + (String(ts).endsWith('Z') ? '' : 'Z'));

// ── canonical form ─────────────────────────────────────────────────────────

function auditTuple(r, { user = true, app = true } = {}) {
  return ['audit_log', r.id, user ? r.user_id ?? null : null, app ? r.app_id ?? null : null,
    r.action ?? null, r.detail ?? null, r.created_at ?? null, r.actor_kind ?? null];
}

function eventTuple(r) {
  return ['events', r.id, r.ts ?? null, r.kind ?? null, r.severity ?? null, r.app_id ?? null, r.app_slug ?? null,
    r.user_id ?? null, r.subject_user_id ?? null, r.summary ?? null, r.ref_table ?? null, r.ref_id ?? null, r.data ?? null];
}

export function rowHash(src, row) {
  return sha256(JSON.stringify(src === 'audit_log' ? auditTuple(row) : eventTuple(row)));
}

/** audit_log only: the hashes the row would have after a user or app deletion cleared its ids. */
export function altHashes(row) {
  const out = {};
  if (row.user_id != null) out.u = sha256(JSON.stringify(auditTuple(row, { user: false })));
  if (row.app_id != null) out.a = sha256(JSON.stringify(auditTuple(row, { app: false })));
  if (row.user_id != null || row.app_id != null) out.ua = sha256(JSON.stringify(auditTuple(row, { user: false, app: false })));
  return Object.keys(out).length ? JSON.stringify(out) : null;
}

export function linkHash(prev, rowH, alt, meta) {
  return sha256(`${prev}|${rowH}|${alt || ''}|${meta || ''}`);
}

function entryFor(src, row) {
  return {
    rowHash: rowHash(src, row),
    alt: src === 'audit_log' ? altHashes(row) : null,
    meta: src === 'events' ? JSON.stringify([row.ts, row.severity]) : null,
  };
}

/** 'ok' | 'pseudonymised' | 'modified' for a live row against its chain entry. */
export function compareRow(src, row, entry) {
  const h = rowHash(src, row);
  if (h === entry.row_hash) return 'ok';
  if (src === 'audit_log' && entry.alt_hash) {
    const key = (row.user_id == null ? 'u' : '') + (row.app_id == null ? 'a' : '');
    let alt = null;
    try { alt = JSON.parse(entry.alt_hash); } catch (_) {}
    if (key && alt?.[key] && alt[key] === h) return 'pseudonymised';
  }
  return 'modified';
}

// ── checkpoints ────────────────────────────────────────────────────────────

let keyOverride = null;
function hmacKey() { return keyOverride ?? deriveSecret(KEY_LABEL); }

function signedPayload(c) {
  return JSON.stringify([c.kind, c.src ?? null, c.upto_row_id ?? null, c.chain_hash ?? null, c.data ?? null, c.created_at, c.prev_signature ?? null]);
}

export function signCheckpoint(c, key = hmacKey()) {
  return createHmac('sha256', key).update(signedPayload(c)).digest('hex');
}

export function checkpointValid(c, key = hmacKey()) {
  const want = Buffer.from(signCheckpoint(c, key), 'hex');
  const got = Buffer.from(String(c.signature || ''), 'hex');
  return got.length === want.length && timingSafeEqual(got, want);
}

function writeCheckpoint(db, { kind, src = null, upto_row_id = null, chain_hash = null, data = null, createdAt = nowSql() }) {
  const prev = db.prepare('SELECT signature FROM audit_chain_checkpoints ORDER BY id DESC LIMIT 1').get()?.signature ?? null;
  const c = { kind, src, upto_row_id, chain_hash, data: data == null ? null : JSON.stringify(data), created_at: createdAt, prev_signature: prev };
  c.signature = signCheckpoint(c);
  const id = Number(db.prepare(`INSERT INTO audit_chain_checkpoints (kind, src, upto_row_id, chain_hash, data, created_at, prev_signature, signature)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(c.kind, c.src, c.upto_row_id, c.chain_hash, c.data, c.created_at, c.prev_signature, c.signature).lastInsertRowid);
  lastSeenCheckpointId = Math.max(lastSeenCheckpointId, id);
  return { id, ...c };
}

function latestValid(db, kind, src) {
  const rows = db.prepare('SELECT * FROM audit_chain_checkpoints WHERE kind = ? AND src IS ? ORDER BY id DESC LIMIT 50').all(kind, src);
  return rows.find(c => checkpointValid(c)) || null;
}

function headOf(db, src) {
  const last = db.prepare('SELECT row_id, chain_hash FROM audit_chain WHERE src = ? ORDER BY row_id DESC LIMIT 1').get(src);
  if (last) return last;
  const floor = latestValid(db, 'compaction', src);
  return floor ? { row_id: floor.upto_row_id, chain_hash: floor.chain_hash } : { row_id: 0, chain_hash: GENESIS };
}

// ── sealing ────────────────────────────────────────────────────────────────

let lastSeenCheckpointId = 0;
let lastSealCheckpointAt = 0;

/** Append every unsealed row (id above the chain head) to its chain. Returns { audit_log, events } counts. */
export async function sealNew({ db = getDb(), batch = BATCH } = {}) {
  const sealed = {};
  const insert = db.prepare('INSERT INTO audit_chain (src, row_id, row_hash, alt_hash, meta, chain_hash) VALUES (?, ?, ?, ?, ?, ?)');
  for (const src of SOURCES) {
    sealed[src] = 0;
    for (let i = 0; i < MAX_BATCHES; i++) {
      const head = headOf(db, src);
      const rows = db.prepare(`SELECT * FROM ${src} WHERE id > ? ORDER BY id LIMIT ?`).all(head.row_id, batch);
      if (!rows.length) break;
      db.transaction(() => {
        let prev = head.chain_hash;
        for (const r of rows) {
          const e = entryFor(src, r);
          prev = linkHash(prev, e.rowHash, e.alt, e.meta);
          insert.run(src, r.id, e.rowHash, e.alt, e.meta, prev);
        }
      })();
      sealed[src] += rows.length;
      if (rows.length < batch) break;
      await yieldTurn();
    }
  }
  return sealed;
}

function retentionChanged(db) {
  const cur = getRetention(db);
  const last = latestValid(db, 'retention', null);
  if (!last) return cur;
  let prev = null;
  try { prev = JSON.parse(last.data); } catch (_) {}
  return prev && ['info', 'warning', 'critical'].every(s => prev[s] === cur[s]) ? null : cur;
}

/** Sign the head of each chain (and the event retention windows when they changed). */
export function checkpointNow({ db = getDb(), now = Date.now() } = {}) {
  const out = [];
  const retention = retentionChanged(db);
  if (retention) out.push(writeCheckpoint(db, { kind: 'retention', data: retention, createdAt: nowSql(now) }));
  for (const src of SOURCES) {
    const head = db.prepare('SELECT row_id, chain_hash FROM audit_chain WHERE src = ? ORDER BY row_id DESC LIMIT 1').get(src);
    if (!head) continue;
    const last = latestValid(db, 'seal', src);
    if (last && last.upto_row_id === head.row_id) continue;
    out.push(writeCheckpoint(db, { kind: 'seal', src, upto_row_id: head.row_id, chain_hash: head.chain_hash, createdAt: nowSql(now) }));
  }
  lastSealCheckpointAt = now;
  const seals = out.filter(c => c.kind === 'seal');
  if (seals.length) {
    recordEvent({
      kind: 'audit.checkpoint',
      severity: 'info',
      summary: 'Audit chain checkpoint signed',
      refTable: 'audit_chain_checkpoints',
      refId: seals[seals.length - 1].id,
      data: { checkpoints: seals.map(fingerprintOf) },
    });
  }
  return out;
}

/** What an external holder keeps: short enough to pass the event scrubber, long enough to be unforgeable. */
export function fingerprintOf(c) {
  return { id: c.id, src: c.src, upto_row_id: c.upto_row_id, chain_fp: String(c.chain_hash).slice(0, FINGERPRINT_LEN), created_at: c.created_at };
}

// ── compaction ─────────────────────────────────────────────────────────────

/** Drop the chain prefix of `src` whose rows retention has already removed, below a signed compaction checkpoint. */
export async function compact({ db = getDb(), src = 'events', now = Date.now(), min = COMPACT_MIN } = {}) {
  if (src !== 'events') return 0;
  const windows = retentionWindows(db, now);
  const head = db.prepare('SELECT MIN(row_id) AS lo FROM audit_chain WHERE src = ?').get(src)?.lo;
  if (head == null) return 0;
  let upto = null;
  let after = head - 1;
  let done = false;
  while (!done) {
    const rows = db.prepare(`SELECT c.row_id, c.chain_hash, c.meta, s.id IS NULL AS gone
                               FROM audit_chain c LEFT JOIN ${src} s ON s.id = c.row_id
                              WHERE c.src = ? AND c.row_id > ? ORDER BY c.row_id LIMIT ?`).all(src, after, BATCH);
    if (!rows.length) break;
    for (const r of rows) {
      if (!r.gone || !prunedByRetention(r.meta, windows)) { done = true; break; }
      upto = r;
    }
    after = rows[rows.length - 1].row_id;
    if (rows.length < BATCH) break;
    await yieldTurn();
  }
  if (!upto) return 0;
  const n = db.prepare('SELECT COUNT(*) AS n FROM audit_chain WHERE src = ? AND row_id <= ?').get(src, upto.row_id).n;
  if (n < min) return 0;
  db.transaction(() => {
    writeCheckpoint(db, { kind: 'compaction', src, upto_row_id: upto.row_id, chain_hash: upto.chain_hash, createdAt: nowSql(now) });
    db.prepare('DELETE FROM audit_chain WHERE src = ? AND row_id <= ?').run(src, upto.row_id);
  })();
  return n;
}

// ── verification ───────────────────────────────────────────────────────────

/** Signed retention policies, each with the time it stopped applying. */
function retentionWindows(db, now = Date.now()) {
  const rows = db.prepare("SELECT * FROM audit_chain_checkpoints WHERE kind = 'retention' ORDER BY id").all().filter(c => checkpointValid(c));
  return rows.map((c, i) => {
    let days = null;
    try { days = JSON.parse(c.data); } catch (_) {}
    return { days, until: i + 1 < rows.length ? sqlMs(rows[i + 1].created_at) : now };
  }).filter(w => w.days);
}

/** True when a missing event was old enough for a signed retention window to have removed it. */
function prunedByRetention(meta, windows) {
  let ts, severity;
  try { [ts, severity] = JSON.parse(meta); } catch (_) { return false; }
  const at = sqlMs(ts);
  if (!Number.isFinite(at)) return false;
  return windows.some(w => Number.isFinite(w.days[severity]) && at < w.until - w.days[severity] * DAY);
}

function problemKey(p) {
  return `${p.type}:${p.src || ''}:${p.row_id ?? p.checkpoint_id ?? ''}`;
}

/**
 * Recompute both chains, every live row and every checkpoint. Returns
 * { ok, checked, problems: [{type, src, row_id|checkpoint_id, detail}], first_broken: {src: row_id} }.
 * types: forged_checkpoint, checkpoint_gap, checkpoints_truncated, broken_link,
 * deleted, modified, unsealed, checkpoint_mismatch.
 */
export async function verifyChain({ db = getDb(), now = Date.now(), batch = BATCH } = {}) {
  const problems = [];
  const stats = { checked: 0, pruned: 0, pseudonymised: 0 };
  const all = db.prepare('SELECT * FROM audit_chain_checkpoints ORDER BY id').all();
  const valid = [];
  let prevSig = null;
  for (const c of all) {
    if (!checkpointValid(c)) {
      problems.push({ type: 'forged_checkpoint', src: c.src, checkpoint_id: c.id, detail: 'Signature does not match: written without the key' });
      continue;
    }
    if (valid.length && c.prev_signature !== prevSig) {
      problems.push({ type: 'checkpoint_gap', src: c.src, checkpoint_id: c.id, detail: 'The checkpoint before this one was removed' });
    }
    valid.push(c);
    prevSig = c.signature;
  }
  const maxId = all.length ? all[all.length - 1].id : 0;
  if (maxId < lastSeenCheckpointId) {
    problems.push({ type: 'checkpoints_truncated', checkpoint_id: lastSeenCheckpointId, detail: `Checkpoints after #${maxId} were removed` });
  }
  const windows = retentionWindows(db, now);

  for (const src of SOURCES) {
    const floor = [...valid].reverse().find(c => c.kind === 'compaction' && c.src === src);
    let prev = floor ? floor.chain_hash : GENESIS;
    let after = floor ? floor.upto_row_id : 0;
    const seals = valid.filter(c => c.kind === 'seal' && c.src === src && c.upto_row_id > after);
    const wanted = new Map(seals.map(c => [c.upto_row_id, null]));
    const maxSealed = db.prepare('SELECT MAX(row_id) AS m FROM audit_chain WHERE src = ?').get(src).m ?? after;

    for (let more = true; more;) {
      const entries = db.prepare('SELECT * FROM audit_chain WHERE src = ? AND row_id > ? AND row_id <= ? ORDER BY row_id LIMIT ?')
        .all(src, after, maxSealed, batch);
      more = entries.length === batch;
      if (!entries.length) break;
      const lo = entries[0].row_id;
      const hi = entries[entries.length - 1].row_id;
      const live = new Map(db.prepare(`SELECT * FROM ${src} WHERE id BETWEEN ? AND ?`).all(lo, hi).map(r => [r.id, r]));
      for (const e of entries) {
        stats.checked++;
        if (linkHash(prev, e.row_hash, e.alt_hash, e.meta) !== e.chain_hash) {
          problems.push({ type: 'broken_link', src, row_id: e.row_id, detail: 'Chain entry does not follow from the one before it' });
        }
        prev = e.chain_hash;
        if (wanted.has(e.row_id)) wanted.set(e.row_id, e.chain_hash);
        const row = live.get(e.row_id);
        if (!row) {
          if (src === 'events' && prunedByRetention(e.meta, windows)) stats.pruned++;
          else problems.push({ type: 'deleted', src, row_id: e.row_id, detail: 'Row was sealed and is now missing' });
          continue;
        }
        const cmp = compareRow(src, row, e);
        if (cmp === 'pseudonymised') stats.pseudonymised++;
        else if (cmp === 'modified') problems.push({ type: 'modified', src, row_id: e.row_id, detail: 'Row content differs from what was sealed' });
      }
      const unsealed = db.prepare(`SELECT s.id FROM ${src} s WHERE s.id > ? AND s.id <= ?
                                     AND NOT EXISTS (SELECT 1 FROM audit_chain c WHERE c.src = ? AND c.row_id = s.id)`).all(after, hi, src);
      for (const u of unsealed) problems.push({ type: 'unsealed', src, row_id: u.id, detail: 'Row inserted below rows already sealed' });
      after = hi;
      if (more) await yieldTurn();
    }
    if (floor) {
      const below = db.prepare(`SELECT id FROM ${src} WHERE id <= ? ORDER BY id LIMIT 20`).all(floor.upto_row_id);
      for (const u of below) problems.push({ type: 'unsealed', src, row_id: u.id, detail: 'Row present below a compaction checkpoint' });
    }
    for (const c of seals) {
      const got = wanted.get(c.upto_row_id);
      if (got !== c.chain_hash) {
        problems.push({ type: 'checkpoint_mismatch', src, row_id: c.upto_row_id, checkpoint_id: c.id,
          detail: got == null ? 'Chain entry named by a signed checkpoint is missing' : 'Chain was rebuilt: it no longer matches a signed checkpoint' });
      }
    }
  }

  const first_broken = {};
  for (const p of problems) {
    if (p.row_id == null || !p.src) continue;
    if (first_broken[p.src] == null || p.row_id < first_broken[p.src]) first_broken[p.src] = p.row_id;
  }
  return { ok: problems.length === 0, checked: stats.checked, pruned: stats.pruned, pseudonymised: stats.pseudonymised, problems, first_broken };
}

function platformAdmins(db) {
  return db.prepare("SELECT id, name, email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL").all();
}

/** Verify, store the result, and on a new failure e-mail platform admins once and record a critical event. */
export async function verifyAndRecord({ db = getDb(), now = Date.now(), trigger = 'job' } = {}) {
  const report = await verifyChain({ db, now });
  const shown = report.problems.slice(0, 200);
  db.prepare('INSERT INTO audit_chain_verifications (ok, checked, problems, trigger_by) VALUES (?, ?, ?, ?)')
    .run(report.ok ? 1 : 0, report.checked, JSON.stringify({ problems: shown, first_broken: report.first_broken, total: report.problems.length }), trigger);
  db.prepare('DELETE FROM audit_chain_verifications WHERE id NOT IN (SELECT id FROM audit_chain_verifications ORDER BY id DESC LIMIT 200)').run();
  if (!report.ok) await alertFailure(db, report);
  return report;
}

async function alertFailure(db, report) {
  const signature = sha256(report.problems.map(problemKey).sort().join(',')).slice(0, FINGERPRINT_LEN);
  const firsts = Object.entries(report.first_broken).map(([s, id]) => `${s} row ${id}`).join(', ') || 'checkpoints';
  const summary = `Audit chain verification failed: ${report.problems.length} problem(s), first at ${firsts}`;
  recordEvent({ kind: 'audit.chain_broken', severity: 'critical', summary, data: { signature, first_broken: report.first_broken, types: [...new Set(report.problems.map(p => p.type))] },
    dedupeKey: `audit-chain:${signature}`, dedupeMs: 30 * DAY });
  const { enqueueEmail } = await import('./emailQueue.js');
  const { renderBrandedEmail, bulletList } = await import('./mail/brandedLayout.js');
  const { dashboardBaseUrl } = await import('./vulnRequests.js');
  const lines = report.problems.slice(0, 10).map(p => `${p.type}: ${p.src || 'checkpoints'} ${p.row_id != null ? `row ${p.row_id}` : `checkpoint ${p.checkpoint_id}`} - ${p.detail}`);
  const url = `${dashboardBaseUrl()}/audit-integrity`;
  for (const a of platformAdmins(db)) {
    try {
      enqueueEmail({
        to: a.email,
        subject: '[AppCrane] CRITICAL: audit history failed its integrity check',
        text: `${summary}.\n\n${lines.join('\n')}\n\nSomeone may have edited or deleted audit history. See ${url}\n`,
        html: renderBrandedEmail({
          preheader: summary,
          greeting: `Hi${a.name ? ` ${a.name}` : ''},`,
          intro: `${summary}. Someone may have edited or deleted audit history.`,
          bodyHtml: bulletList(lines),
          cta: { label: 'Open Audit integrity', url },
          footer: 'You get this because you are a platform admin. This failure is reported once; a different failure is reported again.',
        }),
        appId: null,
        source: MAIL_SOURCE,
        idempotencyKey: `${MAIL_SOURCE}:failure:${signature}:${a.id}`,
      });
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[audit-chain] failure alert skipped: ${e.message}`);
    }
  }
}

// ── read side ──────────────────────────────────────────────────────────────

export function chainStatus(db = getDb()) {
  const chains = SOURCES.map(src => {
    const r = db.prepare('SELECT COUNT(*) AS n, MAX(row_id) AS head, MAX(sealed_at) AS last_sealed_at FROM audit_chain WHERE src = ?').get(src);
    const pending = db.prepare(`SELECT COUNT(*) AS n FROM ${src} WHERE id > ?`).get(r.head ?? headOf(db, src).row_id).n;
    const seal = latestValid(db, 'seal', src);
    const floor = latestValid(db, 'compaction', src);
    return { src, entries: r.n, head_row_id: r.head, last_sealed_at: r.last_sealed_at, unsealed: pending,
      last_checkpoint: seal ? fingerprintOf(seal) : null, compacted_up_to: floor?.upto_row_id ?? null };
  });
  const last = db.prepare('SELECT * FROM audit_chain_verifications ORDER BY id DESC LIMIT 1').get();
  let lastVerification = null;
  if (last) {
    let p = {};
    try { p = JSON.parse(last.problems || '{}'); } catch (_) {}
    lastVerification = { ran_at: last.ran_at, ok: !!last.ok, checked: last.checked, trigger: last.trigger_by, ...p };
  }
  return { chains, last_verification: lastVerification };
}

export function verificationHistory(db = getDb(), limit = 20) {
  return db.prepare('SELECT id, ran_at, ok, checked, trigger_by FROM audit_chain_verifications ORDER BY id DESC LIMIT ?').all(limit)
    .map(r => ({ ...r, ok: !!r.ok }));
}

/** The latest signed seal checkpoints, for an external party to keep. */
export function exportCheckpoints(db = getDb(), limit = 100) {
  return db.prepare("SELECT * FROM audit_chain_checkpoints WHERE kind = 'seal' ORDER BY id DESC LIMIT ?").all(limit)
    .map(c => ({ id: c.id, src: c.src, upto_row_id: c.upto_row_id, chain_hash: c.chain_hash, created_at: c.created_at, signature: c.signature }));
}

/**
 * Compare checkpoints held outside AppCrane with the chain as it is now. Each
 * item needs src, upto_row_id and chain_hash (or a chain_fp prefix of at least
 * FINGERPRINT_LEN). This catches a rebuild by someone who holds the key.
 */
export function checkExternalCheckpoints(items, db = getDb()) {
  const list = Array.isArray(items) ? items.slice(0, 1000) : [];
  return list.map((it) => {
    const src = SOURCES.includes(it?.src) ? it.src : null;
    const rowId = Number(it?.upto_row_id);
    const held = String(it?.chain_hash || it?.chain_fp || '').toLowerCase();
    if (!src || !Number.isInteger(rowId) || rowId < 1 || !/^[0-9a-f]+$/.test(held) || held.length < FINGERPRINT_LEN) {
      return { ...it, result: 'invalid' };
    }
    const entry = db.prepare('SELECT chain_hash FROM audit_chain WHERE src = ? AND row_id = ?').get(src, rowId);
    let current = entry?.chain_hash;
    if (!current) {
      const floor = db.prepare("SELECT * FROM audit_chain_checkpoints WHERE kind = 'compaction' AND src = ? AND upto_row_id = ? ORDER BY id DESC LIMIT 1").get(src, rowId);
      current = floor?.chain_hash;
    }
    if (!current) return { src, upto_row_id: rowId, result: 'not_in_chain' };
    return { src, upto_row_id: rowId, result: current.startsWith(held) ? 'match' : 'mismatch' };
  });
}

// ── job ────────────────────────────────────────────────────────────────────

let timer = null;
let lastVerifyAt = 0;
let running = false;

export async function runAuditChainTick({ db = getDb(), now = Date.now(), forceVerify = false } = {}) {
  if (running) return { skipped: true };
  running = true;
  try {
    const sealed = await sealNew({ db });
    const due = now - lastSealCheckpointAt >= CHECKPOINT_MS;
    if (due) checkpointNow({ db, now });
    let verified = null;
    if (forceVerify || now - lastVerifyAt >= VERIFY_MS) {
      lastVerifyAt = now;
      await compact({ db, now });
      verified = await verifyAndRecord({ db, now, trigger: 'job' });
    }
    return { sealed, verified: verified ? { ok: verified.ok, problems: verified.problems.length } : null };
  } finally {
    running = false;
  }
}

export function startAuditChain() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: SEAL_MS });
  lastVerifyAt = Date.now() - VERIFY_MS + 10 * 60_000;
  const tick = () => trackJob(JOB_ID, () => runAuditChainTick()).catch(e => log.warn(`[audit-chain] ${e.message}`));
  const first = setTimeout(tick, 60_000);
  first.unref?.();
  timer = setInterval(tick, SEAL_MS);
  timer.unref?.();
}

export function stopAuditChain() {
  if (timer) clearInterval(timer);
  timer = null;
}

export function _resetAuditChainForTests({ key = null } = {}) {
  keyOverride = key;
  lastSeenCheckpointId = 0;
  lastSealCheckpointAt = 0;
  lastVerifyAt = 0;
  running = false;
}
