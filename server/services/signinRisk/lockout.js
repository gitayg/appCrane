import { createHash } from 'crypto';
import { getDb } from '../../db.js';
import { parseUtc, sqlUtc } from '../sessionPolicy.js';
import { readPolicy } from './config.js';
import { KINDS, signal } from './signals.js';
import { sendLockedMail } from './mail.js';

// Per-ACCOUNT password lockout, independent of the source address: N wrong
// passwords inside the window lock the subject for base * 2^(k-1) minutes
// (k = locks in a row, capped at the max). Stored in the database, so a
// restart does not hand an attacker a fresh budget.
//
// Subjects (see migration 235):
//   u:<id>  a real account, from any browser it has not signed in from before
//   l:<h>   a name that matches no account, locked exactly like a real one so
//           the locked answer does not tell anyone which names exist
//   d:<id>  a browser this account HAS signed in from (signin_devices row).
//           Such a browser is exempt from the u: lock and has its own counter.
//
// Break-glass, by design: the lock covers password guessing only. It never
// touches SSO sign-ins, sessions already issued, or API keys; a recognised
// browser of the account keeps its own counter, so a stranger hammering the
// password cannot lock the owner out of the laptop they always use; and a
// platform admin can lift any lock (audited). See the design note in the
// final report for why this is the chosen trade-off.

const LOCK_COUNT_DECAY_MS = 24 * 3600_000;
const MAX_ROWS = 50_000;

export function loginKey(login) {
  return 'l:' + createHash('sha256').update(String(login || '').trim().toLowerCase()).digest('hex').slice(0, 40);
}

export function subjectFor({ user, login, knownDevice }) {
  if (user && knownDevice) return `d:${knownDevice.id}`;
  if (user) return `u:${user.id}`;
  return loginKey(login);
}

/** { locked, until, retry_after_s } for a subject at nowMs. */
export function lockState(db, key, nowMs = Date.now()) {
  const row = db.prepare('SELECT locked_until FROM signin_lockouts WHERE subject_key = ?').get(key);
  const until = parseUtc(row?.locked_until);
  if (!Number.isFinite(until) || until <= nowMs) return { locked: false, until: null, retry_after_s: 0 };
  return { locked: true, until: new Date(until).toISOString(), retry_after_s: Math.max(1, Math.ceil((until - nowMs) / 1000)) };
}

export function lockMinutes(policy, lockCount) {
  const m = policy.lockout_base_minutes * 2 ** Math.max(0, lockCount - 1);
  return Math.min(policy.lockout_max_minutes, m);
}

/**
 * Count one wrong password for a subject. Returns { locked, until, minutes,
 * just_locked, failures }. Locks (and e-mails the owner, emits the signal)
 * when the count inside the window reaches the threshold.
 */
export function recordPasswordFailure(db, { key, user = null, ip = null, method = 'password' }, nowMs = Date.now()) {
  const policy = readPolicy(db);
  const windowMs = policy.lockout_window_minutes * 60_000;
  const row = db.prepare('SELECT * FROM signin_lockouts WHERE subject_key = ?').get(key);
  const started = parseUtc(row?.window_started_at);
  const inWindow = row && Number.isFinite(started) && nowMs - started < windowMs;
  const failures = inWindow ? row.failures + 1 : 1;
  const windowStart = inWindow ? row.window_started_at : sqlUtc(nowMs);
  const lastLocked = parseUtc(row?.last_locked_at);
  const priorLocks = row && Number.isFinite(lastLocked) && nowMs - lastLocked < LOCK_COUNT_DECAY_MS ? row.lock_count : 0;

  if (failures < policy.lockout_threshold) {
    db.prepare(`INSERT INTO signin_lockouts (subject_key, user_id, failures, window_started_at, lock_count, last_failure_at, last_ip)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(subject_key) DO UPDATE SET failures = excluded.failures, window_started_at = excluded.window_started_at,
        lock_count = excluded.lock_count, last_failure_at = excluded.last_failure_at, last_ip = excluded.last_ip`)
      .run(key, user?.id ?? null, failures, windowStart, priorLocks, sqlUtc(nowMs), ip);
    if (!row) pruneRows(db, nowMs);
    return { locked: false, until: null, minutes: 0, just_locked: false, failures };
  }

  const lockCount = priorLocks + 1;
  const minutes = lockMinutes(policy, lockCount);
  const untilMs = nowMs + minutes * 60_000;
  db.prepare(`INSERT INTO signin_lockouts (subject_key, user_id, failures, window_started_at, locked_until, lock_count, last_locked_at, last_failure_at, last_ip)
    VALUES (?, ?, 0, NULL, ?, ?, ?, ?, ?)
    ON CONFLICT(subject_key) DO UPDATE SET failures = 0, window_started_at = NULL, locked_until = excluded.locked_until,
      lock_count = excluded.lock_count, last_locked_at = excluded.last_locked_at, last_failure_at = excluded.last_failure_at, last_ip = excluded.last_ip`)
    .run(key, user?.id ?? null, sqlUtc(untilMs), lockCount, sqlUtc(nowMs), sqlUtc(nowMs), ip);
  const untilIso = new Date(untilMs).toISOString();
  if (user) {
    const scope = key.startsWith('d:') ? 'a recognised browser' : 'unrecognised browsers';
    const mailed = user.email ? sendLockedMail(user, { untilIso, minutes, ip }) : false;
    signal({
      kind: KINDS.locked, severity: 'warning', subjectUserId: user.id,
      summary: `Password sign-in locked for ${minutes} min after ${failures} failures (${scope})`,
      data: { subject: key.split(':')[0], minutes, lock_count: lockCount, until: untilIso, ip, method, mailed },
      audit: { actorId: null, action: 'signin-locked' },
    });
  }
  return { locked: true, until: untilIso, minutes, just_locked: true, failures };
}

/** A successful password sign-in for this subject clears its counter and its backoff. */
export function clearSubject(db, key) {
  db.prepare('DELETE FROM signin_lockouts WHERE subject_key = ?').run(key);
}

/** Platform-admin unlock: every lock and counter of the user. Audited. Returns the number of rows cleared. */
export function unlockUser(db, userId, { actorId, ip = null, via = 'api' } = {}) {
  const n = db.prepare('DELETE FROM signin_lockouts WHERE user_id = ?').run(userId).changes;
  signal({
    kind: KINDS.unlocked, severity: 'info', userId: actorId, subjectUserId: userId,
    summary: via === 'cli' ? 'Password sign-in lock lifted on the host (crane signin unlock)' : 'Password sign-in lock lifted by a platform admin',
    data: { cleared: n, ip, via },
    audit: { actorId, action: 'signin-unlock' },
  });
  return n;
}

/** Accounts locked right now (real users only). */
export function listLocked(db = getDb(), nowMs = Date.now()) {
  return db.prepare(`SELECT l.subject_key, l.user_id, l.locked_until, l.lock_count, l.last_locked_at, l.last_ip,
      u.name, u.username, u.email, u.role
    FROM signin_lockouts l JOIN users u ON u.id = l.user_id
    WHERE l.locked_until IS NOT NULL ORDER BY l.locked_until DESC`).all()
    .filter((r) => parseUtc(r.locked_until) > nowMs)
    .map((r) => ({
      user_id: r.user_id, name: r.name, username: r.username, email: r.email, role: r.role,
      scope: r.subject_key.startsWith('d:') ? 'device' : 'account',
      locked_until: new Date(parseUtc(r.locked_until)).toISOString(), lock_count: r.lock_count, last_ip: r.last_ip,
    }));
}

/** Drop rows with no lock in force and no recent failure. */
export function pruneLockouts(db = getDb(), nowMs = Date.now()) {
  return db.prepare(`DELETE FROM signin_lockouts
    WHERE (locked_until IS NULL OR locked_until <= ?) AND (last_failure_at IS NULL OR last_failure_at <= ?)`)
    .run(sqlUtc(nowMs), sqlUtc(nowMs - LOCK_COUNT_DECAY_MS)).changes;
}

function pruneRows(db, nowMs) {
  const n = db.prepare('SELECT COUNT(*) n FROM signin_lockouts').get().n;
  if (n > MAX_ROWS) pruneLockouts(db, nowMs);
}
