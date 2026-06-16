/**
 * Async email queue for the app email service (v2.8.0).
 *
 * enqueueEmail() validates + inserts a row and returns immediately — the
 * caller (an app's server, or AppCrane's own request-lifecycle notifications)
 * never blocks on SMTP. A worker ticks every few seconds, claims due rows,
 * sends via the shared transport (emailService), and retries with backoff.
 * After MAX_ATTEMPTS a row is dead-lettered and the platform admin is emailed
 * so a broken relay surfaces to a human, not just a log line.
 *
 * Recipient policy: a message may only go to a KNOWN SSO user's email on the
 * configured recipient domain (default opswat.com). This bounds the service to
 * "notify a platform user" — no arbitrary recipients, no spam vector.
 */

import { getDb } from '../db.js';
import { sendEmail } from './emailService.js';
import log from '../utils/logger.js';

const TICK_MS = 5_000;
const MAX_ATTEMPTS = 5;
const BATCH = 10;
// Backoff schedule (seconds) indexed by attempt number. Last value repeats.
const BACKOFF_S = [30, 120, 600, 1800];
let timer = null;

function getSetting(db, key, fallback) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row?.value ?? fallback;
}

/**
 * Resolve the recipient if and only if it's a known, active platform user
 * (any auth method — SSO, SAML, OIDC, or local). Returns the canonical email
 * or throws. This is the hard bound on the service: it can only ever email
 * people who already have an account on this AppCrane — no arbitrary
 * recipients, no spam vector.
 */
export function assertValidRecipient(db, to) {
  const addr = String(to || '').trim().toLowerCase();
  if (!addr || !addr.includes('@')) throw new Error(`Invalid recipient: ${to}`);
  const user = db.prepare('SELECT email FROM users WHERE lower(email) = ? AND active = 1').get(addr);
  if (!user) {
    throw new Error(`Recipient ${addr} is not a platform user — email may only be sent to registered AppCrane users`);
  }
  return user.email;
}

/**
 * Enqueue one message. Validates the recipient against the SSO directory.
 * @param {object} m { appId?, env?, to, subject, text?, html?, replyTo?, fromName?, idempotencyKey?, source? }
 * @returns {{ id:number, deduped?:boolean }}
 */
export function enqueueEmail(m) {
  const db = getDb();
  const to = assertValidRecipient(db, m.to);
  if (!m.subject || !String(m.subject).trim()) throw new Error('subject is required');
  if (!m.text && !m.html) throw new Error('text or html body is required');

  // Idempotency: a retrying caller with the same key gets the existing row.
  if (m.idempotencyKey && m.appId != null) {
    const existing = db.prepare(
      'SELECT id FROM email_queue WHERE app_id = ? AND idempotency_key = ?'
    ).get(m.appId, m.idempotencyKey);
    if (existing) return { id: existing.id, deduped: true };
  }

  const res = db.prepare(`
    INSERT INTO email_queue (app_id, env, to_email, from_name, reply_to, subject, body_text, body_html, idempotency_key, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    m.appId ?? null, m.env ?? null, to, m.fromName ?? null, m.replyTo ?? null,
    String(m.subject), m.text ?? null, m.html ?? null,
    m.idempotencyKey ?? null, m.source || 'app'
  );
  return { id: res.lastInsertRowid };
}

function resolveFromName(db, row) {
  // Display name only — the address is platform-controlled and resolved by the
  // transport (the Graph mailbox / SMTP From), never per-app.
  return row.from_name || getSetting(db, 'email_from_name', 'AIMI');
}

async function deadLetter(db, row) {
  // Notify every platform admin by email that a message failed for good.
  const admins = db.prepare("SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL").all();
  const subject = `[AppCrane] email delivery FAILED after ${MAX_ATTEMPTS} attempts`;
  const text =
    `A queued email could not be delivered.\n\n` +
    `Queue id: ${row.id}\nApp id: ${row.app_id ?? '(platform)'}  env: ${row.env ?? '-'}\n` +
    `To: ${row.to_email}\nSubject: ${row.subject}\nSource: ${row.source}\n` +
    `Last error: ${row.error || '(none recorded)'}\n`;
  for (const a of admins) {
    // Send directly (not via the queue) so a queue/transport fault can't
    // swallow its own alarm.
    await sendEmail({ to: a.email, subject, text }).catch(e =>
      log.error(`[email] dead-letter notice to ${a.email} failed: ${e.message}`));
  }
}

async function processRow(db, row) {
  db.prepare("UPDATE email_queue SET status='sending' WHERE id = ?").run(row.id);
  try {
    const result = await sendEmail({
      to: row.to_email,
      subject: row.subject,
      text: row.body_text || undefined,
      html: row.body_html || undefined,
      fromName: resolveFromName(db, row),
      replyTo: row.reply_to || undefined,
    });
    db.prepare("UPDATE email_queue SET status='sent', sent_at=datetime('now'), message_id=?, attempts=attempts+1 WHERE id = ?")
      .run(result?.messageId || (result?.mock ? 'mock' : null), row.id);
    log.info(`[email] sent #${row.id} → ${row.to_email} (${row.source})`);
  } catch (e) {
    const attempts = row.attempts + 1;
    if (attempts >= MAX_ATTEMPTS) {
      db.prepare("UPDATE email_queue SET status='failed', attempts=?, error=? WHERE id = ?")
        .run(attempts, String(e.message).slice(0, 500), row.id);
      log.error(`[email] #${row.id} dead-lettered after ${attempts} attempts: ${e.message}`);
      await deadLetter(db, { ...row, attempts, error: e.message });
    } else {
      const delay = BACKOFF_S[Math.min(attempts - 1, BACKOFF_S.length - 1)];
      db.prepare(`UPDATE email_queue SET status='queued', attempts=?, error=?,
        next_attempt_at=datetime('now', '+' || ? || ' seconds') WHERE id = ?`)
        .run(attempts, String(e.message).slice(0, 500), delay, row.id);
      log.warn(`[email] #${row.id} attempt ${attempts} failed (retry in ${delay}s): ${e.message}`);
    }
  }
}

async function tick() {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT * FROM email_queue
      WHERE status = 'queued' AND next_attempt_at <= datetime('now')
      ORDER BY id ASC LIMIT ?
    `).all(BATCH);
    for (const row of rows) {
      await processRow(db, row);
    }
  } catch (e) {
    log.error(`[email] tick error: ${e.message}`);
  }
}

/** Start the worker. Idempotent. Resets rows orphaned mid-send by a restart. */
export function startEmailWorker() {
  if (timer) return;
  try {
    const db = getDb();
    const reset = db.prepare("UPDATE email_queue SET status='queued' WHERE status='sending'").run();
    if (reset.changes > 0) log.warn(`[email] reset ${reset.changes} orphaned 'sending' row(s) to 'queued' on boot`);
  } catch (e) {
    log.warn(`[email] boot orphan-reset failed: ${e.message}`);
  }
  log.info(`[email] queue worker started (tick every ${TICK_MS / 1000}s)`);
  timer = setInterval(() => { tick().catch(() => {}); }, TICK_MS);
}

export function stopEmailWorker() {
  if (timer) { clearInterval(timer); timer = null; }
}
