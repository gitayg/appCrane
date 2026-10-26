// App intake with security approval (migration 139).
//
// Every new app answers a short intake: purpose, data classification, whether
// it stores personal or customer data, its external integrations, and who
// should have access. Whether production then waits for a platform admin's
// approval is the classification policy's `intake_approval` flag (default:
// confidential and restricted wait; public and internal are approved on
// submission). Sandbox is never gated.

import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { logAudit } from '../middleware/audit.js';
import { recordEvent } from './eventStore.js';
import { enqueueEmail } from './emailQueue.js';
import { esc, bulletList, renderBrandedEmail } from './mail/brandedLayout.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { appOwners, platformAdmins } from './memoryAdmissionMail.js';
import { DEFAULT_LEVEL, assertLevel, levelPolicy } from './dataClassification.js';
import log from '../utils/logger.js';

export const INTAKE_MAIL_SOURCE = 'intake';
const MAX_TEXT = 2000;

function text(v, field) {
  if (v == null || v === '') return null;
  if (typeof v !== 'string') throw new AppError(`${field} must be a string`, 400, 'VALIDATION');
  return v.trim().slice(0, MAX_TEXT) || null;
}

/** Validate intake input. Throws AppError 400. */
export function normalizeIntake(input = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new AppError('intake must be an object', 400, 'VALIDATION');
  }
  const answers = input.intake_answers && typeof input.intake_answers === 'object' ? input.intake_answers : {};
  const pick = (k) => (input[k] !== undefined ? input[k] : answers[k]);
  const pd = pick('personal_data');
  if (pd !== undefined && pd !== null && typeof pd !== 'boolean') {
    throw new AppError('personal_data must be true or false', 400, 'VALIDATION');
  }
  return {
    purpose: text(pick('purpose'), 'purpose'),
    data_classification: assertLevel(input.data_classification ?? DEFAULT_LEVEL),
    personal_data: pd === true,
    external_integrations: text(pick('external_integrations'), 'external_integrations'),
    access: text(pick('access'), 'access'),
  };
}

/**
 * Record (or resubmit) an app's intake. The one entry point every creation
 * path calls: dashboard New App, catalogue installs, the MCP create tools and
 * the importer.
 *
 * @param {object} app  apps row (needs id, slug)
 * @param {{ purpose?: string, data_classification?: string, owner?: number|null,
 *           intake_answers?: { personal_data?: boolean, external_integrations?: string, access?: string },
 *           submitted_by?: number|null, db?: object }} intake
 * @returns {{ app_id: number, status: 'pending'|'approved', data_classification: string, approval_required: boolean }}
 */
export function submitIntake(app, intake = {}) {
  const db = intake.db || getDb();
  const n = normalizeIntake(intake);
  const submittedBy = intake.submitted_by ?? intake.owner ?? null;
  const required = !!levelPolicy(db, n.data_classification).intake_approval;
  const status = required ? 'pending' : 'approved';
  const answers = JSON.stringify({ purpose: n.purpose, personal_data: n.personal_data,
    external_integrations: n.external_integrations, access: n.access, owner: intake.owner ?? null });
  db.prepare(`
    INSERT INTO app_intake (app_id, data_classification, purpose, personal_data, external_integrations, access_notes,
      answers_json, status, grandfathered, submitted_by, submitted_at, reviewed_by, reviewed_at, review_comment, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, datetime('now'), NULL, ?, ?, datetime('now'))
    ON CONFLICT(app_id) DO UPDATE SET
      data_classification = CASE WHEN app_intake.classification_locked = 1 THEN app_intake.data_classification ELSE excluded.data_classification END,
      purpose = excluded.purpose, personal_data = excluded.personal_data,
      external_integrations = excluded.external_integrations, access_notes = excluded.access_notes,
      answers_json = excluded.answers_json, status = excluded.status, grandfathered = 0,
      submitted_by = excluded.submitted_by, submitted_at = excluded.submitted_at,
      reviewed_by = NULL, reviewed_at = excluded.reviewed_at, review_comment = excluded.review_comment,
      updated_at = excluded.updated_at
  `).run(app.id, n.data_classification, n.purpose, n.personal_data ? 1 : 0, n.external_integrations, n.access,
    answers, status, submittedBy, required ? null : new Date().toISOString().slice(0, 19).replace('T', ' '),
    required ? null : 'No approval required for this classification');

  const row = getIntake(db, app.id);
  logAudit(submittedBy, app.id, 'app-intake-submit', { data_classification: row.data_classification, status, personal_data: n.personal_data });
  recordEvent({
    kind: 'intake.submitted', severity: 'info', appId: app.id, userId: submittedBy,
    summary: required
      ? `Intake submitted (${row.data_classification}): waiting for security approval before production`
      : `Intake submitted (${row.data_classification}): no approval required`,
    data: { data_classification: row.data_classification, status },
  });
  if (required) notifyApprovers(db, app, row);
  return { app_id: app.id, status: row.status, data_classification: row.data_classification, approval_required: required };
}

export function getIntake(db, appId) {
  const row = db.prepare('SELECT * FROM app_intake WHERE app_id = ?').get(appId);
  if (!row) return null;
  return { ...row, personal_data: !!row.personal_data, grandfathered: !!row.grandfathered, classification_locked: !!row.classification_locked };
}

/**
 * Does intake allow production for this app right now?
 * @returns {{ ok: boolean, required: boolean, status: string, data_classification: string, message: string }}
 */
export function intakeGate(db, app) {
  const row = getIntake(db, app.id);
  const level = row?.data_classification || DEFAULT_LEVEL;
  const required = !!levelPolicy(db, level).intake_approval;
  const status = row ? row.status : 'none';
  if (status === 'approved') {
    return { ok: true, required, status, data_classification: level, message: row.grandfathered ? 'Approved (existing app, grandfathered at upgrade)' : 'Intake approved' };
  }
  if (status === 'rejected') {
    return { ok: false, required: true, status, data_classification: level,
      message: `Intake was rejected${row.review_comment ? `: ${row.review_comment}` : ''}. Update the intake and resubmit before deploying to production.` };
  }
  if (!required) {
    return { ok: true, required, status, data_classification: level, message: `No intake approval required for ${level} apps` };
  }
  return { ok: false, required, status, data_classification: level,
    message: status === 'none'
      ? `This ${level} app has no intake. Submit the intake form; production stays closed until a platform admin approves it. Sandbox deploys are allowed.`
      : `This ${level} app is waiting for security approval of its intake. Production stays closed until a platform admin approves it. Sandbox deploys are allowed.` };
}

/** Throws 403 INTAKE_NOT_APPROVED when production is closed by intake. */
export function assertIntakeAllowsProduction(db, app) {
  const g = intakeGate(db, app);
  if (!g.ok) {
    const e = new AppError(g.message, 403, 'INTAKE_NOT_APPROVED');
    e.intake = g;
    throw e;
  }
  return g;
}

/** Approve or reject. Platform admins only. */
export function reviewIntake(db, app, { decision, comment }, user) {
  if (!isPlatformAdmin(user)) throw new AppError('Only platform admins can review app intake', 403, 'FORBIDDEN');
  if (!['approve', 'reject'].includes(decision)) throw new AppError("decision must be 'approve' or 'reject'", 400, 'VALIDATION');
  const note = text(comment, 'comment');
  if (decision === 'reject' && !note) throw new AppError('A rejection needs a comment the owner can act on', 400, 'VALIDATION');
  const row = getIntake(db, app.id);
  if (!row) throw new AppError('This app has no intake to review', 404, 'NOT_FOUND');
  const status = decision === 'approve' ? 'approved' : 'rejected';
  db.prepare(`UPDATE app_intake SET status = ?, reviewed_by = ?, reviewed_at = datetime('now'), review_comment = ?,
    grandfathered = 0, updated_at = datetime('now') WHERE app_id = ?`).run(status, user.id, note, app.id);
  const updated = getIntake(db, app.id);
  logAudit(user.id, app.id, `app-intake-${status === 'approved' ? 'approve' : 'reject'}`, { comment: note, data_classification: updated.data_classification });
  recordEvent({
    kind: `intake.${status}`, severity: status === 'approved' ? 'info' : 'warning', appId: app.id, userId: user.id,
    summary: `Intake ${status} for production (${updated.data_classification})`,
    data: { data_classification: updated.data_classification },
  });
  notifyOwners(db, app, updated, user);
  return updated;
}

/** Approver queue. */
export function listIntake(db, { status = 'pending' } = {}) {
  const where = status === 'all' ? '' : 'WHERE i.status = ?';
  const args = status === 'all' ? [] : [status];
  return db.prepare(`
    SELECT i.*, a.slug, a.name, a.source_type, a.visibility, a.auth_mode, a.domain,
           su.name AS submitted_by_name, ru.name AS reviewed_by_name
    FROM app_intake i JOIN apps a ON a.id = i.app_id
    LEFT JOIN users su ON su.id = i.submitted_by
    LEFT JOIN users ru ON ru.id = i.reviewed_by
    ${where}
    ORDER BY i.submitted_at DESC, i.app_id DESC LIMIT 500
  `).all(...args).map((r) => ({ ...r, personal_data: !!r.personal_data, grandfathered: !!r.grandfathered, classification_locked: !!r.classification_locked }));
}

function send(m) {
  try {
    enqueueEmail({ ...m, source: INTAKE_MAIL_SOURCE });
    return true;
  } catch (e) {
    log.warn(`[intake] mail to ${m.to} skipped: ${e.message}`);
    return false;
  }
}

function answerLines(row) {
  return [
    `Classification: ${row.data_classification}`,
    `Purpose: ${row.purpose || '(not given)'}`,
    `Stores personal or customer data: ${row.personal_data ? 'yes' : 'no'}`,
    `External integrations: ${row.external_integrations || '(none listed)'}`,
    `Who should have access: ${row.access_notes || '(not given)'}`,
  ];
}

function notifyApprovers(db, app, row) {
  const url = `${dashboardBaseUrl()}/intake`;
  for (const a of platformAdmins(db)) {
    send({
      appId: app.id, to: a.email,
      idempotencyKey: `intake-submit:${app.id}:${row.submitted_at}:${a.id}`,
      subject: `[AppCrane] ${app.name || app.slug} needs security approval`,
      text: `${app.name || app.slug} (${app.slug}) was submitted for security approval before production.\n\n${answerLines(row).join('\n')}\n\nReview it: ${url}\n`,
      html: renderBrandedEmail({
        preheader: `${app.slug} is waiting for intake approval`,
        greeting: `Hi${a.name ? ' ' + a.name : ''},`,
        intro: `${app.name || app.slug} was submitted for security approval before production.`,
        bodyHtml: bulletList(answerLines(row)),
        cta: { label: 'Open the intake queue', url },
        footer: 'You receive this because you are a platform admin on this AppCrane instance.',
      }),
    });
  }
}

function notifyOwners(db, app, row, reviewer) {
  const approved = row.status === 'approved';
  const url = `${dashboardBaseUrl()}/app?slug=${encodeURIComponent(app.slug)}`;
  const lines = [`Decision: ${approved ? 'approved' : 'rejected'}`, `Classification: ${row.data_classification}`];
  if (row.review_comment) lines.push(`Comment: ${row.review_comment}`);
  for (const o of appOwners(db, app.id)) {
    send({
      appId: app.id, to: o.email,
      idempotencyKey: `intake-review:${app.id}:${row.status}:${row.reviewed_at}:${o.id}`,
      subject: approved
        ? `[AppCrane] ${app.name || app.slug} is approved for production`
        : `[AppCrane] ${app.name || app.slug} intake was not approved`,
      text: `Hi${o.name ? ' ' + o.name : ''},\n\n${reviewer.name || 'A platform admin'} ${approved ? 'approved' : 'rejected'} the intake for ${app.name || app.slug}.\n\n${lines.join('\n')}\n\n`
        + (approved ? 'Production deploys are open, subject to the release check.\n' : 'Update the intake and resubmit; sandbox deploys still work.\n') + url + '\n',
      html: renderBrandedEmail({
        preheader: `Intake ${approved ? 'approved' : 'rejected'} for ${app.slug}`,
        greeting: `Hi${o.name ? ' ' + o.name : ''},`,
        intro: `${reviewer.name || 'A platform admin'} ${approved ? 'approved' : 'rejected'} the intake for ${app.name || app.slug}.`,
        bodyHtml: bulletList(lines) + `<p style="margin:12px 0 0;font-size:14px;line-height:21px;">${esc(approved
          ? 'Production deploys are open, subject to the release check.'
          : 'Update the intake and resubmit; sandbox deploys still work.')}</p>`,
        cta: { label: 'Open the app', url },
        footer: 'You receive this because you own this app on AppCrane.',
      }),
    });
  }
}
