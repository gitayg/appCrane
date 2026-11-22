// Per-app "you are interacting with an AI system" notice (migration 180).
//
// AppCrane does not rewrite app responses. When the notice is on, the app is
// told through the identity contract and renders it itself:
//   - container env at deploy: APPCRANE_AI_NOTICE=1 and APPCRANE_AI_NOTICE_TEXT
//     (takes effect on the next deploy);
//   - live: the JSON body of GET /api/identity/verify for that app carries
//     ai_notice { enabled, text }.

import { AppError } from '../../utils/errors.js';
import { logAudit } from '../../middleware/audit.js';

export const DEFAULT_NOTICE_TEXT = 'You are interacting with an AI system.';
export const MAX_NOTICE_LENGTH = 300;

export function getNotice(db, appId) {
  const row = db.prepare('SELECT notice_enabled, notice_text, notice_updated_by, notice_updated_at FROM app_ai_profile WHERE app_id = ?').get(appId);
  return {
    enabled: !!row?.notice_enabled,
    text: row?.notice_text || DEFAULT_NOTICE_TEXT,
    custom_text: !!row?.notice_text,
    updated_by: row?.notice_updated_by ?? null,
    updated_at: row?.notice_updated_at ?? null,
  };
}

export function setNotice(db, app, { enabled, text }, user) {
  if (typeof enabled !== 'boolean') throw new AppError('enabled must be true or false', 400, 'VALIDATION');
  let clean = null;
  if (text !== undefined && text !== null && text !== '') {
    if (typeof text !== 'string') throw new AppError('text must be a string', 400, 'VALIDATION');
    clean = text.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
    if (clean.length > MAX_NOTICE_LENGTH) throw new AppError(`text may be at most ${MAX_NOTICE_LENGTH} characters`, 400, 'VALIDATION');
    if (!clean) clean = null;
  }
  const before = getNotice(db, app.id);
  db.prepare(`INSERT INTO app_ai_profile (app_id, notice_enabled, notice_text, notice_updated_by, notice_updated_at)
    VALUES (?, ?, ?, ?, datetime('now'))
    ON CONFLICT(app_id) DO UPDATE SET notice_enabled = excluded.notice_enabled, notice_text = excluded.notice_text,
      notice_updated_by = excluded.notice_updated_by, notice_updated_at = excluded.notice_updated_at`)
    .run(app.id, enabled ? 1 : 0, clean, user.id);
  const after = getNotice(db, app.id);
  logAudit(user.id, app.id, 'app-ai-notice-change', { from: { enabled: before.enabled, text: before.text }, to: { enabled: after.enabled, text: after.text } });
  return after;
}

/** The identity-contract field: { enabled, text } when the notice is on, else null. */
export function noticeForIdentity(db, appId) {
  const n = getNotice(db, appId);
  return n.enabled ? { enabled: true, text: n.text } : null;
}

/** Container env vars for the notice. {} when it is off. */
export function aiNoticeEnv(db, app) {
  if (!app?.id) return {};
  const n = getNotice(db, app.id);
  return n.enabled ? { APPCRANE_AI_NOTICE: '1', APPCRANE_AI_NOTICE_TEXT: n.text } : {};
}
