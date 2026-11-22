// AI-literacy acknowledgement (migration 180, ai_literacy_acks): once per user
// and statement version, before that user classifies an app as using AI.
// Changing the text means a new version, and everyone acknowledges again.

import { createHash } from 'crypto';
import { AppError } from '../../utils/errors.js';
import { logAudit } from '../../middleware/audit.js';

export const STATEMENT_VERSION = '2026-11-v1';
export const STATEMENT_TEXT = [
  'I am building or running an app that uses AI. I understand that:',
  '1. AI output can be wrong, biased or made up, and a person must check it before it is relied on.',
  '2. The people who use the app should be told that they are interacting with an AI system.',
  '3. Personal or confidential data sent to an AI model leaves the app; I send only what the app needs.',
  '4. If the app makes or supports decisions about people (for example hiring, education or access to services), I record that in the intake so it can be reviewed.',
  '5. AppCrane records which models the app calls through the LLM gateway and keeps those records as configured.',
].join('\n');
export const STATEMENT_SHA256 = createHash('sha256').update(STATEMENT_TEXT).digest('hex');

export function statement() {
  return { version: STATEMENT_VERSION, text: STATEMENT_TEXT, sha256: STATEMENT_SHA256 };
}

export function acknowledgement(db, userId, version = STATEMENT_VERSION) {
  return db.prepare('SELECT * FROM ai_literacy_acks WHERE user_id = ? AND statement_version = ?').get(userId, version) || null;
}

export function hasAcknowledged(db, userId) {
  return acknowledgement(db, userId) != null;
}

/** Throws 409 AI_LITERACY_ACK_REQUIRED, carrying the statement, when the user has not acknowledged the current version. */
export function assertAcknowledged(db, user) {
  if (hasAcknowledged(db, user.id)) return;
  const e = new AppError('Acknowledge the AI-literacy statement before classifying an app as using AI', 409, 'AI_LITERACY_ACK_REQUIRED');
  e.details = { statement: statement() };
  throw e;
}

/** Record the acknowledgement. Idempotent; `version` must be the current one. */
export function acknowledge(db, user, version) {
  if (version !== STATEMENT_VERSION) {
    throw new AppError(`The current AI-literacy statement is version ${STATEMENT_VERSION}; reload it and acknowledge that version`, 409, 'AI_LITERACY_VERSION_MISMATCH');
  }
  const existing = acknowledgement(db, user.id);
  if (existing) return { ...existing, created: false };
  db.prepare('INSERT INTO ai_literacy_acks (user_id, statement_version, statement_sha256) VALUES (?, ?, ?)')
    .run(user.id, STATEMENT_VERSION, STATEMENT_SHA256);
  logAudit(user.id, null, 'ai-literacy-acknowledge', { statement_version: STATEMENT_VERSION, statement_sha256: STATEMENT_SHA256 });
  return { ...acknowledgement(db, user.id), created: true };
}

/** True when an owner of the app, or whoever classified it, acknowledged the current version. */
export function appHasAcknowledgedOwner(db, appId) {
  return db.prepare(`SELECT 1 FROM ai_literacy_acks k WHERE k.statement_version = ? AND k.user_id IN (
      SELECT user_id FROM app_user_roles WHERE app_id = ? AND app_role = 'owner'
      UNION SELECT ai_use_set_by FROM app_ai_profile WHERE app_id = ? AND ai_use_set_by IS NOT NULL)`)
    .get(STATEMENT_VERSION, appId, appId) != null;
}
