// The intake "AI use" answer per app (migration 180, app_ai_profile).
//
//   none                    the app does not use AI
//   assistive               AI helps a person who makes the decision
//   decisions_about_people  the app's AI output decides something about people
//   annex_iii               a use listed in Annex III of Regulation (EU) 2024/1689
//
// An Annex III answer needs a platform admin's intake approval before
// production, like a confidential app, and the release check runs at least at
// the confidential level's policy (see approvalRequiredForAi, releaseCheckLevel).
// A platform admin's answer locks it against owners, and an owner lowering the
// answer sends the intake back to a platform admin before production reopens.

import { AppError } from '../../utils/errors.js';
import { isPlatformAdmin } from '../../utils/roles.js';
import { roleForUserOnApp } from '../permissions.js';
import { logAudit } from '../../middleware/audit.js';
import { recordEvent } from '../eventStore.js';
import { assertAcknowledged } from './literacy.js';

export const AI_USES = Object.freeze(['none', 'assistive', 'decisions_about_people', 'annex_iii']);
export const AI_USING = Object.freeze(['assistive', 'decisions_about_people', 'annex_iii']);
const aiRank = (u) => AI_USES.indexOf(u);

export const ANNEX_III_CATEGORIES = Object.freeze([
  { id: 'biometrics', label: 'Biometrics' },
  { id: 'critical_infrastructure', label: 'Critical infrastructure' },
  { id: 'education', label: 'Education and vocational training' },
  { id: 'employment', label: "Employment, workers' management and access to self-employment" },
  { id: 'essential_services', label: 'Access to and enjoyment of essential private services and essential public services and benefits' },
  { id: 'law_enforcement', label: 'Law enforcement' },
  { id: 'migration', label: 'Migration, asylum and border control management' },
  { id: 'justice_democracy', label: 'Administration of justice and democratic processes' },
]);
const CATEGORY_IDS = ANNEX_III_CATEGORIES.map((c) => c.id);

export const AI_USE_GUIDANCE = Object.freeze({
  decisions_about_people: 'This app makes decisions about people with AI. AppCrane records this answer; it does not check the app. '
    + 'If the use falls under an Annex III area (for example employment, education or access to essential services), choose that answer instead: it closes production until a platform admin approves. '
    + 'The transparency notice below can tell users that they are interacting with an AI system.',
  annex_iii: 'An Annex III use: production stays closed until a platform admin approves the intake, and the release check runs at least at the confidential level. '
    + 'AppCrane keeps this app\'s LLM gateway logs at least six months.',
});

export const usesAi = (aiUse) => AI_USING.includes(aiUse);

export function getAiProfile(db, appId) {
  const row = db.prepare('SELECT * FROM app_ai_profile WHERE app_id = ?').get(appId);
  return {
    ai_use: row?.ai_use ?? null,
    annex_iii_category: row?.annex_iii_category ?? null,
    ai_use_set_by: row?.ai_use_set_by ?? null,
    ai_use_set_at: row?.ai_use_set_at ?? null,
    locked: !!row?.ai_use_locked,
    review_required: !!row?.ai_review_required,
    uses_ai: usesAi(row?.ai_use),
    guidance: AI_USE_GUIDANCE[row?.ai_use] || null,
  };
}

const isAnnexIii = (db, appId) => db.prepare("SELECT 1 FROM app_ai_profile WHERE app_id = ? AND ai_use = 'annex_iii'").get(appId) != null;

/** True when the app's AI use alone needs a platform admin's intake approval: Annex III, or an owner lowered the answer. */
export function approvalRequiredForAi(db, appId) {
  return db.prepare("SELECT 1 FROM app_ai_profile WHERE app_id = ? AND (ai_use = 'annex_iii' OR ai_review_required = 1)").get(appId) != null;
}

/** A platform admin's intake approval covers the lowered answer. */
export function clearAiReview(db, appId) {
  db.prepare('UPDATE app_ai_profile SET ai_review_required = 0 WHERE app_id = ?').run(appId);
}

const LEVEL_ORDER = ['public', 'internal', 'confidential', 'restricted'];

/** The classification level whose release-check policy applies: Annex III raises it to at least confidential. */
export function releaseCheckLevel(db, appId, level) {
  if (!isAnnexIii(db, appId)) return level;
  return LEVEL_ORDER.indexOf(level) < LEVEL_ORDER.indexOf('confidential') ? 'confidential' : level;
}

export function normalizeAiUse(input = {}) {
  const aiUse = input.ai_use;
  if (!AI_USES.includes(aiUse)) throw new AppError(`ai_use must be one of ${AI_USES.join(', ')}`, 400, 'VALIDATION');
  const cat = input.annex_iii_category ?? null;
  if (aiUse === 'annex_iii') {
    if (!CATEGORY_IDS.includes(cat)) throw new AppError(`annex_iii_category must be one of ${CATEGORY_IDS.join(', ')}`, 400, 'VALIDATION');
    return { ai_use: aiUse, annex_iii_category: cat };
  }
  if (cat != null) throw new AppError('annex_iii_category applies only when ai_use is annex_iii', 400, 'VALIDATION');
  return { ai_use: aiUse, annex_iii_category: null };
}

/**
 * Record an app's AI-use answer. Owner or platform admin. Classifying an app
 * as using AI needs the actor's current AI-literacy acknowledgement. An owner
 * moving an approved app into Annex III sends its intake back for review; a
 * platform admin's change keeps the current status. Every change is audited.
 */
export function setAiUse(db, app, input, user) {
  const admin = isPlatformAdmin(user);
  if (!admin && roleForUserOnApp(user, app) !== 'owner') {
    throw new AppError('Only the app owner or a platform admin can set the AI use', 403, 'FORBIDDEN');
  }
  const next = normalizeAiUse(input);
  const prev = getAiProfile(db, app.id);
  const same = prev.ai_use === next.ai_use && prev.annex_iii_category === next.annex_iii_category;
  if (!admin && prev.locked && !same) {
    logAudit(user.id, app.id, 'app-ai-use-change-refused', { from: prev.ai_use, to: next.ai_use, reason: 'locked' });
    throw new AppError('A platform admin set the AI use; ask a platform admin to change it', 403, 'AI_USE_LOCKED');
  }
  if (usesAi(next.ai_use)) assertAcknowledged(db, user);
  if (same && !(admin && !prev.locked)) return { ...getAiProfile(db, app.id), changed: false };

  const downgrade = prev.ai_use != null && aiRank(next.ai_use) < aiRank(prev.ai_use);
  const ownerDowngrade = downgrade && !admin;
  db.prepare(`INSERT INTO app_ai_profile (app_id, ai_use, annex_iii_category, ai_use_set_by, ai_use_set_at, ai_use_locked, ai_review_required)
    VALUES (?, ?, ?, ?, datetime('now'), ?, ?)
    ON CONFLICT(app_id) DO UPDATE SET ai_use = excluded.ai_use, annex_iii_category = excluded.annex_iii_category,
      ai_use_set_by = excluded.ai_use_set_by, ai_use_set_at = excluded.ai_use_set_at,
      ai_use_locked = excluded.ai_use_locked,
      ai_review_required = CASE WHEN excluded.ai_review_required = 1 THEN 1 ELSE app_ai_profile.ai_review_required END`)
    .run(app.id, next.ai_use, next.annex_iii_category, user.id, admin ? 1 : 0, ownerDowngrade ? 1 : 0);

  let reReview = false;
  if (!admin && (ownerDowngrade || (next.ai_use === 'annex_iii' && prev.ai_use !== 'annex_iii'))) {
    reReview = db.prepare("UPDATE app_intake SET status = 'pending', updated_at = datetime('now') WHERE app_id = ? AND status = 'approved'").run(app.id).changes > 0;
    if (ownerDowngrade && !db.prepare('SELECT 1 FROM app_intake WHERE app_id = ?').get(app.id)) {
      db.prepare("INSERT INTO app_intake (app_id, status) VALUES (?, 'pending')").run(app.id);
      reReview = true;
    }
  }
  logAudit(user.id, app.id, prev.ai_use == null ? 'app-ai-use-set' : 'app-ai-use-change', {
    from: prev.ai_use, to: next.ai_use, from_category: prev.annex_iii_category, to_category: next.annex_iii_category,
    by_platform_admin: admin, locked: admin, downgrade, intake_back_to_review: reReview,
  });
  recordEvent({
    kind: 'ai_use.changed', severity: next.ai_use === 'annex_iii' ? 'warning' : 'info', appId: app.id, userId: user.id,
    summary: `AI use ${prev.ai_use == null ? 'set to' : `changed from ${prev.ai_use} to`} ${next.ai_use}${next.annex_iii_category ? ` (${next.annex_iii_category})` : ''}`,
    data: { from: prev.ai_use, to: next.ai_use, category: next.annex_iii_category },
  });
  return { ...getAiProfile(db, app.id), changed: true, intake_back_to_review: reReview };
}
