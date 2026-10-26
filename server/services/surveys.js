// In-app surveys: definitions, when one is due, answer validation and storage.
// Tables: migration 127. Results and NPS: services/surveyResults.js. Mail:
// services/surveyMail.js. HTTP: routes/surveys.js.
//
// Due (isDue): the survey is on and has questions, it targets the app, the
// person has opened the app at least min_visits times and first did so at
// least min_days ago, no "Not now" is still running, and they have not
// answered it for this app inside the current round. A round is
// frequency_days long and starts at their last answer; 0 means they are asked
// once and never again. The same round rule refuses a second answer.

import { AppError } from '../utils/errors.js';

export const KINDS = ['nps', 'scale', 'choice', 'text'];
export const DEFAULT_NPS_PROMPT = 'How likely are you to recommend {app} to a colleague?';
export const MAX_QUESTIONS = 10;
export const TEXT_CAP = 2000;
const VISIT_WINDOW_MIN = 30;

export function sqlTs(d) {
  return new Date(d).toISOString().slice(0, 19).replace('T', ' ');
}
const plusDays = (now, days) => sqlTs(new Date(now).getTime() + days * 86_400_000);
const plusMinutes = (now, m) => sqlTs(new Date(now).getTime() + m * 60_000);

function bad(message, code = 'VALIDATION') { return new AppError(message, 400, code); }

function int(v, name, min, max, fallback) {
  if (v === undefined || v === null || v === '') {
    if (fallback !== undefined) return fallback;
    throw bad(`${name} is required`);
  }
  const n = typeof v === 'string' && /^-?\d+$/.test(v.trim()) ? Number(v) : v;
  if (!Number.isInteger(n) || n < min || n > max) throw bad(`${name} must be a whole number from ${min} to ${max}`);
  return n;
}

function str(v, name, max, { required = true } = {}) {
  if (v === undefined || v === null) v = '';
  if (typeof v !== 'string') throw bad(`${name} must be text`);
  const s = v.trim();
  if (!s && required) throw bad(`${name} is required`);
  if (s.length > max) throw bad(`${name} is longer than ${max} characters`);
  return s;
}

const bool = (v, fallback) => (v === undefined ? fallback : v === true || v === 1);

function normalizeQuestion(q, i) {
  if (!q || typeof q !== 'object') throw bad(`question ${i + 1} must be an object`);
  if (!KINDS.includes(q.kind)) throw bad(`question ${i + 1}: kind must be one of ${KINDS.join(', ')}`);
  const out = {
    kind: q.kind,
    prompt: str(q.prompt ?? (q.kind === 'nps' ? DEFAULT_NPS_PROMPT : ''), `question ${i + 1} prompt`, 300),
    required: bool(q.required, true),
    scale_min: null, scale_max: null, low_label: null, high_label: null, options: null, max_length: null,
  };
  if (q.kind === 'nps') {
    out.scale_min = 0; out.scale_max = 10;
    out.low_label = str(q.low_label ?? 'Not likely', `question ${i + 1} low label`, 60, { required: false }) || null;
    out.high_label = str(q.high_label ?? 'Very likely', `question ${i + 1} high label`, 60, { required: false }) || null;
  } else if (q.kind === 'scale') {
    out.scale_min = int(q.scale_min, `question ${i + 1} lowest score`, 0, 1, 1);
    out.scale_max = int(q.scale_max, `question ${i + 1} highest score`, 2, 10, 5);
    out.low_label = str(q.low_label, `question ${i + 1} low label`, 60, { required: false }) || null;
    out.high_label = str(q.high_label, `question ${i + 1} high label`, 60, { required: false }) || null;
  } else if (q.kind === 'choice') {
    if (!Array.isArray(q.options)) throw bad(`question ${i + 1}: options must be a list`);
    const opts = q.options.map((o, j) => str(o, `question ${i + 1} option ${j + 1}`, 100));
    if (opts.length < 2 || opts.length > 10) throw bad(`question ${i + 1}: give 2 to 10 options`);
    if (new Set(opts.map((o) => o.toLowerCase())).size !== opts.length) throw bad(`question ${i + 1}: options must differ`);
    out.options = opts;
  } else {
    out.max_length = int(q.max_length, `question ${i + 1} answer length`, 1, TEXT_CAP, 1000);
  }
  return out;
}

/** Validate a survey definition from the admin UI. Throws AppError(400). */
export function normalizeSurveyInput(db, body) {
  if (!body || typeof body !== 'object') throw bad('body must be an object');
  const questions = body.questions;
  if (!Array.isArray(questions) || questions.length < 1) throw bad('a survey needs at least one question');
  if (questions.length > MAX_QUESTIONS) throw bad(`a survey has at most ${MAX_QUESTIONS} questions`);
  const qs = questions.map(normalizeQuestion);
  if (qs.filter((q) => q.kind === 'nps').length > 1) throw bad('a survey has at most one NPS question');
  const allApps = bool(body.all_apps, true);
  let appIds = [];
  if (!allApps) {
    if (!Array.isArray(body.apps) || body.apps.length === 0) throw bad('choose at least one app, or run the survey on all apps');
    const find = db.prepare('SELECT id FROM apps WHERE slug = ?');
    appIds = [...new Set(body.apps.map((slug) => {
      const row = typeof slug === 'string' ? find.get(slug) : null;
      if (!row) throw bad(`unknown app: ${String(slug).slice(0, 80)}`);
      return row.id;
    }))];
  }
  return {
    name: str(body.name, 'name', 120),
    enabled: bool(body.enabled, false),
    all_apps: allApps,
    app_ids: appIds,
    frequency_days: int(body.frequency_days, 'frequency_days', 0, 3650, 90),
    min_visits: int(body.min_visits, 'min_visits', 0, 1000, 3),
    min_days: int(body.min_days, 'min_days', 0, 3650, 0),
    snooze_days: int(body.snooze_days, 'snooze_days', 1, 365, 7),
    questions: qs,
  };
}

function writeChildren(db, id, s) {
  db.prepare('DELETE FROM survey_questions WHERE survey_id = ?').run(id);
  db.prepare('DELETE FROM survey_apps WHERE survey_id = ?').run(id);
  const insQ = db.prepare(`
    INSERT INTO survey_questions (survey_id, position, kind, prompt, required, scale_min, scale_max, low_label, high_label, options, max_length)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  s.questions.forEach((q, i) => insQ.run(id, i, q.kind, q.prompt, q.required ? 1 : 0, q.scale_min, q.scale_max,
    q.low_label, q.high_label, q.options ? JSON.stringify(q.options) : null, q.max_length));
  const insA = db.prepare('INSERT INTO survey_apps (survey_id, app_id) VALUES (?, ?)');
  for (const appId of s.app_ids) insA.run(id, appId);
}

export function createSurvey(db, input, userId) {
  return db.transaction(() => {
    const id = Number(db.prepare(`
      INSERT INTO surveys (name, enabled, all_apps, frequency_days, min_visits, min_days, snooze_days, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(input.name, input.enabled ? 1 : 0, input.all_apps ? 1 : 0, input.frequency_days,
      input.min_visits, input.min_days, input.snooze_days, userId ?? null).lastInsertRowid);
    writeChildren(db, id, input);
    return id;
  })();
}

export function updateSurvey(db, id, input) {
  return db.transaction(() => {
    const r = db.prepare(`
      UPDATE surveys SET name = ?, enabled = ?, all_apps = ?, frequency_days = ?, min_visits = ?, min_days = ?,
        snooze_days = ?, updated_at = datetime('now') WHERE id = ?
    `).run(input.name, input.enabled ? 1 : 0, input.all_apps ? 1 : 0, input.frequency_days,
      input.min_visits, input.min_days, input.snooze_days, id);
    if (!r.changes) throw new AppError('Survey not found', 404, 'NOT_FOUND');
    writeChildren(db, id, input);
  })();
}

export function deleteSurvey(db, id) {
  const r = db.prepare('DELETE FROM surveys WHERE id = ?').run(id);
  if (!r.changes) throw new AppError('Survey not found', 404, 'NOT_FOUND');
}

function questionRow(q) {
  return {
    id: q.id, kind: q.kind, prompt: q.prompt, required: q.required === 1,
    scale_min: q.scale_min, scale_max: q.scale_max, low_label: q.low_label, high_label: q.high_label,
    options: q.options ? JSON.parse(q.options) : null, max_length: q.max_length,
  };
}

export function questionsFor(db, surveyId) {
  return db.prepare('SELECT * FROM survey_questions WHERE survey_id = ? ORDER BY position, id').all(surveyId).map(questionRow);
}

export function getSurvey(db, id) {
  const s = db.prepare('SELECT * FROM surveys WHERE id = ?').get(id);
  if (!s) return null;
  const apps = db.prepare(`
    SELECT a.slug, a.name FROM survey_apps sa JOIN apps a ON a.id = sa.app_id WHERE sa.survey_id = ? ORDER BY a.name
  `).all(id);
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM survey_responses WHERE survey_id = ?').get(id);
  return {
    id: s.id, name: s.name, enabled: s.enabled === 1, all_apps: s.all_apps === 1,
    apps, frequency_days: s.frequency_days, min_visits: s.min_visits, min_days: s.min_days,
    snooze_days: s.snooze_days, created_at: s.created_at, updated_at: s.updated_at,
    responses: n, questions: questionsFor(db, id),
  };
}

export function listSurveys(db) {
  return db.prepare('SELECT id FROM surveys ORDER BY id').all().map((r) => getSurvey(db, r.id));
}

/** Platform admins open every app; everyone else needs an assignment. */
export function userCanOpenApp(db, user, app) {
  if (!user || !app) return false;
  if (user.role === 'platform_admin') return true;
  return !!db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
}

export function isHuman(user) {
  return !!user && (user.kind ?? 'human') === 'human';
}

/** Count one visit per person per app per 30 minutes. */
export function recordVisit(db, userId, appId, now = new Date()) {
  const ts = sqlTs(now);
  const row = db.prepare('SELECT last_counted_at FROM survey_app_visits WHERE user_id = ? AND app_id = ?').get(userId, appId);
  if (!row) {
    db.prepare('INSERT INTO survey_app_visits (user_id, app_id, first_seen_at, last_counted_at, visit_count) VALUES (?, ?, ?, ?, 1)')
      .run(userId, appId, ts, ts);
  } else if (row.last_counted_at <= plusMinutes(now, -VISIT_WINDOW_MIN)) {
    db.prepare('UPDATE survey_app_visits SET visit_count = visit_count + 1, last_counted_at = ? WHERE user_id = ? AND app_id = ?')
      .run(ts, userId, appId);
  }
}

export function targetsApp(db, survey, appId) {
  if (survey.all_apps === 1 || survey.all_apps === true) return true;
  return !!db.prepare('SELECT 1 FROM survey_apps WHERE survey_id = ? AND app_id = ?').get(survey.id, appId);
}

function lastAnswer(db, surveyId, appId, userId) {
  return db.prepare(`
    SELECT submitted_at FROM survey_responses WHERE survey_id = ? AND app_id = ? AND user_id = ?
    ORDER BY submitted_at DESC, id DESC LIMIT 1
  `).get(surveyId, appId, userId);
}

/** True when the person already answered in the current round. */
export function answeredThisRound(db, survey, appId, userId, now = new Date()) {
  const last = lastAnswer(db, survey.id, appId, userId);
  if (!last) return false;
  if (survey.frequency_days === 0) return true;
  return last.submitted_at > plusDays(now, -survey.frequency_days);
}

/** Why the survey is or is not due for this person on this app ('due' when it is). */
export function dueReason(db, survey, userId, appId, now = new Date()) {
  if (survey.enabled !== 1) return 'off';
  if (!targetsApp(db, survey, appId)) return 'not-targeted';
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM survey_questions WHERE survey_id = ?').get(survey.id);
  if (!n) return 'no-questions';
  const v = db.prepare('SELECT first_seen_at, visit_count FROM survey_app_visits WHERE user_id = ? AND app_id = ?').get(userId, appId);
  if ((v?.visit_count ?? 0) < survey.min_visits) return 'too-few-visits';
  if (survey.min_days > 0 && (!v || v.first_seen_at > plusDays(now, -survey.min_days))) return 'too-new';
  const snooze = db.prepare('SELECT snoozed_until FROM survey_snoozes WHERE survey_id = ? AND user_id = ? AND app_id = ?')
    .get(survey.id, userId, appId);
  if (snooze && snooze.snoozed_until > sqlTs(now)) return 'snoozed';
  if (answeredThisRound(db, survey, appId, userId, now)) return 'answered';
  return 'due';
}

function forDisplay(db, survey, app) {
  return {
    id: survey.id,
    name: survey.name,
    questions: questionsFor(db, survey.id).map((q) => ({ ...q, prompt: q.prompt.replaceAll('{app}', app.name) })),
  };
}

/**
 * The survey to show this person on this app now, or null. Counts the visit
 * first. Agents are never surveyed. The caller checks the person may open the app.
 */
export function pendingSurvey(db, user, app, now = new Date()) {
  if (!isHuman(user)) return null;
  recordVisit(db, user.id, app.id, now);
  const surveys = db.prepare('SELECT * FROM surveys ORDER BY id').all();
  for (const s of surveys) {
    if (dueReason(db, s, user.id, app.id, now) === 'due') return forDisplay(db, s, app);
  }
  return null;
}

export function snoozeSurvey(db, survey, userId, appId, now = new Date()) {
  const until = plusDays(now, survey.snooze_days || 1);
  db.prepare(`
    INSERT INTO survey_snoozes (survey_id, user_id, app_id, snoozed_until) VALUES (?, ?, ?, ?)
    ON CONFLICT(survey_id, user_id, app_id) DO UPDATE SET snoozed_until = excluded.snoozed_until
  `).run(survey.id, userId, appId, until);
  return until;
}

/**
 * Check answers against the questions. `input` maps question id to value.
 * Scores must be whole numbers in range (strings are refused), a choice must
 * be one of the options, text is trimmed and refused past its cap.
 * @returns {{ answers: Array<{question_id:number, kind:string, prompt:string, value:number|string}>, nps: number|null }}
 */
export function validateAnswers(questions, input, appName = '') {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw bad('answers must be an object keyed by question id');
  const known = new Set(questions.map((q) => String(q.id)));
  for (const k of Object.keys(input)) if (!known.has(k)) throw bad(`unknown question: ${k.slice(0, 40)}`);
  const answers = [];
  let nps = null;
  for (const q of questions) {
    const label = `"${q.prompt.slice(0, 60)}"`;
    let v = input[String(q.id)];
    if (typeof v === 'string' && q.kind !== 'choice') v = q.kind === 'text' ? v.trim() : v;
    if (v === undefined || v === null || v === '') {
      if (q.required) throw bad(`${label} needs an answer`);
      continue;
    }
    if (q.kind === 'nps' || q.kind === 'scale') {
      if (typeof v !== 'number' || !Number.isInteger(v) || v < q.scale_min || v > q.scale_max) {
        throw bad(`${label} takes a whole number from ${q.scale_min} to ${q.scale_max}`);
      }
      if (q.kind === 'nps') nps = v;
    } else if (q.kind === 'choice') {
      if (typeof v !== 'string' || !q.options.includes(v)) throw bad(`${label} takes one of the listed options`);
    } else {
      if (typeof v !== 'string') throw bad(`${label} takes text`);
      const cap = Math.min(q.max_length || TEXT_CAP, TEXT_CAP);
      if (v.length > cap) throw bad(`${label} is longer than ${cap} characters`);
    }
    answers.push({ question_id: q.id, kind: q.kind, prompt: q.prompt.replaceAll('{app}', appName), value: v });
  }
  if (!answers.length) throw bad('answer at least one question');
  return { answers, nps };
}

/**
 * Store one answer. Throws AppError for an unknown/off/untargeted survey (404),
 * an answer already given this round (409) or invalid answers (400). Mail is
 * the caller's business and runs after this returns.
 */
export function recordResponse(db, { user, app, surveyId, answers, now = new Date() }) {
  const survey = db.prepare('SELECT * FROM surveys WHERE id = ?').get(surveyId);
  if (!survey || survey.enabled !== 1 || !targetsApp(db, survey, app.id)) {
    throw new AppError('This survey is not running on this app', 404, 'NOT_FOUND');
  }
  return db.transaction(() => {
    if (answeredThisRound(db, survey, app.id, user.id, now)) {
      throw new AppError('You already answered this survey', 409, 'ALREADY_ANSWERED');
    }
    const checked = validateAnswers(questionsFor(db, survey.id), answers, app.name);
    const id = Number(db.prepare(`
      INSERT INTO survey_responses (survey_id, app_id, user_id, answers, nps_score, submitted_at) VALUES (?, ?, ?, ?, ?, ?)
    `).run(survey.id, app.id, user.id, JSON.stringify(checked.answers), checked.nps, sqlTs(now)).lastInsertRowid);
    db.prepare('DELETE FROM survey_snoozes WHERE survey_id = ? AND user_id = ? AND app_id = ?').run(survey.id, user.id, app.id);
    return { id, survey, answers: checked.answers, nps: checked.nps };
  })();
}
