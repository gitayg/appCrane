import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';
import {
  normalizeSurveyInput, createSurvey, updateSurvey, deleteSurvey, getSurvey, listSurveys,
  userCanOpenApp, isHuman, pendingSurvey, snoozeSurvey, recordResponse, targetsApp,
} from '../services/surveys.js';
import { surveyResults, surveyResponses, responsesCsv } from '../services/surveyResults.js';
import { queueSurveyResponseMail } from '../services/surveyMail.js';

/**
 * In-app surveys (NPS). Rules: services/surveys.js; results: surveyResults.js;
 * mail: surveyMail.js.
 *
 *   GET    /api/surveys/pending?app=<slug>   the caller's due survey for an app they can open, or null
 *   POST   /api/surveys/:id/responses        { app, answers } -- one per round, needs the app
 *   POST   /api/surveys/:id/snooze           { app } -- "Not now"
 *   GET    /api/surveys/results              NPS summary (platform admin: all; owner: own apps)
 *   GET    /api/surveys/responses[.csv]      the answers behind it, same scope
 *   GET/POST/PUT/DELETE /api/surveys/admin   survey definitions, platform admin only
 *
 * The app is named in the query or body, never a :slug route param, and each
 * handler checks the caller against THAT app (userCanOpenApp, or the
 * owner/platform-admin scope in surveyResults.resolveFilter).
 */
const router = Router();
router.use(requireAuth);

// Exported so a test can swap the queue for one that throws.
export const mailer = { queue: queueSurveyResponseMail };

function appFor(db, user, slug) {
  if (!slug || typeof slug !== 'string') throw new AppError('app is required', 400, 'VALIDATION');
  const app = db.prepare('SELECT id, slug, name FROM apps WHERE slug = ?').get(slug);
  if (!app) throw new AppError('App not found', 404, 'NOT_FOUND');
  if (!userCanOpenApp(db, user, app)) throw new AppError('You do not have access to this app', 403, 'FORBIDDEN');
  return app;
}

function surveyId(raw) {
  const id = Number(raw);
  if (!Number.isInteger(id) || id <= 0) throw new AppError('Survey not found', 404, 'NOT_FOUND');
  return id;
}

router.get('/pending', (req, res) => {
  const db = getDb();
  const app = appFor(db, req.user, req.query.app);
  res.json({ survey: pendingSurvey(db, req.user, app), app: { slug: app.slug, name: app.name } });
});

router.post('/:id/responses', (req, res) => {
  const db = getDb();
  if (!isHuman(req.user)) throw new AppError('Only people answer surveys', 403, 'FORBIDDEN');
  const app = appFor(db, req.user, req.body?.app);
  const r = recordResponse(db, { user: req.user, app, surveyId: surveyId(req.params.id), answers: req.body?.answers });
  let mail = { sent: 0, skipped: 0 };
  try {
    mail = mailer.queue({
      db, app, survey: r.survey, respondent: { name: req.user.name, email: req.user.email },
      responseId: r.id, answers: r.answers, nps: r.nps,
    });
  } catch (e) {
    log.warn(`[survey-mail] ${app.slug} response ${r.id}: not queued: ${e.message}`);
  }
  res.status(201).json({ id: r.id, mail_queued: mail.sent });
});

router.post('/:id/snooze', (req, res) => {
  const db = getDb();
  const app = appFor(db, req.user, req.body?.app);
  const survey = db.prepare('SELECT * FROM surveys WHERE id = ?').get(surveyId(req.params.id));
  if (!survey || !targetsApp(db, survey, app.id)) throw new AppError('Survey not found', 404, 'NOT_FOUND');
  res.json({ snoozed_until: snoozeSurvey(db, survey, req.user.id, app.id) });
});

router.get('/results', (req, res) => {
  res.json(surveyResults(getDb(), req.user, req.query));
});

router.get('/responses', (req, res) => {
  res.json({ responses: surveyResponses(getDb(), req.user, req.query) });
});

router.get('/responses.csv', (req, res) => {
  const rows = surveyResponses(getDb(), req.user, req.query, 10_000);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="survey-responses.csv"');
  res.send(responsesCsv(rows));
});

router.get('/admin', requirePlatformAdmin, (req, res) => {
  res.json({ surveys: listSurveys(getDb()) });
});

router.post('/admin', requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const id = createSurvey(db, normalizeSurveyInput(db, req.body), req.user.id);
  logAudit(req.user.id, null, 'survey.create', { survey_id: id });
  res.status(201).json({ survey: getSurvey(db, id) });
});

router.put('/admin/:id', requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const id = surveyId(req.params.id);
  updateSurvey(db, id, normalizeSurveyInput(db, req.body));
  logAudit(req.user.id, null, 'survey.update', { survey_id: id });
  res.json({ survey: getSurvey(db, id) });
});

router.delete('/admin/:id', requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const id = surveyId(req.params.id);
  deleteSurvey(db, id);
  logAudit(req.user.id, null, 'survey.delete', { survey_id: id });
  res.json({ ok: true });
});

export default router;
