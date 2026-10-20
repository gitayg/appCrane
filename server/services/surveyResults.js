// Survey results: who may see which app's answers, the NPS math, the trend
// and the response list behind the "NPS & surveys" page.
//
// NPS = % promoters (9-10) minus % detractors (0-6) of the NPS answers,
// rounded to a whole number, from -100 to 100; null when nobody answered.
// Passives (7-8) count toward the total only.
//
// Visibility: a platform admin sees every app; an app owner sees the apps
// they own; anyone else is refused.

import { AppError } from '../utils/errors.js';

export function npsOf(scores) {
  const valid = scores.filter((s) => Number.isInteger(s) && s >= 0 && s <= 10);
  const n = valid.length;
  const promoters = valid.filter((s) => s >= 9).length;
  const detractors = valid.filter((s) => s <= 6).length;
  return {
    responses: n,
    promoters,
    passives: n - promoters - detractors,
    detractors,
    nps: n === 0 ? null : Math.round(((promoters - detractors) / n) * 100),
  };
}

/** App ids the user may read results for, or 'all'. Throws 403 for neither. */
export function visibleAppIds(db, user) {
  if (user?.role === 'platform_admin') return 'all';
  const ids = db.prepare("SELECT app_id FROM app_user_roles WHERE user_id = ? AND app_role = 'owner'").all(user?.id ?? -1)
    .map((r) => r.app_id);
  if (!ids.length) throw new AppError('Survey results are for app owners and platform admins', 403, 'FORBIDDEN');
  return ids;
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Resolve the filter into SQL; an app outside the caller's view is 403. */
export function resolveFilter(db, user, { app, from, to } = {}) {
  const visible = visibleAppIds(db, user);
  const where = [];
  const args = [];
  if (app) {
    const row = db.prepare('SELECT id FROM apps WHERE slug = ?').get(String(app));
    if (!row) throw new AppError(`App '${String(app).slice(0, 80)}' not found`, 404, 'NOT_FOUND');
    if (visible !== 'all' && !visible.includes(row.id)) throw new AppError('You do not own this app', 403, 'FORBIDDEN');
    where.push('r.app_id = ?'); args.push(row.id);
  } else if (visible !== 'all') {
    where.push(`r.app_id IN (${visible.map(() => '?').join(',')})`); args.push(...visible);
  }
  if (from) {
    if (!DATE_RE.test(String(from))) throw new AppError('from must be YYYY-MM-DD', 400, 'VALIDATION');
    where.push('r.submitted_at >= ?'); args.push(`${from} 00:00:00`);
  }
  if (to) {
    if (!DATE_RE.test(String(to))) throw new AppError('to must be YYYY-MM-DD', 400, 'VALIDATION');
    where.push('r.submitted_at <= ?'); args.push(`${to} 23:59:59`);
  }
  return { sql: where.length ? `WHERE ${where.join(' AND ')}` : '', args };
}

function weekStart(ts) {
  const d = new Date(`${ts.slice(0, 10)}T00:00:00Z`);
  const back = (d.getUTCDay() + 6) % 7;
  d.setUTCDate(d.getUTCDate() - back);
  return d.toISOString().slice(0, 10);
}

export function bucketOf(ts, bucket) {
  return bucket === 'week' ? weekStart(ts) : ts.slice(0, 7);
}

export function surveyResults(db, user, query = {}) {
  const bucket = query.bucket === 'week' ? 'week' : 'month';
  const { sql, args } = resolveFilter(db, user, query);
  const rows = db.prepare(`
    SELECT r.app_id, r.nps_score, r.submitted_at, a.slug, a.name
    FROM survey_responses r JOIN apps a ON a.id = r.app_id ${sql}
    ORDER BY r.submitted_at
  `).all(...args);

  const scores = rows.map((r) => r.nps_score).filter((s) => s !== null);
  const distribution = Array.from({ length: 11 }, (_, score) => ({ score, count: 0 }));
  for (const s of scores) distribution[s].count++;

  const byApp = new Map();
  const byPeriod = new Map();
  for (const r of rows) {
    if (!byApp.has(r.app_id)) byApp.set(r.app_id, { slug: r.slug, name: r.name, total: 0, scores: [] });
    const a = byApp.get(r.app_id);
    a.total++;
    if (r.nps_score !== null) a.scores.push(r.nps_score);
    const p = bucketOf(r.submitted_at, bucket);
    if (!byPeriod.has(p)) byPeriod.set(p, { total: 0, scores: [] });
    const b = byPeriod.get(p);
    b.total++;
    if (r.nps_score !== null) b.scores.push(r.nps_score);
  }

  return {
    bucket,
    overall: { total: rows.length, ...npsOf(scores) },
    apps: [...byApp.values()].map((a) => ({ slug: a.slug, name: a.name, total: a.total, ...npsOf(a.scores) }))
      .sort((x, y) => y.total - x.total),
    trend: [...byPeriod.entries()].map(([period, b]) => ({ period, total: b.total, ...npsOf(b.scores) })),
    distribution,
  };
}

export function surveyResponses(db, user, query = {}, limit = 500) {
  const { sql, args } = resolveFilter(db, user, query);
  return db.prepare(`
    SELECT r.id, r.submitted_at, r.nps_score, r.answers, a.slug AS app_slug, a.name AS app_name,
           s.name AS survey_name, u.name AS user_name, u.email AS user_email
    FROM survey_responses r
    JOIN apps a ON a.id = r.app_id
    JOIN surveys s ON s.id = r.survey_id
    LEFT JOIN users u ON u.id = r.user_id
    ${sql}
    ORDER BY r.submitted_at DESC, r.id DESC LIMIT ?
  `).all(...args, limit).map((r) => ({ ...r, answers: JSON.parse(r.answers) }));
}

function csvCell(v) {
  let s = v === null || v === undefined ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function responsesCsv(rows) {
  const head = ['submitted_at', 'app', 'survey', 'user', 'email', 'nps', 'answers'];
  const lines = [head.join(',')];
  for (const r of rows) {
    const answers = r.answers.map((a) => `${a.prompt}: ${a.value}`).join(' | ');
    lines.push([r.submitted_at, r.app_slug, r.survey_name, r.user_name, r.user_email, r.nps_score, answers].map(csvCell).join(','));
  }
  return lines.join('\r\n') + '\r\n';
}
