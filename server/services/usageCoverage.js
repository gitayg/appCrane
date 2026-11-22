import { parseBypassPaths } from '../utils/authBypassPaths.js';
import { getIngressForApp } from './tcpIngress.js';
import { fromSqlTime } from './envActivity.js';

// How much of an environment's traffic the activity tables can see. Requests
// are counted where Caddy's forward_auth asks /api/identity/verify, so anything
// that reaches the container another way is missing from them, and a zero
// there is not proof of no use.
//
//   none     headless (no forward_auth at all), tcp ingress (no HTTP route),
//            or nothing on record for the environment yet
//   partial  auth-bypass paths, dual ingress (its raw port), production on a
//            custom domain without AppCrane sign-in, or tracking that started
//            inside the requested range
//   full     every request passes forward_auth for the whole range

const RANK = { full: 0, partial: 1, none: 2 };

function envCoverage(db, app, env, fromDay) {
  const reasons = [];
  const add = (level, code, message, extra = {}) => reasons.push({ env, level, code, message, ...extra });
  const headless = app.auth_mode === 'headless';
  if (headless) add('none', 'headless', 'The app is headless: no request passes AppCrane sign-in, so none is counted.');
  const ingress = getIngressForApp(db, app.id).ingress_type;
  if (ingress === 'tcp') add('none', 'tcp', 'The app is served on a raw TCP port that bypasses AppCrane.');
  if (ingress === 'dual') add('partial', 'tcp', 'Traffic on the app\'s raw TCP port bypasses AppCrane and is not counted.');
  if (!headless && parseBypassPaths(app.auth_bypass_paths, () => {}).length) {
    add('partial', 'bypass_paths', 'Requests to the app\'s auth-bypass paths are not counted.');
  }
  if (env === 'production' && (app.domain || '').trim() && !(app.custom_domain_auth && !headless)) {
    add('partial', 'custom_domain', 'Production requests on the custom domain do not pass AppCrane sign-in and are not counted.');
  }
  const row = db.prepare('SELECT tracking_since FROM env_activity_last WHERE app_id = ? AND env = ?').get(app.id, env);
  const since = fromSqlTime(row?.tracking_since);
  const sinceDay = since ? new Date(since).toISOString().slice(0, 10) : null;
  if (!sinceDay) add('none', 'not_tracked', 'AppCrane has no activity record for this environment yet.');
  else if (fromDay && sinceDay > fromDay) {
    add('partial', 'tracking_started', `Tracking started on ${sinceDay}; days before it read as zero.`, { tracking_since: sinceDay });
  }
  const level = reasons.reduce((l, r) => (RANK[r.level] > RANK[l] ? r.level : l), 'full');
  return { level, reasons, tracking_since: sinceDay };
}

/** { coverage, coverage_reasons, tracking_since } over one or more environments. */
export function usageCoverage(db, app, envs, fromDay = null) {
  const per = envs.map(env => envCoverage(db, app, env, fromDay));
  const levels = per.map(p => p.level);
  const coverage = levels.every(l => l === 'full') ? 'full' : levels.every(l => l === 'none') ? 'none' : 'partial';
  const days = per.map(p => p.tracking_since).filter(Boolean).sort();
  return { coverage, coverage_reasons: per.flatMap(p => p.reasons), tracking_since: days[0] || null };
}
