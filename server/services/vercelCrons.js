// vercel.json `crons` -> AppCrane cron jobs.
//
// Vercel calls `GET <production deployment><path>` on each entry's schedule
// (UTC), sends `Authorization: Bearer <CRON_SECRET>` when the project sets
// CRON_SECRET, and does not follow redirects. An app that relied on that keeps
// working here: at deploy the release's top-level vercel.json is read and its
// crons become kind='http', origin='vercel' rows in app_cron_jobs, which
// cronScheduler.js runs against the app's own container (cronHttp.js).
//
// Only origin='vercel' rows are ever created, changed or removed by this sync.
// A malformed file changes nothing and is reported to the deploy log; it never
// fails the deploy, because the app itself deploys fine without its crons.

import { readFileSync, statSync } from 'fs';
import { join } from 'path';
import { getDb } from '../db.js';
import { regularFileInside } from '../utils/paths.js';
import { parseCron } from './cronScheduler.js';

// Vercel's own per-project limit ("Cron jobs now support 100 per project on
// every plan"), so any file that deploys on Vercel fits, and a file that would
// not is refused here too instead of filling the scheduler.
export const MAX_VERCEL_CRONS = 100;
export const VERCEL_CRON_TIMEOUT_SECONDS = 300;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_PATH_LENGTH = 512;
const CRON_FIELD_RE = /^[0-9*,/-]+$/;

export class VercelCronError extends Error {}

function fail(msg) { throw new VercelCronError(msg); }

export function validateCronPath(path) {
  if (typeof path !== 'string' || !path) fail('path must be a non-empty string');
  if (path.length > MAX_PATH_LENGTH) fail(`path is longer than ${MAX_PATH_LENGTH} characters`);
  if (!path.startsWith('/')) fail(`path "${path}" must start with "/"`);
  if (path.startsWith('//')) fail(`path "${path}" must not start with "//" (that names a host)`);
  if (/[\s\\#]/.test(path) || /[\u0000-\u001f\u007f]/.test(path)) fail(`path "${path}" contains whitespace, a backslash, "#" or a control character`);
  const pathname = path.split('?')[0];
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { fail(`path "${path}" is not valid percent-encoding`); }
  if (decoded.split('/').some((seg) => seg === '..' || seg === '.')) fail(`path "${path}" contains a "." or ".." segment`);
  const u = new URL(path, 'http://appcrane.invalid');
  if (u.host !== 'appcrane.invalid' || u.protocol !== 'http:') fail(`path "${path}" names a scheme or host`);
  return path;
}

export function validateCronSchedule(schedule) {
  if (typeof schedule !== 'string' || !schedule.trim()) fail('schedule must be a non-empty string');
  const fields = schedule.trim().split(/\s+/);
  if (fields.length !== 5) fail(`schedule "${schedule}" must have exactly 5 fields`);
  for (const f of fields) {
    if (!CRON_FIELD_RE.test(f)) fail(`schedule "${schedule}" uses "${f}"; Vercel takes numbers, "*", ",", "-" and "/" only (no MON, JAN or @daily)`);
  }
  try { parseCron(schedule); } catch (e) { fail(`schedule "${schedule}" is invalid: ${e.message}`); }
  if (fields[2] !== '*' && fields[4] !== '*') fail(`schedule "${schedule}" sets both day of month and day of week; Vercel requires one of them to be "*"`);
  return fields.join(' ');
}

/** The `crons` value of a parsed vercel.json, validated. [] when absent. Throws VercelCronError. */
export function parseVercelCrons(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) fail('vercel.json must be a JSON object');
  if (json.crons === undefined) return [];
  if (!Array.isArray(json.crons)) fail('"crons" must be an array');
  if (json.crons.length > MAX_VERCEL_CRONS) fail(`"crons" has ${json.crons.length} entries; the limit is ${MAX_VERCEL_CRONS} (Vercel's own per-project limit)`);
  const out = [];
  json.crons.forEach((c, i) => {
    if (!c || typeof c !== 'object' || Array.isArray(c)) fail(`crons[${i}] must be an object`);
    let path, schedule;
    try {
      path = validateCronPath(c.path);
      schedule = validateCronSchedule(c.schedule);
    } catch (e) { fail(`crons[${i}]: ${e.message}`); }
    out.push({ path, schedule });
  });
  const seen = new Set();
  for (const c of out) {
    const key = `${c.path} ${c.schedule}`;
    if (seen.has(key)) fail(`crons lists ${c.path} at "${c.schedule}" twice`);
    seen.add(key);
  }
  const pathCount = new Map();
  for (const c of out) pathCount.set(c.path, (pathCount.get(c.path) || 0) + 1);
  return out.map((c) => ({ ...c, name: pathCount.get(c.path) > 1 ? `vercel:${c.path} [${c.schedule}]` : `vercel:${c.path}` }));
}

/**
 * Read <releaseDir>/vercel.json. {present:false} when there is none;
 * throws VercelCronError on a link, an oversize file or bad JSON.
 */
export function readVercelJson(releaseDir) {
  const p = join(releaseDir, 'vercel.json');
  let st;
  try { st = statSync(p); } catch { return { present: false }; }
  if (!regularFileInside(releaseDir, p)) fail('vercel.json is a symbolic link or not a regular file');
  if (st.size > MAX_FILE_BYTES) fail(`vercel.json is ${st.size} bytes; the limit is ${MAX_FILE_BYTES}`);
  let json;
  try { json = JSON.parse(readFileSync(p, 'utf8')); } catch (e) { fail(`vercel.json is not valid JSON: ${e.message}`); }
  return { present: true, json };
}

/**
 * Make the origin='vercel' rows of (appId, env) match `crons`. Rows of any
 * other origin are never written; a name one of them holds is skipped.
 */
export function syncVercelCrons(appId, env, crons) {
  const db = getDb();
  const result = { created: [], updated: [], removed: [], skipped: [] };
  db.transaction(() => {
    const rows = db.prepare('SELECT id, name, origin, schedule, http_path FROM app_cron_jobs WHERE app_id = ? AND env = ?').all(appId, env);
    const byName = new Map(rows.map((r) => [r.name, r]));
    const keep = new Set();
    for (const c of crons) {
      const row = byName.get(c.name);
      if (row && row.origin !== 'vercel') { result.skipped.push(c.name); continue; }
      keep.add(c.name);
      if (!row) {
        db.prepare(`INSERT INTO app_cron_jobs (app_id, env, name, schedule, command, enabled, timeout_seconds, kind, origin, http_path)
                    VALUES (?, ?, ?, ?, ?, 1, ?, 'http', 'vercel', ?)`)
          .run(appId, env, c.name, c.schedule, `GET ${c.path}`, VERCEL_CRON_TIMEOUT_SECONDS, c.path);
        result.created.push(c.name);
      } else if (row.schedule !== c.schedule || row.http_path !== c.path) {
        db.prepare(`UPDATE app_cron_jobs SET schedule = ?, http_path = ?, command = ?, updated_at = datetime('now') WHERE id = ? AND origin = 'vercel'`)
          .run(c.schedule, c.path, `GET ${c.path}`, row.id);
        result.updated.push(c.name);
      }
    }
    for (const r of rows) {
      if (r.origin === 'vercel' && !keep.has(r.name)) {
        db.prepare("DELETE FROM app_cron_jobs WHERE id = ? AND origin = 'vercel'").run(r.id);
        result.removed.push(r.name);
      }
    }
  })();
  return result;
}

/**
 * Deploy-time entry point. Returns the deploy-log lines; never throws for a
 * bad file. `releaseDir` null (an image deploy) means there is no vercel.json.
 */
export function syncVercelCronsForRelease(appId, env, releaseDir) {
  let crons;
  try {
    const file = releaseDir ? readVercelJson(releaseDir) : { present: false };
    crons = file.present ? parseVercelCrons(file.json) : [];
  } catch (e) {
    if (!(e instanceof VercelCronError)) throw e;
    return [`WARNING: vercel.json crons NOT synced (deploy continues, existing vercel.json jobs left as they were): ${e.message}`];
  }
  const r = syncVercelCrons(appId, env, crons);
  const lines = [];
  if (crons.length) lines.push(`vercel.json crons: ${crons.length} declared, ${r.created.length} created, ${r.updated.length} updated, ${r.removed.length} removed`);
  else if (r.removed.length) lines.push(`vercel.json crons: none declared, ${r.removed.length} removed`);
  for (const n of r.skipped) lines.push(`WARNING: vercel.json cron ${n} skipped: a deployhub.json cron job already has that name`);
  return lines;
}
