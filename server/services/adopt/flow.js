import crypto from 'crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../../db.js';
import { appUrl, isolationEnabled } from '../appOrigin.js';
import { logAudit } from '../../middleware/audit.js';
import { encrypt } from '../encryption.js';
import { userHasPlatformPermission } from '../permissions.js';
import { isEnvFilePath } from '../envFilePushGuard.js';
import { slugRefusal, slugTakenRefusal } from '../../utils/slugPolicy.js';
import log from '../../utils/logger.js';
import { readProjectZip } from './archive.js';
import { buildReport, scaffoldFor, uploadedEnvValues } from './report.js';
import { downloadGithubZip, parseRepoUrl, SourceError } from './sources.js';

// Analyse a project, then adopt it: a Crane-hosted app with the code in its
// local repository, the env vars the user filled in (sandbox only, encrypted),
// a first deploy to SANDBOX, the intake record and, optionally, a request per
// change the report asked for. Production is never touched: the stage is
// refused unless it is 'sandbox', and the app's push-to-deploy is set to
// sandbox only before the first commit.

export class AdoptError extends Error {
  constructor(code, message, status = 400, extra = {}) {
    super(message);
    this.code = code;
    this.statusCode = status;
    Object.assign(this, extra);
  }
}

const TTL_HOURS = 24;
const ENV_KEY_RE = /^[A-Z_][A-Z0-9_]*$/i;
const MAX_ENV_VALUE = 64 * 1024;
const RESERVED_ENV = new Set(['PORT', 'NODE_ENV', 'DATA_DIR', 'CRANE_URL', 'CRANE_INTERNAL_URL', 'APP_BASE_PATH', 'FE_PORT']);
export const ADOPT_REQUESTER = 'AppCrane adoption';

const stagingDir = () => resolve(join(process.env.DATA_DIR || './data', 'adopt'));
const stagingPath = (id) => join(stagingDir(), `${id}.zip`);
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

export function assertMayAdopt(user) {
  if (!userHasPlatformPermission(user, 'platform.create_app')) {
    throw new AdoptError('FORBIDDEN', 'You do not have permission to create apps, so you cannot adopt one.', 403);
  }
}

function sweepExpired(db) {
  const rows = db.prepare("SELECT id FROM app_adoptions WHERE status IN ('analyzed', 'failed') AND expires_at < datetime('now')").all();
  for (const r of rows) {
    try { rmSync(stagingPath(r.id), { force: true }); } catch (_) {}
  }
  if (rows.length) db.prepare("DELETE FROM app_adoptions WHERE status IN ('analyzed', 'failed') AND expires_at < datetime('now')").run();
}

async function tokenForRepo(user, src) {
  if (src.github_token) return String(src.github_token).trim();
  if (!src.use_github_app) return null;
  if (user.role !== 'platform_admin') {
    throw new SourceError('FORBIDDEN', "Reading a repository through this AppCrane's GitHub App is limited to platform admins. Supply your own GitHub token instead.", 403);
  }
  const { findInstallationForRepo, getInstallationToken } = await import('../githubApp.js');
  const { installationId } = await findInstallationForRepo(src.owner, src.repo);
  return getInstallationToken(installationId, { repositories: [src.repo] });
}

function defaultName(label) {
  const base = String(label || 'app').split('@')[0].split('/').pop().replace(/\.zip$/i, '');
  return base.replace(/[^A-Za-z0-9 _-]/g, ' ').trim().slice(0, 60) || 'app';
}

export function suggestSlug(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'app';
}

/**
 * source: { kind: 'github', url, ref?, github_token?, use_github_app? }
 *       | { kind: 'zip', buffer, filename? }
 */
export async function analyzeSource(user, source, { fetchZip = downloadGithubZip } = {}) {
  assertMayAdopt(user);
  const db = getDb();
  let buffer;
  let label;
  if (source?.kind === 'github') {
    const repo = parseRepoUrl(source.url, source.ref);
    const token = await tokenForRepo(user, { ...source, ...repo });
    buffer = await fetchZip(repo, token);
    label = repo.label;
  } else if (source?.kind === 'zip') {
    buffer = source.buffer;
    label = String(source.filename || 'upload.zip').replace(/[^A-Za-z0-9._ -]/g, '').slice(0, 120) || 'upload.zip';
  } else {
    throw new AdoptError('VALIDATION', "source.kind must be 'github' or 'zip'.");
  }

  const { files, skipped } = readProjectZip(buffer);
  const name = defaultName(label);
  const report = buildReport(files, { name, skipped });

  sweepExpired(db);
  const id = crypto.randomBytes(16).toString('base64url');
  mkdirSync(stagingDir(), { recursive: true, mode: 0o700 });
  writeFileSync(stagingPath(id), buffer, { mode: 0o600 });
  chmodSync(stagingPath(id), 0o600);
  db.prepare(`
    INSERT INTO app_adoptions (id, user_id, source_kind, source_label, source_sha256, report_json, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now', ?))
  `).run(id, user.id, source.kind, label, sha256(buffer), JSON.stringify(report), `+${TTL_HOURS} hours`);
  logAudit(user.id, null, 'app-adopt-analyze', { adoption_id: id, source_kind: source.kind, source: label, framework: report.project.framework, origin: report.project.origin.tool, verdict: report.verdict, risks: report.risk_counts });
  return { id, source: { kind: source.kind, label }, suggested: { name, slug: suggestSlug(name) }, report };
}

export function getAdoption(user, id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{10,64}$/.test(id)) throw new AdoptError('NOT_FOUND', 'No such adoption.', 404);
  const row = getDb().prepare('SELECT * FROM app_adoptions WHERE id = ?').get(id);
  if (!row || (row.user_id !== user.id && user.role !== 'platform_admin')) throw new AdoptError('NOT_FOUND', 'No such adoption.', 404);
  return row;
}

export function adoptionView(row) {
  return {
    id: row.id, status: row.status, source: { kind: row.source_kind, label: row.source_label },
    report: JSON.parse(row.report_json), app_id: row.app_id, error: row.error,
    created_at: row.created_at, expires_at: row.expires_at, adopted_at: row.adopted_at,
  };
}

async function createManagedApp(user, { name, slug, description }) {
  const { callTool } = await import('../mcpTools.js');
  const r = await callTool(user, 'appcrane_create_managed_app', { name, slug, ...(description ? { description } : {}) });
  return JSON.parse(r.content[0].text);
}

function setSandboxEnv(db, appId, userId, vars) {
  const upsert = db.prepare(`
    INSERT INTO env_vars (app_id, env, key, value_encrypted, updated_by, updated_at)
    VALUES (?, 'sandbox', ?, ?, ?, datetime('now'))
    ON CONFLICT(app_id, env, key) DO UPDATE SET
      value_encrypted = excluded.value_encrypted, updated_by = excluded.updated_by, updated_at = excluded.updated_at
  `);
  db.transaction(() => {
    for (const [k, v] of Object.entries(vars)) upsert.run(appId, k, encrypt(String(v)), userId);
  })();
}

function requestMessage(app, item) {
  return [
    item.title,
    '',
    `Found when ${app.slug} was adopted into AppCrane.`,
    '',
    item.detail,
  ].join('\n');
}

async function submitIntakeGuarded(app, intake, userId, injected) {
  let mod;
  try { mod = injected ? { submitIntake: injected } : await import('../appIntake.js'); } catch (e) {
    return { submitted: false, skipped: true, reason: `intake module unavailable: ${e.message}` };
  }
  if (typeof mod.submitIntake !== 'function') return { submitted: false, skipped: true, reason: 'submitIntake is not exported' };
  try {
    const result = await mod.submitIntake(app, { ...intake, submitted_by: userId });
    return { submitted: true, result };
  } catch (e) {
    return { submitted: false, skipped: /not implemented/i.test(e.message), reason: e.message };
  }
}

function cleanIntake(raw, user) {
  const i = raw && typeof raw === 'object' ? raw : {};
  const str = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : undefined);
  const answers = i.intake_answers && typeof i.intake_answers === 'object' ? i.intake_answers : {};
  return {
    purpose: str(i.purpose, 2000),
    data_classification: str(i.data_classification, 40),
    owner: Number.isInteger(i.owner) ? i.owner : user.id,
    intake_answers: {
      ...(typeof answers.personal_data === 'boolean' ? { personal_data: answers.personal_data } : {}),
      ...(str(answers.external_integrations, 2000) !== undefined ? { external_integrations: str(answers.external_integrations, 2000) } : {}),
      ...(str(answers.access, 200) !== undefined ? { access: str(answers.access, 200) } : {}),
    },
  };
}

/**
 * opts: { id, name, slug, description?, stage, env_vars?, intake?, open_requests?, acknowledge_risks? }
 */
export async function adoptAnalyzed(user, opts, deps = {}) {
  const stage = opts?.stage ?? 'sandbox';
  if (stage !== 'sandbox') {
    throw new AdoptError('PRODUCTION_REFUSED', 'Adoption deploys to the sandbox only. Promote to production from the app once the sandbox works and the intake is approved.', 400);
  }
  assertMayAdopt(user);
  const db = getDb();
  const row = getAdoption(user, opts.id);
  if (row.user_id !== user.id) throw new AdoptError('FORBIDDEN', 'Only the person who analysed this project can adopt it.', 403);
  if (row.status !== 'analyzed') throw new AdoptError('ALREADY_ADOPTED', `This analysis is ${row.status}; analyse the project again to adopt it.`, 409);

  const name = String(opts.name || '').trim().slice(0, 100);
  const slug = String(opts.slug || '').trim();
  if (!name || !slug) throw new AdoptError('VALIDATION', 'name and slug are required.');
  const slugProblem = slugRefusal(slug, user);
  if (slugProblem) throw new AdoptError('VALIDATION', slugProblem);
  const taken = slugTakenRefusal(db, slug);
  if (taken) throw new AdoptError('DUPLICATE', taken, 409);

  const supplied = opts.env_vars && typeof opts.env_vars === 'object' ? opts.env_vars : {};
  for (const [k, v] of Object.entries(supplied)) {
    if (!ENV_KEY_RE.test(k)) throw new AdoptError('VALIDATION', `Invalid env var name: ${k}`);
    if (RESERVED_ENV.has(k.toUpperCase())) throw new AdoptError('VALIDATION', `${k} is set by AppCrane and cannot be supplied.`);
    if (typeof v !== 'string' || v.length > MAX_ENV_VALUE) throw new AdoptError('VALIDATION', `The value for ${k} must be a string of at most ${MAX_ENV_VALUE} characters.`);
  }

  const report = JSON.parse(row.report_json);
  if (report.risk_counts?.critical && opts.acknowledge_risks !== true) {
    throw new AdoptError('RISKS_NOT_ACKNOWLEDGED',
      `The analysis found ${report.risk_counts.critical} critical risk(s). Rotate the exposed credentials, then adopt again with acknowledge_risks: true.`, 409);
  }

  if (!existsSync(stagingPath(row.id))) throw new AdoptError('EXPIRED', 'The analysed project is no longer staged; analyse it again.', 410);
  const buffer = readFileSync(stagingPath(row.id));
  if (sha256(buffer) !== row.source_sha256) throw new AdoptError('STAGING_MISMATCH', 'The staged project changed since it was analysed; analyse it again.', 409);
  const claimed = db.prepare("UPDATE app_adoptions SET status = 'adopting' WHERE id = ? AND status = 'analyzed'").run(row.id);
  if (claimed.changes !== 1) throw new AdoptError('ALREADY_ADOPTED', 'This analysis is already being adopted.', 409);

  let app = null;
  try {
    const { files } = readProjectZip(buffer);
    const scaffold = scaffoldFor(files, name);
    const fromUpload = uploadedEnvValues(files);
    const envVars = {};
    for (const [k, v] of Object.entries(fromUpload)) if (ENV_KEY_RE.test(k) && !RESERVED_ENV.has(k.toUpperCase())) envVars[k] = v;
    for (const [k, v] of Object.entries(supplied)) if (v !== '') envVars[k] = v;

    await createManagedApp(user, { name, slug, description: String(opts.description || `Adopted from ${row.source_label}`).slice(0, 500) });
    app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
    db.prepare('UPDATE app_adoptions SET app_id = ? WHERE id = ?').run(app.id, row.id);

    db.prepare('UPDATE webhook_configs SET auto_deploy_prod = 0, auto_deploy_sandbox = 1 WHERE app_id = ?').run(app.id);

    const envKeys = Object.keys(envVars).sort();
    if (envKeys.length) {
      setSandboxEnv(db, app.id, user.id, envVars);
      logAudit(user.id, app.id, 'env-set', { env: 'sandbox', keys: envKeys, via: 'adopt' });
    }
    const buildTimeEnv = (report.env || []).some((v) => v.build_time);
    if (buildTimeEnv) {
      const { encryptEnvFiles, storeEnvFiles } = await import('../envFileStore.js');
      const content = Buffer.from('# Written by AppCrane before each build so client-side env vars reach the bundler.\n', 'utf8');
      storeEnvFiles(db, app.id, 'sandbox', encryptEnvFiles([{ rel_path: '.env', mode: 0o600, bytes: content.length, content }]));
    }

    const commitFiles = [];
    const leftOut = [];
    for (const [path, buf] of files) {
      if (isEnvFilePath(path)) { leftOut.push(path); continue; }
      commitFiles.push({ path, content: buf.toString('base64'), encoding: 'base64' });
    }
    for (const f of scaffold) commitFiles.push({ path: f.path, content: Buffer.from(f.content, 'utf8').toString('base64'), encoding: 'base64' });

    const { pushFilesToManagedRepo } = await import('../managedRepo.js');
    const pushed = await pushFilesToManagedRepo(app, commitFiles, {
      message: `Adopt ${row.source_label} into AppCrane`,
      branch: app.branch || 'main',
      actorId: user.id,
    });
    const triggered = pushed?.auto_deploy?.triggered || [];
    if (triggered.some((t) => t.env !== 'sandbox')) {
      log.error(`adopt: ${slug} push started a non-sandbox deploy: ${JSON.stringify(triggered)}`);
      throw new AdoptError('PRODUCTION_REFUSED', 'The first push started a deploy outside the sandbox; stopped.', 500);
    }

    const intake = await submitIntakeGuarded(app, cleanIntake(opts.intake, user), user.id, deps.submitIntake);

    const requests = [];
    if (opts.open_requests) {
      const wanted = [...(report.changes || []), ...(report.risks || [])].filter((i) => i.request);
      const insert = db.prepare("INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status) VALUES (?, ?, ?, ?, 'new')");
      for (const it of wanted.slice(0, 25)) {
        const id = insert.run(app.slug, user.id, ADOPT_REQUESTER, requestMessage(app, it)).lastInsertRowid;
        requests.push({ id: Number(id), title: it.title });
      }
    }

    db.prepare("UPDATE app_adoptions SET status = 'adopted', adopted_at = datetime('now') WHERE id = ?").run(row.id);
    try { rmSync(stagingPath(row.id), { force: true }); } catch (_) {}
    logAudit(user.id, app.id, 'app-adopt', {
      adoption_id: row.id, source: row.source_label, env_keys: envKeys, files: commitFiles.length,
      scaffold: scaffold.map((f) => f.path), deployments: triggered, intake: intake.submitted ? 'submitted' : 'skipped', requests: requests.length,
    });

    const craneDomain = process.env.CRANE_DOMAIN;
    return {
      app: { id: app.id, slug: app.slug, name: app.name },
      sandbox_url: craneDomain || isolationEnabled(db) ? appUrl(db, slug, 'sandbox', { craneBase: `https://${craneDomain}` }) : `/${slug}-sandbox/`,
      commit: pushed?.commit?.sha || null,
      files_committed: commitFiles.length,
      env_files_left_out: leftOut,
      scaffold: scaffold.map((f) => f.path),
      env_keys_set: envKeys,
      deployments: triggered,
      deploy_note: pushed?.auto_deploy?.action || null,
      intake,
      requests,
    };
  } catch (e) {
    db.prepare("UPDATE app_adoptions SET status = 'failed', error = ? WHERE id = ?").run(String(e.message).slice(0, 500), row.id);
    if (app) e.appSlug = app.slug;
    throw e;
  }
}
