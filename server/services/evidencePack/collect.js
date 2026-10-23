import { readFileSync } from 'fs';
import { join } from 'path';
import {
  tableExists, columns, SECRET_NAME_RE, toCsv, json, scrub, periodBounds, daysBetween, sqliteToIso,
} from './util.js';
import { loadOptional } from './optional.js';
import { allSettings, settingValue } from './settingsRead.js';
import { listDrills } from '../restoreDrills.js';

// One function per evidence file. Each returns the file's content and never a
// credential: settings whose name marks them secret are reported as set / not
// set, keys and tokens as ages and states, and free text is scrubbed.

const AUTH_SETTING_RE = /^(auth_|oidc_|saml_|scim_|sso_|mfa_|session_|password_|api_key_|login_)/;

function settingsLike(db, re) {
  const out = {};
  for (const r of allSettings(db)) {
    if (!re.test(r.key)) continue;
    out[r.key] = SECRET_NAME_RE.test(r.key)
      ? { configured: !!(r.value && String(r.value).length), value: '[not exported]', updated_at: r.updated_at }
      : { value: r.value, updated_at: r.updated_at };
  }
  return out;
}

function mfaEnabledSet(db) {
  if (!tableExists(db, 'user_mfa')) return null;
  return new Set(db.prepare('SELECT user_id FROM user_mfa WHERE enabled_at IS NOT NULL').all().map((r) => r.user_id));
}

export function usersAndRoles(db) {
  const mfa = mfaEnabledSet(db);
  const rows = db.prepare(`SELECT id, username, name, email, role, kind, active, created_at, last_login_at,
      sso_sub IS NOT NULL AS sso_linked, saml_name_id IS NOT NULL AS saml_linked, scim_external_id IS NOT NULL AS scim_managed,
      password_hash IS NOT NULL AS has_password FROM users ORDER BY id`).all()
    .map((u) => ({ ...u, mfa_enabled: mfa ? (mfa.has(u.id) ? 1 : 0) : 'unknown' }));
  return toCsv(rows, ['id', 'username', 'name', 'email', 'role', 'kind', 'active', 'created_at', 'last_login_at', 'sso_linked', 'saml_linked', 'scim_managed', 'has_password', 'mfa_enabled']);
}

export function appRoleAssignments(db) {
  const rows = db.prepare(`SELECT a.slug AS app, r.user_id, u.username, r.app_role FROM app_user_roles r
      JOIN apps a ON a.id = r.app_id LEFT JOIN users u ON u.id = r.user_id ORDER BY a.slug, r.user_id`).all();
  return toCsv(rows, ['app', 'user_id', 'username', 'app_role']);
}

export function authenticationSettings(db) {
  const counts = db.prepare(`SELECT role, COUNT(*) AS n, SUM(active) AS active FROM users GROUP BY role`).all();
  return json({
    note: 'Settings whose name marks a secret are reported as configured or not; their values are never exported.',
    settings: settingsLike(db, AUTH_SETTING_RE),
    users_by_role: counts,
    mfa_table_present: tableExists(db, 'user_mfa'),
  });
}

export function apiKeyPolicy(db) {
  const raw = settingValue(db, 'api_key_max_age_days');
  const n = parseInt(raw, 10);
  return json({
    api_key_max_age_days: Number.isFinite(n) && n > 0 ? Math.min(365, Math.max(7, n)) : 90,
    configured_value: raw ?? null,
    default_days: 90,
    bounds_days: [7, 365],
    covers: ['user API keys', 'personal MCP keys (per-turn coder keys excluded)', 'Crew agent tokens'],
    storage: 'SHA-256 hash of the key; the key value is shown once at issue and never stored in clear',
  });
}

export function apiKeyAges(db, now) {
  const nowIso = new Date(now).toISOString();
  const rows = [];
  const ucols = columns(db, 'users');
  if (ucols.includes('api_key_issued_at')) {
    for (const u of db.prepare(`SELECT id, username, role, active, api_key_issued_at, api_key_expires_at, api_key_last_used_at,
        api_key_hash LIKE 'expired:%' AS expired FROM users WHERE api_key_hash IS NOT NULL ORDER BY id`).all()) {
      rows.push({ credential: 'user_api_key', id: u.id, owner_user_id: u.id, owner: u.username, issued_at: u.api_key_issued_at,
        expires_at: u.api_key_expires_at, last_used_at: u.api_key_last_used_at, age_days: daysBetween(sqliteToIso(u.api_key_issued_at), nowIso),
        state: u.expired ? 'expired' : (u.active ? 'active' : 'owner inactive') });
    }
  }
  if (tableExists(db, 'user_mcp_keys')) {
    const has = columns(db, 'user_mcp_keys');
    for (const k of db.prepare(`SELECT k.id, k.user_id, u.username, k.label, ${has.includes('issued_at') ? 'k.issued_at' : 'k.created_at AS issued_at'}, k.expires_at, k.last_used_at, k.revoked_at, k.read_only
        FROM user_mcp_keys k LEFT JOIN users u ON u.id = k.user_id WHERE k.coder_session_id IS NULL ORDER BY k.id`).all()) {
      rows.push({ credential: 'mcp_key', id: k.id, owner_user_id: k.user_id, owner: k.username, label: k.label, issued_at: k.issued_at,
        expires_at: k.expires_at, last_used_at: k.last_used_at, age_days: daysBetween(sqliteToIso(k.issued_at), nowIso),
        state: k.revoked_at ? 'revoked' : (k.expires_at && sqliteToIso(k.expires_at) < nowIso ? 'expired' : 'active'), read_only: k.read_only });
    }
  }
  if (tableExists(db, 'crew_agent_tokens')) {
    const has = columns(db, 'crew_agent_tokens');
    for (const t of db.prepare(`SELECT id, agent_id, created_at, ${has.includes('expires_at') ? 'expires_at' : 'NULL AS expires_at'}, last_used_at, revoked_at FROM crew_agent_tokens ORDER BY id`).all()) {
      rows.push({ credential: 'crew_agent_token', id: t.id, owner: `agent ${t.agent_id}`, issued_at: t.created_at, expires_at: t.expires_at,
        last_used_at: t.last_used_at, age_days: daysBetween(sqliteToIso(t.created_at), nowIso),
        state: t.revoked_at ? 'revoked' : (t.expires_at && sqliteToIso(t.expires_at) < nowIso ? 'expired' : 'active') });
    }
  }
  return toCsv(rows, ['credential', 'id', 'owner_user_id', 'owner', 'label', 'issued_at', 'expires_at', 'last_used_at', 'age_days', 'state', 'read_only']);
}

export async function accessReviews(period, degraded) {
  const m = await loadOptional('accessReviews');
  if (!m.fn) {
    degraded.push({ file: 'CC6/access-reviews.json', source: 'access reviews', reason: m.reason });
    return json({ available: false, reason: m.reason });
  }
  try {
    return json({ available: true, period, evidence: await m.fn({ from: period.from, to: period.to }) });
  } catch (e) {
    degraded.push({ file: 'CC6/access-reviews.json', source: 'access reviews', reason: `evidence call failed: ${scrub(e.message, 200)}` });
    return json({ available: false, reason: 'the access review module failed to produce evidence' });
  }
}

export const AUDIT_ROW_CAP = 200_000;

export function auditLog(db, period, notes) {
  const [from, to] = periodBounds(period);
  const rows = db.prepare(`SELECT l.id, l.created_at, l.user_id, u.username, l.actor_kind, a.slug AS app, l.action, l.detail
      FROM audit_log l LEFT JOIN users u ON u.id = l.user_id LEFT JOIN apps a ON a.id = l.app_id
      WHERE datetime(l.created_at) >= datetime(?) AND datetime(l.created_at) < datetime(?) ORDER BY l.id LIMIT ?`)
    .all(from, to, AUDIT_ROW_CAP + 1);
  if (rows.length > AUDIT_ROW_CAP) {
    rows.length = AUDIT_ROW_CAP;
    notes.push(`audit-log.csv holds the first ${AUDIT_ROW_CAP} rows of the period; choose a shorter period for the rest.`);
  }
  return { csv: toCsv(rows.map((r) => ({ ...r, detail: scrub(r.detail) })), ['id', 'created_at', 'user_id', 'username', 'actor_kind', 'app', 'action', 'detail']), count: rows.length };
}

export async function auditChain(db, period, degraded) {
  const m = await loadOptional('auditChain');
  if (!m.fn) {
    degraded.push({ file: 'CC7/audit-chain-verification.json', source: 'audit hash chain', reason: m.reason });
    return json({ available: false, reason: m.reason, note: 'Without the hash chain, the audit log is append-only by convention but not tamper-evident.' });
  }
  try {
    const result = await m.fn({ db, from: period.from, to: period.to });
    let status = null;
    if (typeof m.mod.chainStatus === 'function') { try { status = m.mod.chainStatus(db); } catch (_) { status = null; } }
    return json({ available: true, verified_at: new Date().toISOString(), function: m.name, result, status });
  } catch (e) {
    degraded.push({ file: 'CC7/audit-chain-verification.json', source: 'audit hash chain', reason: `verification failed to run: ${scrub(e.message, 200)}` });
    return json({ available: false, reason: 'the audit chain verification failed to run' });
  }
}

export function eventsSummary(db, period) {
  if (!tableExists(db, 'events')) return json({ available: false, reason: 'no event store' });
  const [from, to] = periodBounds(period);
  const byKind = db.prepare(`SELECT kind, severity, COUNT(*) AS n FROM events WHERE datetime(ts) >= datetime(?) AND datetime(ts) < datetime(?)
      GROUP BY kind, severity ORDER BY kind, severity`).all(from, to);
  const bySeverity = db.prepare(`SELECT severity, COUNT(*) AS n FROM events WHERE datetime(ts) >= datetime(?) AND datetime(ts) < datetime(?)
      GROUP BY severity`).all(from, to);
  return json({ available: true, period, by_severity: bySeverity, by_kind: byKind });
}

export function criticalEvents(db, period) {
  if (!tableExists(db, 'events')) return toCsv([], ['id', 'ts', 'kind', 'app', 'user_id', 'summary']);
  const [from, to] = periodBounds(period);
  const rows = db.prepare(`SELECT id, ts, kind, app_slug AS app, user_id, summary FROM events
      WHERE severity = 'critical' AND datetime(ts) >= datetime(?) AND datetime(ts) < datetime(?) ORDER BY id LIMIT 50000`).all(from, to);
  return toCsv(rows.map((r) => ({ ...r, summary: scrub(r.summary, 400) })), ['id', 'ts', 'kind', 'app', 'user_id', 'summary']);
}

export async function siemSinks(db, degraded) {
  if (!tableExists(db, 'siem_sinks')) {
    degraded.push({ file: 'CC7/siem-sinks.json', source: 'SIEM streaming', reason: 'not installed' });
    return json({ available: false, reason: 'SIEM streaming is not installed' });
  }
  const m = await loadOptional('siem');
  const rows = db.prepare('SELECT * FROM siem_sinks ORDER BY id').all();
  const sinks = rows.map((r) => {
    let health = null;
    if (m.fn) { try { health = m.fn(r, db); } catch (_) { health = null; } }
    return {
      id: r.id, name: r.name, type: r.type, preset: r.preset, format: r.format, enabled: r.enabled,
      min_severity: r.min_severity, filter_kinds: r.filter_kinds, delivered_count: r.delivered_count,
      last_success_at: r.last_success_at, failing_since: r.failing_since, consecutive_failures: r.consecutive_failures,
      last_error: scrub(r.last_error, 300), created_at: r.created_at,
      health: health && typeof health === 'object' ? { status: health.status ?? null, lag: health.lag ?? health.backlog ?? null } : null,
    };
  });
  if (!m.fn) degraded.push({ file: 'CC7/siem-sinks.json', source: 'SIEM delivery health', reason: m.reason });
  return json({ available: true, note: 'Destination URLs, credentials and certificates are not exported.', sinks });
}

export async function jobHealthEvidence(db) {
  const { getJobHealth } = await import('../jobHealth.js');
  let jobs = [];
  try { jobs = getJobHealth().map((j) => ({ id: j.id, label: j.label, status: j.status, cadence_ms: j.cadence_ms, last_run: j.last_run, last_error: scrub(j.last_error, 300), next_expected_run: j.next_expected_run })); } catch (_) { jobs = []; }
  const runs = tableExists(db, 'job_runs')
    ? db.prepare('SELECT job, started_at, finished_at, ok, duration_ms, error FROM job_runs ORDER BY id DESC LIMIT 2000').all().map((r) => ({ ...r, error: scrub(r.error, 300) }))
    : [];
  return json({ note: 'Job Health keeps the last 20 recorded runs per job; older runs are not retained.', jobs, recorded_runs: runs });
}

export function dependencyScans(db, period) {
  if (!tableExists(db, 'app_vuln_scans')) return toCsv([], ['app', 'env', 'scanned_at', 'ecosystem', 'status', 'package_count', 'critical', 'high', 'medium', 'low', 'error']);
  const [from, to] = periodBounds(period);
  const rows = db.prepare(`SELECT a.slug AS app, s.env, s.scanned_at, s.ecosystem, s.status, s.package_count, s.findings_json, s.error
      FROM app_vuln_scans s JOIN apps a ON a.id = s.app_id
      WHERE datetime(s.scanned_at) >= datetime(?) AND datetime(s.scanned_at) < datetime(?) ORDER BY s.id`).all(from, to);
  const out = rows.map((r) => {
    const sev = { critical: 0, high: 0, medium: 0, low: 0 };
    try {
      const f = JSON.parse(r.findings_json || '[]');
      for (const x of Array.isArray(f) ? f : (f.findings || [])) {
        const s = String(x.severity || '').toLowerCase();
        if (s in sev) sev[s]++;
        else if (s === 'moderate') sev.medium++;
      }
    } catch (_) { /* unparsable findings count as none */ }
    return { app: r.app, env: r.env, scanned_at: r.scanned_at, ecosystem: r.ecosystem, status: r.status, package_count: r.package_count, ...sev, error: scrub(r.error, 300) };
  });
  return toCsv(out, ['app', 'env', 'scanned_at', 'ecosystem', 'status', 'package_count', 'critical', 'high', 'medium', 'low', 'error']);
}

export function deployments(db, period) {
  const [from, to] = periodBounds(period);
  const rows = db.prepare(`SELECT d.id, a.slug AS app, d.env, d.version, d.status, d.commit_hash, d.commit_message, d.deployed_by, u.username AS deployed_by_username,
      d.started_at, d.finished_at, d.artifact_sha256, d.declared_commit_sha, d.image_ref
      FROM deployments d JOIN apps a ON a.id = d.app_id LEFT JOIN users u ON u.id = d.deployed_by
      WHERE datetime(d.started_at) >= datetime(?) AND datetime(d.started_at) < datetime(?) ORDER BY d.id`).all(from, to);
  return toCsv(rows.map((r) => ({ ...r, commit_message: scrub(r.commit_message, 300) })),
    ['id', 'app', 'env', 'version', 'status', 'commit_hash', 'commit_message', 'deployed_by', 'deployed_by_username', 'started_at', 'finished_at', 'artifact_sha256', 'declared_commit_sha', 'image_ref']);
}

export async function releaseChecks(db, period, degraded) {
  const m = await loadOptional('releaseCheck');
  if (!m.fn || !tableExists(db, 'release_checks')) {
    const reason = m.reason || 'release_checks table absent';
    degraded.push({ file: 'CC8/release-checks.json', source: 'release check', reason });
    return json({ available: false, reason });
  }
  const [from, to] = periodBounds(period);
  const rows = db.prepare(`SELECT r.id, a.slug AS app, r.env, r.deployment_id, r.trigger, r.data_classification, r.mode, r.result, r.blocked,
      r.checks_json, r.created_by, r.created_at FROM release_checks r JOIN apps a ON a.id = r.app_id
      WHERE datetime(r.created_at) >= datetime(?) AND datetime(r.created_at) < datetime(?) ORDER BY r.id`).all(from, to);
  const checks = rows.map(({ checks_json: cj, ...r }) => {
    let parsed = null;
    try { parsed = JSON.parse(cj); } catch (_) { parsed = null; }
    return { ...r, checks: Array.isArray(parsed) ? parsed.map((c) => ({ id: c.id, result: c.result ?? c.status ?? null, summary: scrub(c.summary ?? c.message ?? null, 300) })) : null };
  });
  const exceptions = tableExists(db, 'release_check_exceptions')
    ? db.prepare(`SELECT e.id, a.slug AS app, e.check_id, e.reason, e.expires_at, e.created_by, e.created_at, e.revoked_at FROM release_check_exceptions e
        JOIN apps a ON a.id = e.app_id ORDER BY e.id`).all().map((e) => ({ ...e, reason: scrub(e.reason, 300) }))
    : [];
  const summary = {};
  for (const c of checks) summary[c.result] = (summary[c.result] || 0) + 1;
  return json({ available: true, check_ids: Array.isArray(m.mod.CHECK_IDS) ? m.mod.CHECK_IDS : null, summary, release_checks: checks, exceptions });
}

export async function backupConfiguration() {
  const { getLocalBackupConfig } = await import('../localBackup.js');
  const { getBackupConfig, offSiteState } = await import('../backupScheduler.js');
  const local = getLocalBackupConfig();
  const s3 = getBackupConfig();
  return json({
    local: { enabled: local.enabled, keep: local.keep, hour: local.hour, last_run: local.last_run, last_error: scrub(local.last_error, 300), contents: local.contents, excludes: local.excludes },
    off_site: {
      ...offSiteStateSafe(offSiteState),
      enabled: s3.enabled, region: s3.region, endpoint_set: !!s3.endpoint, hour: s3.hour, encrypt: s3.encrypt, server_side_encryption: s3.sse || null,
      include_repos: s3.include_repos, retention: { daily: s3.keep_daily, weekly: s3.keep_weekly, monthly: s3.keep_monthly },
      last_run: s3.last_run, last_error: scrub(s3.last_error, 300), last_set: s3.last_set, last_bytes: s3.last_bytes, last_duration_ms: s3.last_duration_ms,
      covers: s3.covers, excludes: s3.excludes,
    },
    note: 'Bucket name, access key id and secret are not exported.',
  });
}

function offSiteStateSafe(fn) {
  try {
    const s = fn();
    return { configured: s.configured, has_off_site_copy: s.has_off_site_copy, notice: s.notice };
  } catch (_) { return { configured: null }; }
}

export async function backupHistory(db, period) {
  const { listLocalBackups } = await import('../localBackup.js');
  const local = (await listLocalBackups()).map((b) => ({ file: b.file, bytes: b.bytes, modified_at: b.modified_at }));
  const [from, to] = periodBounds(period);
  const runs = tableExists(db, 'job_runs')
    ? db.prepare(`SELECT job, started_at, finished_at, ok, duration_ms, error FROM job_runs WHERE job IN ('local-backup', 'offsite-backup')
        AND datetime(started_at) >= datetime(?) AND datetime(started_at) < datetime(?) ORDER BY id`).all(from, to).map((r) => ({ ...r, error: scrub(r.error, 300) }))
    : [];
  const appBackups = tableExists(db, 'backups')
    ? db.prepare(`SELECT a.slug AS app, b.env, b.size_bytes, b.created_at FROM backups b JOIN apps a ON a.id = b.app_id
        WHERE datetime(b.created_at) >= datetime(?) AND datetime(b.created_at) < datetime(?) ORDER BY b.id`).all(from, to)
    : [];
  return json({ local_archives_on_disk: local, recorded_backup_job_runs: runs, per_app_backups: appBackups });
}

export function restoreDrills(period) {
  const [from, to] = periodBounds(period);
  const rows = listDrills({ limit: 5000, from: from.replace(' ', 'T'), to: to.replace(' ', 'T') }).map((d) => ({
    run_id: d.run_id, source: d.source, trigger: d.trigger, status: d.status, backup_ref: d.backup_ref, backup_created_at: d.backup_created_at,
    rpo_seconds: d.rpo_seconds, rto_ms: d.rto_ms, cleaned_up: d.cleaned_up ? 1 : 0, started_at: d.started_at, finished_at: d.finished_at,
    failed_checks: d.checks.filter((c) => c.status === 'fail').map((c) => c.id).join(' '),
    checks: d.checks.map((c) => `${c.id}:${c.status}`).join(' '),
    error: scrub(d.error, 300),
  }));
  return toCsv(rows, ['run_id', 'source', 'trigger', 'status', 'backup_ref', 'backup_created_at', 'rpo_seconds', 'rto_ms', 'cleaned_up', 'started_at', 'finished_at', 'failed_checks', 'checks', 'error']);
}

function keyRotation(db) {
  let last = null;
  try { last = db.prepare("SELECT MAX(created_at) AS at FROM audit_log WHERE action = 'security.key_rotated'").get()?.at || null; } catch (_) {}
  return {
    supported: true,
    method: 'crane rotate-key, run on the host with AppCrane stopped: backs up deployhub.db and .env, re-encrypts every stored secret under a new key in one transaction, '
      + 're-signs the audit chain checkpoints, checks every value against the new key, then replaces the key in .env.',
    last_rotated_at: last,
    status: last
      ? `ENCRYPTION_KEY was last rotated at ${last} (UTC).`
      : 'ENCRYPTION_KEY has not been rotated since the instance was installed (or since rotation was recorded).',
    limits: 'Off-site backups and evidence packs made before a rotation stay signed under the previous key and verify only with it. '
      + 'Rotation is refused while MariaDB encryption at rest is in use. Losing the current key makes every encrypted value and every encrypted backup unrecoverable.',
  };
}

export async function encryption(db) {
  const count = (sql) => { try { return db.prepare(sql).get().n; } catch (_) { return null; } };
  const { getBackupConfig } = await import('../backupScheduler.js');
  const s3 = getBackupConfig();
  return json({
    algorithm: 'AES-256-GCM (16-byte IV, 16-byte tag), key = instance ENCRYPTION_KEY',
    encrypted_at_rest: [
      { data: 'app environment variables', where: 'env_vars.value_encrypted', rows: count('SELECT COUNT(*) AS n FROM env_vars') },
      { data: 'managed database passwords', where: 'managed_databases.password_enc / app_password_enc', rows: count('SELECT COUNT(*) AS n FROM managed_databases') },
      { data: 'SSO client secret and SAML IdP certificate', where: 'settings oidc_client_secret_enc, saml_idp_cert_enc', rows: null },
      { data: 'stored GitHub tokens and app credentials', where: 'apps.github_token_encrypted, apps.claude_credentials_encrypted, apps.service_token_encrypted', rows: null },
      { data: 'SIEM sink credentials', where: 'siem_sinks.secrets_enc', rows: count('SELECT COUNT(*) AS n FROM siem_sinks') },
    ],
    hashed_not_encrypted: ['user API keys (SHA-256)', 'MCP keys (SHA-256)', 'Crew agent tokens (SHA-256)', 'passwords (PBKDF2-SHA256, salted)'],
    legacy_encrypted_api_keys: count('SELECT COUNT(*) AS n FROM users WHERE api_key_encrypted IS NOT NULL'),
    off_site_backups: { client_side_encryption: s3.encrypt, server_side_encryption: s3.sse || null },
    local_backups: 'Not encrypted. Written 0600 inside a 0700 directory on the same host; they contain the ENCRYPTION_KEY.',
    key_rotation: keyRotation(db),
    data_in_transit: 'TLS is terminated by the reverse proxy in front of AppCrane; its configuration is outside this pack.',
  });
}

export function appVersion(repoRoot) {
  try { return JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')).version || null; } catch (_) { return null; }
}
