import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { scrubSummary, scrubData, scrubText } from './eventScrub.js';

// The shared event store (migration 134). Producers call recordEvent() or one
// of the record*Event() adapters below in a single line; every one of them is
// wrapped so a failure here is logged at debug and never reaches the producer.

export const SEVERITIES = Object.freeze(['info', 'warning', 'critical']);

const dedupeSeen = new Map();
const eventListeners = new Set();

/** Called with the new event id after every insert (SIEM delivery wake-up). Returns an unsubscribe. */
export function onEvent(listener) {
  eventListeners.add(listener);
  return () => eventListeners.delete(listener);
}

function toInt(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function guard(fn) {
  try {
    return fn();
  } catch (e) {
    log.debug?.(`[events] not recorded: ${e.message}`);
    return null;
  }
}

/**
 * Append one event. Returns its id, or null when it was skipped (dedupe) or
 * could not be written. Never throws.
 *
 * dedupeKey + dedupeMs: skip the event when the same key was recorded within
 * dedupeMs in this process (a condition re-observed every few minutes).
 */
export function recordEvent(ev) {
  return guard(() => {
    if (!ev || !ev.kind || !ev.summary) return null;
    if (ev.dedupeKey && ev.dedupeMs) {
      const last = dedupeSeen.get(ev.dedupeKey);
      if (last && Date.now() - last < ev.dedupeMs) return null;
    }
    const severity = SEVERITIES.includes(ev.severity) ? ev.severity : 'info';
    const db = getDb();
    const appId = toInt(ev.appId);
    let appSlug = ev.appSlug || null;
    if (appId && !appSlug) appSlug = db.prepare('SELECT slug FROM apps WHERE id = ?').get(appId)?.slug || null;
    const info = db.prepare(`
      INSERT INTO events (kind, severity, app_id, app_slug, user_id, subject_user_id, summary, ref_table, ref_id, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      String(ev.kind).slice(0, 64), severity, appId, appSlug,
      toInt(ev.userId), toInt(ev.subjectUserId), scrubSummary(ev.summary),
      ev.refTable ? String(ev.refTable).slice(0, 64) : null, toInt(ev.refId),
      scrubData(ev.data),
    );
    if (ev.dedupeKey && ev.dedupeMs) dedupeSeen.set(ev.dedupeKey, Date.now());
    for (const fn of eventListeners) { try { fn(Number(info.lastInsertRowid)); } catch (_) {} }
    return Number(info.lastInsertRowid);
  });
}

// ── audit_log ─────────────────────────────────────────────────────────────

const REVEAL_ACTIONS = new Set(['env-reveal', 'secret-reveal', 'env_file.reveal']);
const WARNING_ACTIONS = new Set([
  'user-set-role', 'app-set-role', 'platform-policy-change', 'disk-quota-exceeded', 'server-restart',
  'self-update-triggered', 'user-regen-key', 'user-set-password', 'view-as-start', 'oauth-client-authorized',
]);
const WARNING_RE = /delete|deprovision|restore|revoke|evict/;

export function auditKind(action) {
  if (action === 'login') return 'login';
  if (action === 'login-failed') return 'login.failed';
  if (REVEAL_ACTIONS.has(action)) return 'secret.reveal';
  if (action === 'coder.release') return 'coder.release';
  if (action.startsWith('change.')) return action;
  if (action.startsWith('survey.')) return 'survey';
  if (action.startsWith('task-')) return 'task';
  if (action.startsWith('appstudio.')) return 'request';
  return 'audit';
}

function auditSeverity(action) {
  if (action === 'login-failed' || REVEAL_ACTIONS.has(action) || WARNING_ACTIONS.has(action) || WARNING_RE.test(action)) return 'warning';
  return 'info';
}

function parseDetail(detail) {
  if (detail == null) return null;
  if (typeof detail !== 'string') return detail;
  try { return JSON.parse(detail); } catch { return { text: detail }; }
}

function auditSummary(action, d) {
  const method = d && typeof d.method === 'string' && !d.path ? ` (${d.method})` : '';
  if (action === 'login') return `Signed in${method}`;
  if (action === 'login-failed') return `Sign-in failed${method}${d?.reason ? `: ${d.reason}` : ''}`;
  if (REVEAL_ACTIONS.has(action)) {
    const n = Array.isArray(d?.keys) ? d.keys.length : null;
    return `Revealed ${n == null ? 'secret values' : `${n} secret value(s)`}${d?.env ? ` (${d.env})` : ''}`;
  }
  if (action === 'change.auto_approved') return `Change approved by ${d?.policy || 'policy'}: ${d?.package} ${d?.from_version} → ${d?.to_version} (${d?.advisory}), ${d?.outcome}`;
  if (action === 'change.auto_patch_fallback') return `Auto-patch handed back to a person: ${d?.package} (${d?.advisory})`;
  return `Audit: ${action.replace(/[-_.]+/g, ' ')}`;
}

function subjectFrom(action, d) {
  if (!d || typeof d !== 'object') return null;
  const direct = toInt(d.target_user_id) || toInt(d.subject_user_id);
  if (direct) return direct;
  if (action.startsWith('user-')) return toInt(d.user_id) || toInt(d.params?.id);
  return null;
}

/** One event per audit_log row (called by logAudit). */
export function recordAuditEvent(auditId, userId, appId, action, detail) {
  return guard(() => {
    const a = String(action || 'unknown');
    const d = parseDetail(detail);
    const failedLogin = a === 'login-failed';
    return recordEvent({
      kind: auditKind(a),
      severity: auditSeverity(a),
      appId,
      userId: failedLogin ? null : userId,
      subjectUserId: failedLogin ? userId : subjectFrom(a, d),
      summary: auditSummary(a, d),
      refTable: 'audit_log',
      refId: auditId,
      data: { action: a, detail: d },
    });
  });
}

// ── deployments ───────────────────────────────────────────────────────────

/** stage: 'started' | 'succeeded' | 'failed'. Reads the deployments row itself. */
export function recordDeployEvent(deployId, stage, error = null) {
  return guard(() => {
    const d = getDb().prepare(`
      SELECT d.id, d.app_id, d.env, d.version, d.deployed_by, a.slug
        FROM deployments d LEFT JOIN apps a ON a.id = d.app_id WHERE d.id = ?
    `).get(deployId);
    if (!d) return null;
    const version = d.version && d.version !== 'unknown' ? `v${d.version}` : 'a new version';
    const summary = stage === 'started' ? `Deploy to ${d.env} started`
      : stage === 'succeeded' ? `Deployed ${version} to ${d.env}`
        : `Deploy to ${d.env} failed${error ? `: ${scrubText(error?.message ?? error)}` : ''}`;
    return recordEvent({
      kind: `deploy.${stage}`,
      severity: stage === 'failed' ? 'warning' : 'info',
      appId: d.app_id, appSlug: d.slug, userId: d.deployed_by,
      summary, refTable: 'deployments', refId: d.id,
      data: { env: d.env, version: d.version || null },
    });
  });
}

export function recordRollbackEvent(app, env, target, userId) {
  return recordEvent({
    kind: 'deploy.rollback', severity: 'warning', appId: app?.id, appSlug: app?.slug, userId,
    summary: `Rollback of ${env} to deployment #${target?.id}${target?.version ? ` (v${target.version})` : ''}`,
    refTable: 'deployments', refId: target?.id, data: { env, rollback_to: target?.id ?? null },
  });
}

// ── dependency scans ──────────────────────────────────────────────────────

export function recordScanEvents(app, scan, opened, closed) {
  return guard(() => {
    if (opened > 0) {
      recordEvent({
        kind: 'scan.finding', severity: 'warning', appId: app.id, appSlug: app.slug,
        summary: `Dependency scan of ${scan.env} found ${opened} new advisory(ies)`,
        refTable: 'app_vuln_scans', refId: scan.id, data: { env: scan.env, source: scan.source, opened },
      });
    }
    if (closed > 0) {
      recordEvent({
        kind: 'scan.resolved', severity: 'info', appId: app.id, appSlug: app.slug,
        summary: `${closed} dependency advisory(ies) no longer found`,
        refTable: 'app_vuln_scans', refId: scan.id, data: { env: scan.env, source: scan.source, closed },
      });
    }
    return null;
  });
}

// ── client errors ─────────────────────────────────────────────────────────

const CLIENT_ERROR_STEPS = new Set([1, 10, 100, 1000, 10000]);

/** A new fingerprint, or a count reaching 10 / 100 / 1000 / 10000. */
export function recordClientErrorEvent(rowId, report, count, userId) {
  return guard(() => {
    if (!CLIENT_ERROR_STEPS.has(count)) return null;
    const app = report?.appSlug ? getDb().prepare('SELECT id FROM apps WHERE slug = ?').get(report.appSlug) : null;
    return recordEvent({
      kind: 'client_error', severity: count >= 100 ? 'warning' : 'info',
      appId: app?.id ?? null, appSlug: report?.appSlug || null, userId,
      summary: count === 1 ? `New browser error: ${report?.message}` : `Browser error seen ${count} times: ${report?.message}`,
      refTable: 'client_errors', refId: rowId,
      data: { source: report?.source, page: report?.page || null, count },
    });
  });
}

// ── Job Health ────────────────────────────────────────────────────────────

const DAY = 86_400_000;

/** prevOk: the previous run's ok (undefined when none); entry: the run just recorded. */
export function recordJobEvent(id, label, prevOk, entry) {
  return guard(() => {
    if (entry === 'late') {
      return recordEvent({
        kind: 'job.late', severity: 'warning', summary: `Background job late: ${label || id}`,
        data: { job: id }, dedupeKey: `job.late:${id}`, dedupeMs: DAY,
      });
    }
    if (!entry) return null;
    if (!entry.ok && prevOk !== false) {
      return recordEvent({
        kind: 'job.failed', severity: 'warning', summary: `Background job failing: ${label || id}`,
        data: { job: id, error: entry.error },
      });
    }
    if (entry.ok && prevOk === false) {
      return recordEvent({
        kind: 'job.recovered', severity: 'info', summary: `Background job recovered: ${label || id}`,
        data: { job: id },
      });
    }
    return null;
  });
}

// ── host resources ────────────────────────────────────────────────────────

export function recordHostEvent(resource, prevLevel) {
  return guard(() => {
    const level = resource?.level;
    if (!level || level === 'unknown' || level === prevLevel) return null;
    const bad = level === 'warning' || level === 'critical';
    if (!bad && prevLevel !== 'warning' && prevLevel !== 'critical') return null;
    const free = resource.totalBytes ? Math.round((resource.freeBytes / resource.totalBytes) * 100) : null;
    return recordEvent({
      kind: bad ? 'host.alert' : 'host.recovered',
      severity: bad ? level : 'info',
      summary: bad ? `Server ${level}: ${resource.label}${free != null ? ` (${free}% free)` : ''}` : `Server back to normal: ${resource.label}`,
      data: { resource: resource.id, level, previous: prevLevel || null, free_pct: free },
    });
  });
}

// ── memory admission ──────────────────────────────────────────────────────

export function recordAdmissionEvent(outcome, ctx, message) {
  return guard(() => recordEvent({
    kind: 'memory.admission',
    severity: outcome === 'refused' ? 'critical' : 'warning',
    appId: ctx?.appId ?? null, appSlug: ctx?.slug || null, userId: ctx?.userId ?? null,
    summary: message,
    data: { outcome, what: ctx?.what || null, env: ctx?.env || null, automatic: !!ctx?.automatic },
  }));
}

export function _resetEventStoreForTests() {
  dedupeSeen.clear();
}
