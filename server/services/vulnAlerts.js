// Immediate e-mail when a scan finds a vulnerability nobody has been told about.
//
// The daily digest (vulnDigest.js) stays the summary; this is the "it just
// appeared" notice. Called by scanApp after every recorded scan, whatever its
// source (deploy, scheduled, manual) and scanner (lockfile or image).
//
// Once per (app, ecosystem, package, advisory), recorded in vuln_alerts
// (migration 152). The claim is an INSERT OR IGNORE, so two scans of the same
// app racing each other mail it once. A row is dropped when no environment's
// latest successful scan still reports the advisory, so a fix that is later
// undone is mailed again: the request system never reopens a closed request,
// and this mail is then the only signal that the vulnerable version is back.
//
// One mail per recipient per scan, listing every new finding. Recipients: the
// app's owners and every platform admin, active humans only, each once.
// Platform setting `vuln_alerts_immediate` (ON unless stored 'false') turns the
// mail off; findings are still recorded as seen while it is off, so turning it
// back on does not mail the backlog.

import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { enqueueEmail } from './emailQueue.js';
import { recordEvent } from './eventStore.js';
import { stillFound, vulnKey, vulnRequestIdFor } from './vulnRequests.js';
import { renderVulnAlert } from './vulnAlertMail.js';

export const VULN_ALERT_SOURCE = 'vuln-alert';
export const VULN_ALERTS_SETTING = 'vuln_alerts_immediate';
const SUCCESSFUL = ['ok', 'findings'];

const defaults = {
  fetchAdvisories: async (ids) => (await import('./appScan.js')).fetchAdvisories(ids),
  effectiveForApp: async (db, app) => (await import('./autoPatch/policy.js')).effectiveForApp(db, app),
  classifyAdvisory: async (record) => (await import('./autoPatch/classify.js')).classifyAdvisory(record),
  usesLocalRepo: async (app) => (await import('./managedRepo.js')).usesLocalRepo(app),
  releaseCheckOutlook: async (db, app) => releaseCheckOutlook(db, app),
};
let testDeps = null;
/** Test seam: replaces any of the defaults above. */
export function _setVulnAlertDepsForTests(d) { testDeps = d; }
const dep = () => ({ ...defaults, ...(testDeps || {}) });

export function vulnAlertsEnabled(db) {
  const raw = db.prepare('SELECT value FROM settings WHERE key = ?').get(VULN_ALERTS_SETTING)?.value;
  return raw == null ? true : String(raw).trim().toLowerCase() !== 'false';
}

async function releaseCheckOutlook(db, app) {
  const { getClassification, getClassificationPolicy } = await import('./dataClassification.js');
  const { resolveMode, activeExceptions } = await import('./releaseCheck.js');
  const { level } = getClassification(db, app.id);
  const policy = getClassificationPolicy(db);
  return {
    off: resolveMode(db, level) === 'off',
    blocks: !!policy.block_vulnerable_dependencies,
    excepted: activeExceptions(db, app.id).some((e) => e.check_id === 'dependencies'),
  };
}

function forgetResolved(db, appId) {
  const present = stillFound(db, appId);
  const rows = db.prepare('SELECT id, ecosystem, package, advisory_id FROM vuln_alerts WHERE app_id = ?').all(appId);
  const del = db.prepare('DELETE FROM vuln_alerts WHERE id = ?');
  for (const r of rows) {
    if (!present.has(vulnKey(appId, r.ecosystem, r.package, r.advisory_id))) del.run(r.id);
  }
}

/** The findings of this scan this scan is the first to report, narrowed to those advisories. */
function claimNew(db, app, scan, findings) {
  const claim = db.prepare(`INSERT OR IGNORE INTO vuln_alerts (app_id, ecosystem, package, advisory_id, scan_id)
    VALUES (?, ?, ?, ?, ?)`);
  const mine = db.prepare(`SELECT 1 FROM vuln_alerts WHERE app_id = ? AND ecosystem = ? AND package = ?
    AND advisory_id = ? AND scan_id = ?`);
  const out = [];
  db.transaction(() => {
    forgetResolved(db, app.id);
    for (const f of findings) {
      const ids = [];
      for (const id of f.ids || []) {
        const fresh = claim.run(app.id, f.ecosystem, f.name, id, scan.id).changes > 0;
        if (fresh || mine.get(app.id, f.ecosystem, f.name, id, scan.id)) ids.push(id);
      }
      if (ids.length) out.push({ ...f, ids });
    }
  })();
  return out;
}

function recipients(db, appId) {
  const owners = db.prepare(`SELECT u.id, u.name, u.email FROM app_user_roles r JOIN users u ON u.id = r.user_id
    WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 1 AND u.email IS NOT NULL AND trim(u.email) != ''
      AND COALESCE(u.kind, 'human') = 'human' ORDER BY u.id`).all(appId);
  const admins = db.prepare(`SELECT id, name, email FROM users WHERE role = 'platform_admin' AND active = 1
    AND email IS NOT NULL AND trim(email) != '' AND COALESCE(kind, 'human') = 'human' ORDER BY id`).all();
  const byId = new Map();
  const emails = new Set();
  for (const [list, role] of [[owners, 'owner'], [admins, 'platform_admin']]) {
    for (const u of list) {
      const email = String(u.email).trim().toLowerCase();
      if (byId.has(u.id)) { byId.get(u.id).roles.push(role); continue; }
      if (emails.has(email)) continue;
      emails.add(email);
      byId.set(u.id, { id: u.id, name: u.name, email: u.email, roles: [role] });
    }
  }
  return [...byId.values()];
}

async function describe(db, app, findings, d) {
  let records = new Map();
  if (app.source_type !== 'image') {
    try { records = (await d.fetchAdvisories(findings.flatMap((f) => f.ids))).records || new Map(); } catch (_) { records = new Map(); }
  }
  let policy = { enabled: false, reason: 'unknown' };
  try { policy = await d.effectiveForApp(db, app); } catch (_) { /* treated as off */ }
  let local = false;
  try { local = !!(await d.usesLocalRepo(app)); } catch (_) { local = false; }
  let gate = null;
  try { gate = await d.releaseCheckOutlook(db, app); } catch (_) { gate = null; }

  const out = [];
  for (const f of findings) {
    const advisories = [];
    for (const id of f.ids) {
      const rec = records.get(id) || null;
      let rce = null;
      if (rec) { try { rce = !!(await d.classifyAdvisory(rec)).rce; } catch (_) { rce = null; } }
      const severity = typeof rec?.database_specific?.severity === 'string' ? rec.database_specific.severity : null;
      const requestId = vulnRequestIdFor(db, app.id, f, id);
      const reqRow = requestId ? db.prepare('SELECT status FROM enhancement_requests WHERE id = ?').get(requestId) : null;
      advisories.push({ id, rce, severity, requestId, requestOpen: !!reqRow && reqRow.status !== 'done' });
    }
    const anyRce = advisories.some((a) => a.rce);
    let autoPatch;
    if (!anyRce) autoPatch = { will: false, why: null };
    else if (!policy.enabled) autoPatch = { will: false, why: `RCE auto-patch is ${policy.reason}` };
    else if (f.ecosystem !== 'npm') autoPatch = { will: false, why: `auto-patch only fixes npm packages, and this is ${f.ecosystem}` };
    else if (!f.fixed) autoPatch = { will: false, why: 'no fixed version has been published yet' };
    else if (!local) autoPatch = { will: false, why: 'auto-patch only works on apps whose repository AppCrane hosts' };
    else autoPatch = { will: true, why: null };

    let releaseCheck = 'unknown';
    if (gate) {
      if (gate.off) releaseCheck = 'off';
      else if (!f.fixed) releaseCheck = 'warn';
      else if (!gate.blocks) releaseCheck = 'not_enforced';
      else if (gate.excepted) releaseCheck = 'excepted';
      else releaseCheck = 'blocks';
    }
    out.push({ ...f, advisories, rce: anyRce, autoPatch, releaseCheck });
  }
  return out;
}

/**
 * Mail owners and platform admins about the findings in `scan` no earlier scan
 * reported. Never throws. @returns {Promise<{ sent: number, findings: number, skipped?: string }>}
 */
export async function alertNewFindings(db, app, scan) {
  try {
    db = db || getDb();
    if (!scan || !SUCCESSFUL.includes(scan.status)) return { sent: 0, findings: 0, skipped: 'status' };
    const all = scan.findings_json ? JSON.parse(scan.findings_json) : [];
    const fresh = claimNew(db, app, scan, all);
    if (!fresh.length) return { sent: 0, findings: 0 };
    if (!vulnAlertsEnabled(db)) return { sent: 0, findings: fresh.length, skipped: 'disabled' };

    const d = dep();
    const findings = await describe(db, app, fresh, d);
    const people = recipients(db, app.id);
    let sent = 0;
    for (const person of people) {
      const m = renderVulnAlert({ app, env: scan.env, source: scan.source, findings, person });
      try {
        const r = enqueueEmail({
          appId: app.id, env: scan.env, to: person.email, subject: m.subject, text: m.text, html: m.html,
          source: VULN_ALERT_SOURCE, idempotencyKey: `vuln-alert:${scan.id}:${person.id}`,
        });
        if (!r.deduped) sent++;
      } catch (e) {
        log.warn(`[vuln-alert] mail to user ${person.id} for ${app.slug} skipped: ${e.message}`);
      }
    }
    if (sent) {
      recordEvent({
        kind: 'vuln.alert', severity: findings.some((f) => f.rce) ? 'warning' : 'info', appId: app.id, appSlug: app.slug,
        summary: `Vulnerability alert for ${scan.env}: ${findings.length} new vulnerable package(s), e-mailed to ${sent} recipient(s)`,
        refTable: 'app_vuln_scans', refId: scan.id,
        data: {
          env: scan.env, source: scan.source, recipients: sent,
          advisories: findings.flatMap((f) => f.ids.map((id) => `${f.ecosystem}:${f.name}@${f.version} ${id}`)),
        },
      });
      log.info(`[vuln-alert] ${app.slug}/${scan.env}: ${findings.length} new finding(s), ${sent} mail(s) queued`);
    }
    return { sent, findings: findings.length };
  } catch (e) {
    log.warn(`[vuln-alert] ${app?.slug}/${scan?.env}: could not send alerts: ${e.message}`);
    return { sent: 0, findings: 0, error: e.message };
  }
}
