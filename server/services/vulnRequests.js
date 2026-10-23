// One app request per dependency-scan finding, keyed on (app, ecosystem,
// package, advisory) — see migration 121.
//
// A finding names a package version and a LIST of advisories, so a package with
// two advisories opens two requests: the key is the advisory, and an advisory
// fixed or withdrawn on its own closes on its own.
//
// Opened once. The key's UNIQUE index makes the insert a no-op the second time,
// whichever env, scan source or process gets there; a request the owner closed
// or rejected is never reopened, even if the advisory is still found.
//
// Closed by a later scan only when no environment's latest SUCCESSFUL scan
// still reports the key. An 'error' or 'skipped' scan says nothing about the
// packages, so it neither opens nor closes anything, and an environment whose
// latest successful scan still has the finding keeps the request open. Only a
// request still in triage or in progress is closed; one a person already moved
// on (shipped, won't-do, validated) is left as they left it.
//
// No per-request mail or GitHub issue: the first scan of a fleet can open
// hundreds of these at once, and the daily digest already lists every one of
// them with a link. They are otherwise ordinary requests — status 'new', listed
// in the app's queue, plannable and buildable like any other.

import { bucketize } from './requestStatus.js';
import log from '../utils/logger.js';
import { recordScanEvents } from './eventStore.js';

export const VULN_REQUESTER = 'AppCrane dependency scan';
const SUCCESSFUL = ['ok', 'findings'];

export function vulnKey(appId, ecosystem, name, advisoryId) {
  return JSON.stringify([Number(appId), ecosystem, name, advisoryId]);
}

export function dashboardBaseUrl() {
  const craneDomain = process.env.CRANE_DOMAIN;
  return craneDomain
    ? `https://${craneDomain}`
    : (process.env.BASE_URL || `http://localhost:${process.env.PORT || 5001}`);
}

export function requestUrl(requestId) {
  return `${dashboardBaseUrl()}/requests/${Number(requestId)}`;
}

export function vulnRequestTitle(f, advisoryId) {
  return f.fixed
    ? `Upgrade ${f.name} ${f.version} → ${f.fixed} (${advisoryId})`
    : `Upgrade ${f.name} ${f.version}: no fixed version yet (${advisoryId})`;
}

function vulnRequestMessage(app, env, source, f, advisoryId) {
  const lines = [
    vulnRequestTitle(f, advisoryId),
    '',
    `The dependency scan found a vulnerable package in ${app.slug}.`,
    `- Package: ${f.name} ${f.version} (${f.ecosystem})`,
    `- Advisory: ${advisoryId}${app.source_type === 'image' ? '' : ` (https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)})`}`,
    f.fixed
      ? `- Fixed in: ${f.fixed} (the version that fixes every advisory the scan reported for ${f.name} ${f.version})`
      : '- Fixed in: no fixed version has been published yet',
    `- First found in: ${env} (${source} scan)`,
  ];
  if (f.ids.length > 1) lines.push(`- Other advisories on this package version: ${f.ids.filter((i) => i !== advisoryId).join(', ')}`);
  lines.push('', 'This request closes itself when a later scan no longer finds this advisory in any environment.');
  return lines.join('\n');
}

/** Open one request per (package, advisory) not seen before. Returns how many were opened. */
export function openVulnRequests(db, app, env, source, findings) {
  const insert = db.prepare(`
    INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, vuln_key)
    VALUES (?, NULL, ?, ?, 'new', ?)
    ON CONFLICT DO NOTHING
  `);
  let opened = 0;
  db.transaction(() => {
    for (const f of findings) {
      for (const id of f.ids) {
        opened += insert.run(app.slug, VULN_REQUESTER, vulnRequestMessage(app, env, source, f, id),
          vulnKey(app.id, f.ecosystem, f.name, id)).changes;
      }
    }
  })();
  return opened;
}

export function stillFound(db, appId) {
  const rows = db.prepare(`
    SELECT s.findings_json FROM app_vuln_scans s
    WHERE s.app_id = ? AND s.id = (
      SELECT id FROM app_vuln_scans
      WHERE app_id = s.app_id AND env = s.env AND status IN ('ok', 'findings')
      ORDER BY scanned_at DESC, id DESC LIMIT 1
    )
  `).all(appId);
  const keys = new Set();
  for (const r of rows) {
    for (const f of r.findings_json ? JSON.parse(r.findings_json) : []) {
      for (const id of f.ids) keys.add(vulnKey(appId, f.ecosystem, f.name, id));
    }
  }
  return keys;
}

/** Close the open requests no environment's latest successful scan still reports. */
export function closeResolvedVulnRequests(db, app) {
  const present = stillFound(db, app.id);
  const candidates = db.prepare(`
    SELECT id, vuln_key, status, validated_at FROM enhancement_requests
    WHERE vuln_key LIKE ? AND validated_at IS NULL
  `).all(`[${Number(app.id)},%`);
  const close = db.prepare(`
    UPDATE enhancement_requests SET status = 'done', done_note = ?
    WHERE id = ? AND status = ? AND validated_at IS NULL
  `);
  const note = 'Closed automatically: the latest dependency scan of every environment no longer finds this advisory.';
  let closed = 0;
  db.transaction(() => {
    for (const r of candidates) {
      if (present.has(r.vuln_key)) continue;
      const bucket = bucketize(r.status, r.validated_at);
      if (bucket !== 'triage' && bucket !== 'in_progress') continue;
      closed += close.run(note, r.id, r.status).changes;
    }
  })();
  return closed;
}

/** Called by scanApp after it records a scan. Never throws. */
export function syncVulnRequests(db, app, scan) {
  if (!SUCCESSFUL.includes(scan?.status)) return { opened: 0, closed: 0 };
  try {
    const findings = scan.findings_json ? JSON.parse(scan.findings_json) : [];
    const opened = openVulnRequests(db, app, scan.env, scan.source, findings);
    const closed = closeResolvedVulnRequests(db, app);
    if (opened || closed) log.info(`[vuln-requests] ${app.slug}/${scan.env}: opened ${opened}, closed ${closed}`);
    recordScanEvents(app, scan, opened, closed);
    return { opened, closed };
  } catch (e) {
    log.warn(`[vuln-requests] ${app.slug}/${scan.env}: could not update requests: ${e.message}`);
    return { opened: 0, closed: 0, error: e.message };
  }
}

/** The request opened for this finding's advisory, or null. */
export function vulnRequestIdFor(db, appId, f, advisoryId) {
  const row = db.prepare('SELECT id FROM enhancement_requests WHERE vuln_key = ?')
    .get(vulnKey(appId, f.ecosystem, f.name, advisoryId));
  return row ? row.id : null;
}
