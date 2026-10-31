// Daily host security check (hostVulns.js) and the e-mail to platform admins.
//
// Mail only when there is something to do (security updates pending or a
// reboot required) AND it changed since the last mail: a package or version
// not in that mail, or a reboot newly required. While nothing changes and it
// stays unresolved, one reminder per 7 days. A daily "still 3 updates" mail is
// the kind people learn to filter.
//
// The last mailed state lives in settings, so a restart neither forgets it nor
// mails again; the idempotency key is derived from the mail's content (or the
// day, for a reminder), so a crash between enqueueing and saving that state
// cannot send the same mail twice.

import { createHash } from 'crypto';
import { getDb } from '../db.js';
import { enqueueEmail } from './emailQueue.js';
import { jobStarted, trackJob, noteJobFailure, setJobDetail } from './jobHealth.js';
import { today } from './vulnDigest.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, esc, bulletList, renderBrandedEmail } from './mail/brandedLayout.js';
import { detectHostVulns, isActionable } from './hostVulns.js';
import log from '../utils/logger.js';

export const JOB_ID = 'host-vulns';
export const MAIL_SOURCE = 'host-vulns';
export const REMINDER_MS = 7 * 24 * 60 * 60_000;
const DAY_MS = 24 * 60 * 60_000;
const MAX_LISTED = 50;
const K = {
  lastRun: 'host_vulns_last_run',
  hour: 'host_vulns_hour',
  result: 'host_vulns_last_result',
  mailed: 'host_vulns_mailed',
};
const DEFAULT_HOUR = 7;

function getSetting(db, key, fallback = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row && row.value != null ? row.value : fallback;
}
function setSetting(db, key, value) {
  db.prepare(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
  ).run(key, String(value));
}
function readJson(db, key) {
  try { return JSON.parse(getSetting(db, key, 'null')); } catch (_) { return null; }
}

const pkgKey = (p) => `${p.name}@${p.candidate}`;

/**
 * Pure: what to mail given this result and the state of the last mail.
 * @returns {{ kind: 'new'|'reminder'|null, fresh: string[], state: object|null }}
 *   state is what to remember next (null = nothing outstanding, forget it).
 */
export function decideMail(r, prev, now) {
  if (!isActionable(r)) return { kind: null, fresh: [], state: null };
  const cur = { packages: r.packages.map(pkgKey), reboot: r.reboot.required };
  const before = new Set(prev?.packages || []);
  const fresh = cur.packages.filter((k) => !before.has(k));
  if (fresh.length || (cur.reboot && !prev?.reboot)) {
    return { kind: 'new', fresh, state: { ...cur, at: new Date(now).toISOString() } };
  }
  if (!prev?.at || now - Date.parse(prev.at) >= REMINDER_MS) {
    return { kind: 'reminder', fresh: [], state: { ...cur, at: new Date(now).toISOString() } };
  }
  // Nothing new: remember only what is still outstanding, so a package that
  // was fixed and later comes back (or a second reboot) counts as new again.
  return { kind: null, fresh: [], state: { ...cur, at: prev.at } };
}

function ago(hours) {
  if (hours == null) return 'unknown';
  return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} days ago`;
}

/** Plain lines shared by the text and HTML bodies. */
function lines(r, fresh) {
  const isFresh = new Set(fresh);
  const pkgs = r.packages.slice(0, MAX_LISTED).map((p) => (
    `${p.name} ${p.installed || '(not installed)'} -> ${p.candidate}${isFresh.has(pkgKey(p)) ? ' (new)' : ''}`
  ));
  if (r.packages.length > MAX_LISTED) pkgs.push(`... and ${r.packages.length - MAX_LISTED} more`);
  const status = [];
  status.push(r.reboot.required
    ? `Reboot required${r.reboot.packages.length ? ` (by ${r.reboot.packages.join(', ')})` : ''}`
    : 'No reboot required');
  status.push(r.unattended.enabled
    ? 'Unattended security upgrades: on'
    : `Unattended security upgrades: OFF (${r.unattended.installed ? 'installed but not enabled in APT::Periodic' : 'package not installed'}); scripts/host-hardening.sh turns it on`);
  status.push(`Package lists last refreshed: ${ago(r.cache.ageHours)}${r.cache.stale ? ' (stale: the apt-daily timer may not be running, so this list can be incomplete)' : ''}`);
  if (r.unavailable) status.push(`${r.unavailable} further update(s) need an Ubuntu Pro (ESM) subscription`);
  status.push(`Source: ${r.source === 'pro' ? 'pro security-status' : 'apt-get -s dist-upgrade (-security pocket)'}`);
  return { pkgs, status };
}

export function renderHostVulnMail(r, kind, fresh) {
  const n = r.packages.length;
  const parts = [];
  if (n) parts.push(`${n} security update${n === 1 ? '' : 's'} pending`);
  if (r.reboot.required) parts.push('reboot required');
  const summary = parts.join(', ');
  const subject = `[AppCrane] ${kind === 'reminder' ? 'Reminder: ' : ''}Server ${summary}`;
  const host = r.os.prettyName || 'this server';
  const intro = kind === 'reminder'
    ? `Still outstanding on this AppCrane server (${host}): ${summary}.`
    : `This AppCrane server (${host}) has ${summary}${fresh.length ? ` (${fresh.length} new since the last mail)` : ''}.`;
  const { pkgs, status } = lines(r, fresh);
  const howTo = [
    ...(n ? ['Install: sudo apt update && sudo apt upgrade (or let unattended-upgrades do it)'] : []),
    ...(r.reboot.required ? ['Reboot when convenient: sudo reboot'] : []),
  ];

  let text = `${intro}\n\n`;
  if (pkgs.length) text += `Security updates (installed -> available):\n${pkgs.map((l) => `  - ${l}`).join('\n')}\n\n`;
  text += `${status.join('\n')}\n\n${howTo.join('\n')}\n\nSee Settings > Job Health.\n`;

  const html = renderBrandedEmail({
    preheader: summary, greeting: 'Hi,', intro,
    bodyHtml: (pkgs.length
      ? `<p style="margin:14px 0 0;font-size:13px;font-weight:600;color:${BRAND.text};">Security updates (installed &rarr; available)</p>` + bulletList(pkgs)
      : '')
      + bulletList(status)
      + (howTo.length ? `<p style="margin:12px 0 0;font-size:13px;color:${BRAND.dim};">${howTo.map(esc).join('<br>')}</p>` : ''),
    cta: { label: 'Open Job Health', url: `${dashboardBaseUrl()}/settings#jobs` },
    footer: 'You get this because you are a platform admin of this AppCrane.',
  });
  return { subject, text, html };
}

function admins(db) {
  return db.prepare(`SELECT email FROM users WHERE role = 'platform_admin' AND active = 1
                     AND email IS NOT NULL AND trim(email) != ''`).all().map((u) => u.email);
}

function mailAdmins(db, r, decision) {
  const { subject, text, html } = renderHostVulnMail(r, decision.kind, decision.fresh);
  const tag = decision.kind === 'reminder'
    ? `reminder:${today()}`
    : createHash('sha256').update(JSON.stringify([decision.state.packages, decision.state.reboot])).digest('hex').slice(0, 16);
  // Checked here rather than left to enqueueEmail, whose dedupe runs only for
  // app mail (app_id set); platform mail has app_id NULL.
  const seen = db.prepare('SELECT id FROM email_queue WHERE idempotency_key = ?');
  const sent = [];
  for (const to of admins(db)) {
    const idempotencyKey = `host-vulns:${tag}:${to.trim().toLowerCase()}`;
    if (seen.get(idempotencyKey)) continue;
    try {
      enqueueEmail({ to, subject, text, html, appId: null, source: MAIL_SOURCE, idempotencyKey });
      sent.push(to);
    } catch (e) {
      log.warn(`[host-vulns] mail to ${to} skipped: ${e.message}`);
    }
  }
  return sent;
}

function jobDetail(r) {
  if (!r.supported) return { supported: false, reason: r.reason, at: new Date().toISOString() };
  const warn = isActionable(r) || !r.unattended.enabled || r.cache.stale;
  return {
    at: r.at, severity: warn ? 'warning' : 'ok', source: r.source,
    pending: r.packages.length, reboot_required: r.reboot.required,
    unattended_enabled: r.unattended.enabled, cache_age_hours: r.cache.ageHours, cache_stale: r.cache.stale,
    error: r.error || null,
  };
}

/** One check: detect, record for Job Health and the API, mail admins when warranted. */
export async function runHostVulnCheck({ db = getDb(), deps = {}, now = Date.now() } = {}) {
  const r = await detectHostVulns(deps);
  setSetting(db, K.result, JSON.stringify(r));
  setJobDetail(JOB_ID, jobDetail(r));
  // A failed detection says nothing about what is pending; it must neither
  // mail nor clear the state of the last mail.
  if (!r.supported || r.error) return { result: r, kind: null, mailed: [] };
  const decision = decideMail(r, readJson(db, K.mailed), now);
  const mailed = decision.kind ? mailAdmins(db, r, decision) : [];
  if (decision.state) setSetting(db, K.mailed, JSON.stringify(decision.state));
  else db.prepare('DELETE FROM settings WHERE key = ?').run(K.mailed);
  if (mailed.length) log.info(`[host-vulns] ${decision.kind} mail to ${mailed.length} admin(s)`);
  return { result: r, kind: decision.kind, mailed };
}

/** The latest result, for the platform-admin API. Null before the first run. */
export function getLastHostVulns(db = getDb()) {
  return readJson(db, K.result);
}

let _timer = null;

/** Hourly tick, one run per local day after host_vulns_hour (default 07). Started from index.js. */
export function startHostVulnScheduler() {
  if (_timer) return;
  const tick = async () => {
    let db;
    try {
      db = getDb();
      const configured = parseInt(getSetting(db, K.hour, String(DEFAULT_HOUR)), 10);
      const hour = Number.isInteger(configured) && configured >= 0 && configured <= 23 ? configured : DEFAULT_HOUR;
      if (getSetting(db, K.lastRun, '') === today() || new Date().getHours() < hour) return;
      // Claimed before the run, as in vulnDigest.js: pro and apt can take a
      // while on a slow disk, and the next tick must not start a second run.
      setSetting(db, K.lastRun, today());
    } catch (e) {
      log.warn(`[host-vulns] scheduler tick failed: ${e.message}`);
      return;
    }
    try {
      await trackJob(JOB_ID, async () => {
        const { result } = await runHostVulnCheck({ db });
        if (result.error) noteJobFailure(JOB_ID, new Error(result.error));
      });
    } catch (e) {
      log.error(`[host-vulns] daily run failed: ${e.message}`);
    }
  };
  jobStarted(JOB_ID, { cadenceMs: DAY_MS });
  tick().catch(() => {});
  _timer = setInterval(() => { tick().catch(() => {}); }, 60 * 60 * 1000);
  _timer.unref?.();
  log.info('[host-vulns] daily scheduler started (hourly check)');
}

export function stopHostVulnScheduler() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}
