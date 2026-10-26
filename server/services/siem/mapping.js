import os from 'os';
import { readFileSync } from 'fs';
import { scrubText, scrubSummary } from '../eventScrub.js';

// The one mapping from an events row to what a SIEM receives. Every sink goes
// through toEcs(); CEF and RFC 5424 syslog are built from its output, so a field
// is named in exactly one place. Every string is scrubbed again on the way out
// (eventScrub.js) even though the store already scrubbed it on the way in.

let VERSION = '0';
try { VERSION = JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')).version || '0'; } catch (_) {}

export const SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };
const ECS_SEVERITY = { info: 3, warning: 6, critical: 9 };
const SYSLOG_SEVERITY = { info: 6, warning: 4, critical: 2 };
export const SYSLOG_PEN = 32473;

function category(kind) {
  if (kind.startsWith('login')) return ['authentication'];
  if (kind === 'secret.reveal') return ['iam'];
  if (kind.startsWith('deploy')) return ['package'];
  if (kind.startsWith('scan')) return ['vulnerability'];
  if (kind.startsWith('host') || kind.startsWith('memory')) return ['host'];
  if (kind.startsWith('job')) return ['process'];
  if (kind === 'client_error' || kind === 'request' || kind === 'task' || kind === 'survey') return ['web'];
  return ['configuration'];
}

function outcome(kind) {
  if (/(^|\.)(failed|refused)$/.test(kind)) return 'failure';
  if (kind === 'login' || /(^|\.)(succeeded|recovered|resolved)$/.test(kind)) return 'success';
  return 'unknown';
}

function parseData(data) {
  if (data == null) return null;
  if (typeof data === 'object') return data;
  try { return JSON.parse(data); } catch { return { text: String(data) }; }
}

function scrubDeep(v, depth = 0) {
  if (v == null || typeof v === 'number' || typeof v === 'boolean') return v;
  if (typeof v === 'string') return scrubText(v);
  if (depth > 6) return '[nested]';
  if (Array.isArray(v)) return v.map(x => scrubDeep(x, depth + 1));
  if (typeof v === 'object') {
    const out = {};
    for (const [k, x] of Object.entries(v)) out[k] = scrubDeep(x, depth + 1);
    return out;
  }
  return String(v);
}

function isoTs(ts) {
  if (!ts) return new Date().toISOString();
  const s = String(ts);
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s.replace(' ', 'T')}Z`);
  return Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

/** Stable, instance-scoped id a SIEM can dedupe on (at-least-once delivery). */
export function eventUid(instance, id) {
  return `appcrane-${instance}-${id}`;
}

/**
 * ECS-style document for one event. `row` is an events row (plus optional
 * user_name / subject_user_name); `ctx` is { instance, hostname }.
 */
export function toEcs(row, ctx = {}) {
  const kind = String(row.kind || 'unknown');
  const sev = SEVERITY_RANK[row.severity] != null ? row.severity : 'info';
  const data = scrubDeep(parseData(row.data));
  const ip = data?.ip || data?.detail?.ip || data?.source_ip || null;
  const doc = {
    '@timestamp': isoTs(row.ts),
    message: scrubSummary(row.summary || ''),
    event: {
      id: eventUid(ctx.instance || 'local', row.id),
      kind: sev === 'critical' ? 'alert' : 'event',
      category: category(kind),
      action: kind,
      outcome: outcome(kind),
      severity: ECS_SEVERITY[sev],
      module: 'appcrane',
      dataset: 'appcrane.events',
    },
    log: { level: sev },
    observer: { vendor: 'AppCrane', product: 'AppCrane', version: VERSION, hostname: ctx.hostname || os.hostname() },
    appcrane: {
      event_id: row.id,
      kind,
      severity: sev,
      ...(row.app_id || row.app_slug ? { app: { id: row.app_id ?? null, slug: row.app_slug ?? null } } : {}),
      ...(row.subject_user_id ? { subject_user: { id: row.subject_user_id, name: row.subject_user_name ? scrubText(row.subject_user_name) : null } } : {}),
      ...(row.ref_table ? { ref: { table: row.ref_table, id: row.ref_id ?? null } } : {}),
      ...(data ? { data } : {}),
    },
  };
  if (row.user_id) doc.user = { id: String(row.user_id), ...(row.user_name ? { name: scrubText(row.user_name) } : {}) };
  if (ip && typeof ip === 'string') doc.source = { ip };
  return doc;
}

function cefHeader(v) {
  return String(v ?? '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
}

function cefValue(v) {
  return String(v ?? '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n/g, '\\n').replace(/\r/g, '\\r');
}

/** ArcSight CEF:0 line for one ECS document. */
export function toCef(doc) {
  const a = doc.appcrane;
  const ext = [
    ['rt', Date.parse(doc['@timestamp'])],
    ['externalId', doc.event.id],
    ['cat', doc.event.category.join(',')],
    ['outcome', doc.event.outcome],
    ['msg', doc.message],
    ['dvchost', doc.observer.hostname],
  ];
  if (doc.user) { ext.push(['suid', doc.user.id]); if (doc.user.name) ext.push(['suser', doc.user.name]); }
  if (a.subject_user) { ext.push(['duid', a.subject_user.id]); if (a.subject_user.name) ext.push(['duser', a.subject_user.name]); }
  if (doc.source?.ip) ext.push(['src', doc.source.ip]);
  if (a.app?.slug) ext.push(['cs1Label', 'appSlug'], ['cs1', a.app.slug]);
  if (a.ref) ext.push(['cs2Label', 'ref'], ['cs2', `${a.ref.table}:${a.ref.id ?? ''}`]);
  const head = ['CEF:0', 'AppCrane', 'AppCrane', doc.observer.version, a.kind, doc.message, doc.event.severity].map(cefHeader).join('|');
  return `${head}|${ext.map(([k, v]) => `${k}=${cefValue(v)}`).join(' ')}`;
}

function sdValue(v) {
  return String(v).replace(/[\\"\]]/g, m => `\\${m}`);
}

function printable(v, max) {
  const s = String(v || '-').replace(/[^\x21-\x7e]/g, '_').slice(0, max);
  return s || '-';
}

/** One RFC 5424 message (no transport framing). facility defaults to 13 (log audit). */
export function toSyslog(doc, { format = 'json', facility = 13 } = {}) {
  const pri = facility * 8 + SYSLOG_SEVERITY[doc.appcrane.severity];
  const sd = `[appcrane@${SYSLOG_PEN} eventId="${sdValue(doc.event.id)}" kind="${sdValue(doc.appcrane.kind)}"]`;
  const msg = format === 'cef' ? toCef(doc) : JSON.stringify(doc);
  return `<${pri}>1 ${doc['@timestamp']} ${printable(doc.observer.hostname, 255)} appcrane - ${printable(doc.appcrane.kind, 32)} ${sd} ${msg}`;
}

/** RFC 6587 octet-counting frame: "<byte length> <message>". */
export function octetFrame(message) {
  const buf = Buffer.from(message, 'utf8');
  return Buffer.concat([Buffer.from(`${buf.length} `, 'ascii'), buf]);
}
