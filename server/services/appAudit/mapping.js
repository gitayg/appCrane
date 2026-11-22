import os from 'os';
import { readFileSync } from 'fs';

// One app audit event as the ECS-style document the SIEM senders take
// (siem/mapping.js toEcs shape: toCef, toSyslog, the Sentinel row and the S3
// export all read these fields). dataset 'appcrane.app_audit' and
// appcrane.source 'app' mark it as written by the app, never by AppCrane.

let VERSION = '0';
try { VERSION = JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')).version || '0'; } catch (_) {}

const parse = (v, def) => { try { return v ? JSON.parse(v) : def; } catch { return def; } };

export function appEventUid(instance, id) {
  return `appcrane-${instance}-app-audit-${id}`;
}

export function toAppAuditEcs(row, ctx = {}) {
  const targets = parse(row.targets, []);
  const context = parse(row.context, {});
  const metadata = parse(row.metadata, null);
  const actor = { type: row.actor_type, id: row.actor_id, name: row.actor_name ?? null, verified: !!row.actor_verified };
  const doc = {
    '@timestamp': new Date(Date.parse(row.occurred_at) || Date.now()).toISOString(),
    message: `${row.action} by ${row.actor_type}:${row.actor_id} in app ${row.app_slug}`,
    event: {
      id: appEventUid(ctx.instance || 'local', row.id),
      kind: 'event', category: ['configuration'], action: row.action, outcome: 'unknown', severity: 3,
      module: 'appcrane', dataset: 'appcrane.app_audit', created: new Date(`${String(row.created_at).replace(' ', 'T')}Z`).toISOString(),
    },
    log: { level: 'info' },
    observer: { vendor: 'AppCrane', product: 'AppCrane', version: VERSION, hostname: ctx.hostname || os.hostname() },
    appcrane: {
      event_id: row.id, kind: 'app_audit', severity: 'info', source: 'app',
      app: { id: row.app_id, slug: row.app_slug },
      actor, targets, ...(metadata ? { data: metadata } : {}),
      ...(row.unregistered ? { unregistered: true } : {}),
    },
  };
  if (row.actor_type === 'user') doc.user = { id: String(row.actor_id), ...(row.actor_name ? { name: row.actor_name } : {}) };
  if (context.location) doc.source = { ip: context.location };
  if (context.user_agent) doc.user_agent = { original: context.user_agent };
  return doc;
}
