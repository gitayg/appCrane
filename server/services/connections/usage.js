// Per-call usage of the connections gateway: a per-app, per-connection rate
// limit, one event-store row per call (kind 'connection.call', never a body,
// never the query string), and the summaries owners and platform admins read.

import { getDb } from '../../db.js';
import { recordEvent } from '../eventStore.js';

export const EVENT_KIND = 'connection.call';
const windows = new Map();

/** Fixed one-minute window per app and connection. True when the call may go ahead. */
export function takeSlot(appId, connection, perMinute, now = Date.now()) {
  const key = `${appId}:${connection}`;
  const minute = Math.floor(now / 60_000);
  const w = windows.get(key);
  if (!w || w.minute !== minute) { windows.set(key, { minute, n: 1 }); return true; }
  if (w.n >= perMinute) return false;
  w.n += 1;
  return true;
}

export function _resetRateLimitsForTests() { windows.clear(); }

export function recordCall({ app, conn, method, path, status, outcome, bytesIn = 0, bytesOut = 0, latencyMs = 0, actingUserId = null }) {
  return recordEvent({
    kind: EVENT_KIND,
    severity: outcome === 'ok' || outcome === 'upstream_error' ? 'info' : 'warning',
    appId: app.id,
    appSlug: app.slug,
    userId: actingUserId,
    summary: `${app.slug} ${method} ${conn.name}${path} -> ${status} (${outcome})`,
    refTable: 'api_connections',
    refId: conn.id ?? null,
    // Without its leading '/': the event scrubber shortens anything shaped
    // like a file path at a quote or space boundary, which would leave '.../x'.
    data: { connection: conn.name, method, path: path.replace(/^\/+/, ''), status, outcome, bytes_in: bytesIn, bytes_out: bytesOut, latency_ms: latencyMs },
  });
}

function daysOf(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 90 ? n : 7;
}

/** Per connection and outcome over the last `days`, plus the most recent calls. appId null: the whole platform. */
export function usageSummary({ appId = null, connection = null, days, limit = 50 } = {}, db = getDb()) {
  const d = daysOf(days);
  const where = ['kind = ?', "ts >= datetime('now', ?)"];
  const args = [EVENT_KIND, `-${d} days`];
  if (appId != null) { where.push('app_id = ?'); args.push(appId); }
  if (connection) { where.push("json_extract(data, '$.connection') = ?"); args.push(connection); }
  const w = where.join(' AND ');
  const totals = db.prepare(`SELECT app_slug AS app, json_extract(data, '$.connection') AS connection, json_extract(data, '$.outcome') AS outcome,
      COUNT(*) AS calls, SUM(COALESCE(json_extract(data, '$.bytes_in'), 0)) AS bytes_in, SUM(COALESCE(json_extract(data, '$.bytes_out'), 0)) AS bytes_out,
      CAST(AVG(json_extract(data, '$.latency_ms')) AS INTEGER) AS avg_latency_ms
    FROM events WHERE ${w} GROUP BY app_slug, connection, outcome ORDER BY app_slug, connection, outcome`).all(...args);
  const recent = db.prepare(`SELECT ts, app_slug AS app, data FROM events WHERE ${w} ORDER BY id DESC LIMIT ?`).all(...args, Math.min(Math.max(Number(limit) || 50, 1), 200))
    .map((r) => { let x = {}; try { x = JSON.parse(r.data || '{}'); } catch (_) {} return { ts: r.ts, app: r.app, ...x, path: `/${x.path || ''}` }; });
  return { days: d, totals, recent };
}
