import { timingSafeEqual } from 'crypto';
import { getDb } from '../db.js';
import { sleepRow } from './envSleepState.js';
import { wakeToken } from './sleepPolicy.js';
import { wakeEnv } from './envWake.js';
import { appHost, isolationEnabled } from './appOrigin.js';

// A request for a sleeping environment. Caddy cannot reach the stopped
// container, so its handle_errors rewrites the request to /api/_crashed<uri>
// and, while any app has sleep turned on, adds X-AppCrane-Wake: <token>
// (caddy.js). Measured against caddy:2: in handle_errors {uri} is the URI the
// client sent (before strip_prefix) and request_header replaces a value the
// client supplied, so the token proves the request went through the app's own
// route — forward_auth included — and was not sent to /api/_crashed directly.
//
// With the token, the env is woken (one wake shared by every request) and the
// request waits a bounded time. Once the app serves, it is sent back to the
// address it asked for with a 307, which keeps the method and body, so it
// re-enters through Caddy and the app's normal sign-in rules. Not serving yet:
// a browser gets a small page that reloads itself, anything else 503 with
// Retry-After. Without the token nothing is woken.

export const WAKE_HEADER = 'x-appcrane-wake';
export const BROWSER_WAIT_MS = 5_000;
export const API_WAIT_MS = 25_000;
let waits = { browser: BROWSER_WAIT_MS, api: API_WAIT_MS };
export function _setWaitsForTests(w) { waits = { ...waits, ...w }; }

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function tokenOk(db, got) {
  if (typeof got !== 'string' || !got) return false;
  const want = Buffer.from(wakeToken(db));
  const g = Buffer.from(got);
  return g.length === want.length && timingSafeEqual(g, want);
}

function page(res, { title, env, lines, refresh }) {
  res.status(503).set('Cache-Control', 'no-store').set('Retry-After', String(refresh || 5)).type('html').send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
${refresh ? `<meta http-equiv="refresh" content="${refresh}">` : ''}<title>${esc(title)}</title>
<style>body{background:#0f1117;color:#e4e4e7;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#1a1d27;border:1px solid #2a2d3a;border-radius:12px;padding:36px;max-width:480px;width:100%;text-align:center}
h1{margin:0 0 8px;font-size:1.3rem;font-weight:600}.env{font-size:.7rem;color:#a1a1aa;background:#2a2d3a;border-radius:4px;padding:2px 8px;margin-left:6px;text-transform:uppercase}
p{color:#a1a1aa;line-height:1.55;margin:8px 0}.spin{width:28px;height:28px;border:3px solid #2a2d3a;border-top-color:#3b82f6;border-radius:50%;margin:0 auto 16px;animation:s 1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}</style></head>
<body><div class="card">${refresh ? '<div class="spin"></div>' : ''}<h1>${esc(title)}<span class="env">${esc(env)}</span></h1>
${lines.map(l => `<p>${esc(l)}</p>`).join('\n')}</div></body></html>`);
}

function wantsHtml(req) {
  return (req.method === 'GET' || req.method === 'HEAD') && String(req.headers.accept || '').includes('text/html');
}

/** Where the client was going, as a same-origin path. */
export function originalTarget(db, req, slug, env, firstSeg) {
  let uri = req.originalUrl.slice('/api/_crashed'.length) || '/';
  const host = String(req.headers.host || '').toLowerCase().split(':')[0];
  const domain = env === 'production'
    ? String(db.prepare('SELECT domain FROM apps WHERE slug = ?').get(slug)?.domain || '').trim().toLowerCase()
    : '';
  if ((isolationEnabled(db) && host === appHost(db, slug, env)) || (domain && host === domain)) {
    const prefix = `/${firstSeg}`;
    if (uri === prefix || uri.startsWith(prefix + '/') || uri.startsWith(prefix + '?')) uri = uri.slice(prefix.length);
  }
  if (!uri.startsWith('/')) uri = '/' + uri;
  return uri.replace(/^\/{2,}/, '/').replace(/[\r\n]/g, '');
}

/** Returns true when the request was about a sleeping env and has been answered. */
export async function handleSleepingRequest(req, res) {
  const rest = req.originalUrl.slice('/api/_crashed'.length);
  const firstSeg = rest.split(/[/?#]/).filter(Boolean)[0] || '';
  if (!firstSeg) return false;
  const env = firstSeg.endsWith('-sandbox') ? 'sandbox' : 'production';
  const slug = firstSeg.replace(/-sandbox$/, '');
  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) return false;
  const row = sleepRow(db, app.id, env);
  if (!row || (row.state !== 'sleeping' && row.state !== 'waking')) return false;
  const name = app.name || slug;

  if (!tokenOk(db, req.headers[WAKE_HEADER])) {
    page(res, { title: `${name} is asleep`, env, lines: ['This app is asleep to save memory on the server.', 'Open it from its own address to wake it.'] });
    return true;
  }

  const html = wantsHtml(req);
  const wake = wakeEnv(app, env, { reason: 'request' });
  const timeout = new Promise(r => { const t = setTimeout(() => r({ timedOut: true }), html ? waits.browser : waits.api); t.unref?.(); });
  const result = await Promise.race([wake, timeout]);

  if (result.ok && result.healthy !== false && !result.timedOut) {
    res.status(307).set('Cache-Control', 'no-store').set('Location', originalTarget(db, req, slug, env, firstSeg)).end();
    return true;
  }
  if (result.ok === false) {
    const memory = result.code === 'INSUFFICIENT_MEMORY';
    if (html) {
      page(res, { title: `${name} could not wake`, env, refresh: memory ? 30 : 15,
        lines: [memory ? 'The server does not have enough free memory to start it right now.' : 'Starting it failed.', 'This page tries again by itself.'] });
    } else {
      res.status(503).set('Retry-After', '30').set('Cache-Control', 'no-store')
        .json({ error: { code: memory ? 'INSUFFICIENT_MEMORY' : 'WAKE_FAILED', message: `${slug} (${env}) is asleep and could not be started: ${result.error}` } });
    }
    return true;
  }
  if (html) {
    page(res, { title: `Waking up ${name}`, env, refresh: 2, lines: ['This app was asleep to save memory. It is starting now.', 'This page reloads by itself when it is ready.'] });
  } else {
    res.status(503).set('Retry-After', '5').set('Cache-Control', 'no-store')
      .json({ error: { code: 'WAKING', message: `${slug} (${env}) was asleep and is starting. Retry shortly.` } });
  }
  return true;
}
