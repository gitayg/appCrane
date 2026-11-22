import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { join, normalize, extname, relative, sep } from 'node:path';
import { verifyRequest, atLeast } from './identity.js';

// A static site served by a dependency-free Node server, so every file is
// behind a verified AppCrane identity, not just behind the proxy.

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
};

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

/** The file under `root` a URL path names, or null when it would leave root. */
export function resolveInside(root, urlPath) {
  let decoded;
  try { decoded = decodeURIComponent(urlPath); } catch { return null; }
  if (decoded.includes('\0')) return null;
  const rel = normalize(decoded).replace(/^([/\\])+/, '');
  const full = join(root, rel);
  if (full !== root && !full.startsWith(root.endsWith(sep) ? root : root + sep)) return null;
  return full;
}

export function createHandler({ version, publicDir }) {
  return async (req, res) => {
    const url = new URL(req.url, 'http://local');
    const path = url.pathname;

    // AppCrane's health probe calls the container directly, with no identity.
    if (path === '/api/health') return sendJson(res, 200, { status: 'ok', version });

    const check = verifyRequest(req);
    if (!check.ok) {
      return sendJson(res, check.code === 'IDENTITY_NOT_CONFIGURED' ? 503 : 401, { error: { code: check.code, message: check.message } });
    }

    if (path === '/api/me') return sendJson(res, 200, { user: check.identity });
    if (path.startsWith('/api/')) return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'no such API route' } });
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: { code: 'METHOD', message: 'GET only' } });

    let file = resolveInside(publicDir, path.endsWith('/') ? `${path}index.html` : path);
    if (!file) return sendJson(res, 400, { error: { code: 'BAD_PATH', message: 'path not allowed' } });
    // public/admin/ is for app admins and owners. Judged on the resolved file,
    // not the raw URL, so /%61dmin/ or /ADMIN/ cannot slip past. AppCrane's
    // proxy enforces the same through the "access" rule in deployhub.json.
    if (relative(publicDir, file).split(sep)[0].toLowerCase() === 'admin' && !atLeast(check.identity.appRole, 'admin')) {
      return sendJson(res, 403, { error: { code: 'ROLE_REQUIRED', message: 'this needs the admin role or higher' } });
    }
    let info = await stat(file).catch(() => null);
    if (info?.isDirectory()) {
      file = join(file, 'index.html');
      info = await stat(file).catch(() => null);
    }
    if (!info?.isFile()) return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'not found' } });

    res.writeHead(200, {
      'content-type': TYPES[extname(file).toLowerCase()] || 'application/octet-stream',
      'content-length': info.size,
      'x-content-type-options': 'nosniff',
    });
    if (req.method === 'HEAD') return res.end();
    createReadStream(file).pipe(res);
  };
}
