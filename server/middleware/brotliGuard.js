// Refuse Brotli-compressed request bodies (CVE-2026-111497, "Node2Shell").
//
// The Brotli decoder bundled with Node.js before 22.23.4 / 24.22.1 / 26.12.1
// writes past an internal buffer on malformed input, which Node's advisory says
// "can lead to a crash, disclosure of process memory, or remote code execution".
// body-parser 2.x (Express 5) decompresses any body sent with
// `Content-Encoding: br` through zlib.createBrotliDecompress, so every parser in
// this process is reachable by an unauthenticated client. Nothing AppCrane
// serves needs Brotli request bodies (git sends gzip, browsers send none), so
// the request is answered 415 before any parser runs and before the body is
// read. Mounted first in server/index.js; it stays on after the runtime is
// patched, since a request body in Brotli is not something any client here sends.

import log from '../utils/logger.js';

const BR_TOKEN = /(^|,)\s*br\s*(?=,|$)/i;
const LOG_EVERY_MS = 60_000;

/** Does a Content-Encoding value (string, or array of repeated headers) name br? */
export function namesBrotli(value) {
  if (Array.isArray(value)) return value.some(namesBrotli);
  return typeof value === 'string' && BR_TOKEN.test(value);
}

export function createBrotliGuard({ now = Date.now, warn = (m) => log.warn(m) } = {}) {
  let lastLog = -Infinity;
  let quiet = 0;
  return function refuseBrotliBodies(req, res, next) {
    if (!namesBrotli(req.headers['content-encoding'])) return next();
    const t = now();
    if (t - lastLog >= LOG_EVERY_MS) {
      warn(`[brotli-guard] refused a request body sent with Content-Encoding: br (${req.method} ${req.path})` +
        (quiet ? `; ${quiet} more refused since the last report` : '') + ' — CVE-2026-111497');
      lastLog = t;
      quiet = 0;
    } else {
      quiet++;
    }
    res.set('Accept-Encoding', 'gzip, deflate');
    res.set('Connection', 'close');
    res.status(415).json({
      error: {
        code: 'UNSUPPORTED_CONTENT_ENCODING',
        message: 'Request bodies compressed with Brotli (Content-Encoding: br) are not accepted. Send the body uncompressed or with gzip.',
      },
    });
  };
}
