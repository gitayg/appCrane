export class AppError extends Error {
  constructor(message, status = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// A top-level browser navigation (address bar, iframe src, redirect) sends
// `Accept: text/html`; the SPA's own fetch()/XHR calls do not. We use that to
// decide whether a failed request should render a friendly page or return JSON.
// Only GETs qualify — a POST that 401s is always a programmatic caller.
function isBrowserNavigation(req) {
  const accept = req.headers.accept || '';
  return req.method === 'GET' && accept.includes('text/html');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// Friendly HTML shown when a browser lands on a protected route without a valid
// session (401) or without access (403), instead of dumping the raw JSON error.
function authErrorPage(req, status, message) {
  const signedOut = status === 401;
  const heading = signedOut ? 'Your session has expired' : 'You don’t have access';
  const sub = signedOut
    ? 'Please sign in again to continue to AppCrane.'
    : (escapeHtml(message) || 'You’re signed in, but not authorized to view this page.');
  const redirect = encodeURIComponent(req.originalUrl || '/');
  const href = signedOut ? `/login?redirect=${redirect}` : '/launch';
  const btn = signedOut ? 'Sign in' : 'Go to AppCrane';
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AppCrane — ${signedOut ? 'Sign in' : 'Access denied'}</title>
<style>body{background:#0f1117;color:#e4e4e7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}
.box{background:#1a1d27;border:1px solid #2a2d3a;border-radius:12px;padding:40px;max-width:420px;text-align:center;box-sizing:border-box}
h1{margin:0 0 4px;font-size:1.6rem}h1 span{color:#3b82f6}
.title{font-size:1.05rem;font-weight:600;margin:20px 0 6px}
p{color:#9ca3af;margin:6px 0;font-size:14px;line-height:1.6}
a.btn{display:inline-block;margin-top:22px;background:#3b82f6;color:#fff;text-decoration:none;padding:10px 22px;border-radius:8px;font-size:14px;font-weight:500}
a.btn:hover{background:#2563eb}</style></head>
<body><div class="box"><h1>App<span>Crane</span></h1><div class="title">${heading}</div><p>${sub}</p><a class="btn" href="${escapeHtml(href)}">${btn}</a></div></body></html>`;
}

export function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  const code = err.code || 'INTERNAL_ERROR';
  const message = err.message || 'Internal server error';

  if (status >= 500) {
    console.error(`[ERROR] ${message}`, err.stack);
  }

  // Browser navigations that hit an auth wall get a readable page, not raw JSON.
  if ((status === 401 || status === 403) && isBrowserNavigation(req)) {
    return res.status(status).type('html').send(authErrorPage(req, status, message));
  }

  res.status(status).json({ error: { code, message } });
}

export function notFound(req, res) {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: `${req.method} ${req.path} not found` } });
}
