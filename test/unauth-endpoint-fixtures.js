import http from 'node:http';

// A vibe-coded app that trusts nobody's identity and checks nothing: a bundle
// that calls its API, an OpenAPI document naming a route the bundle never
// references, records served to anyone, a write route that takes anything.
// Every request is recorded with its raw headers and body size.

export const VALUES = Object.freeze({
  email: 'unauth-record-value-must-not-leak@example.test',
  name: 'Value Must Not Leak',
  report: 'secret-report-title-must-not-leak',
  created: 'created-row-value-must-not-leak',
});

export const BUNDLE =
  'const base="";async function load(id){' +
  'const u=await fetch("/api/users").then(r=>r.json());' +
  'const me=await fetch("/api/me");' +
  'const inv=await axios.get("/api/invoices");' +
  'await fetch("/api/health");' +
  'await fetch(`/api/users/${id}`);' +
  'await fetch("/api/items",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({a:1})});' +
  'await fetch("/api/reset",{method:"POST"});' +
  'await fetch("/api/logout");' +
  'return [u,me]}\n';

export function appServer({ port = 0, extraPaths = 0, hang = [] } = {}) {
  const requests = [];
  const s = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const path = new URL(req.url, 'http://x').pathname;
      requests.push({ method: req.method, path, rawHeaders: req.rawHeaders.slice(), headers: { ...req.headers }, body });
      if (hang.includes(path)) return;
      const json = (code, obj, extra = {}) => { res.writeHead(code, { 'content-type': 'application/json', ...extra }); res.end(obj === undefined ? '' : JSON.stringify(obj)); };
      if (req.method === 'OPTIONS') { res.writeHead(204, { allow: path === '/api/items' ? 'GET, POST' : 'GET' }); return res.end(); }
      if (req.method === 'GET' && path === '/') {
        res.writeHead(200, { 'content-type': 'text/html' });
        return res.end('<!doctype html><html><head><script type="module" src="/assets/app-1.js"></script></head><body></body></html>');
      }
      if (req.method === 'GET' && path === '/assets/app-1.js') { res.writeHead(200, { 'content-type': 'text/javascript' }); return res.end(BUNDLE); }
      if (req.method === 'GET' && path === '/openapi.json') {
        const paths = { '/api/reports': { get: {} }, '/api/users/{id}': { get: {} }, '/api/items': { get: {}, post: {} } };
        for (let i = 0; i < extraPaths; i++) paths[`/api/extra${i}`] = { get: {} };
        return json(200, { openapi: '3.0.0', info: { title: 'x', version: '1' }, paths });
      }
      if (req.method === 'GET' && path === '/api/users') return json(200, [{ id: 1, email: VALUES.email, name: VALUES.name }]);
      if (req.method === 'GET' && path === '/api/invoices') return json(200, [{ id: 3, total: 10, customer_email: VALUES.email }]);
      if (req.method === 'GET' && path === '/api/me') return json(401, { error: 'not signed in' });
      if (req.method === 'GET' && path === '/api/health') return json(200, { status: 'ok' });
      if (req.method === 'GET' && path === '/api/reports') return json(200, { reports: [{ id: 7, title: VALUES.report }] });
      if (req.method === 'GET' && path === '/api/items') return json(401, { error: 'no' });
      if (req.method === 'POST' && path === '/api/items') return json(201, { id: 99, value: VALUES.created });
      if (req.method === 'GET' && /^\/api\/extra\d+$/.test(path)) return json(200, { ok: true });
      if (req.method !== 'GET') return json(405, { error: 'method' });
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><html><body>spa</body></html>');
    });
  });
  return new Promise((resolve, reject) => {
    s.once('error', reject);
    s.listen(port, '127.0.0.1', () => resolve({ server: s, requests, url: `http://localhost:${s.address().port}` }));
  });
}

/** Header names that would carry or claim an identity. */
export function identityHeaderNames(headers) {
  return Object.keys(headers).filter((h) => /^x-appcrane-/i.test(h) || ['cookie', 'authorization', 'x-api-key', 'proxy-authorization'].includes(h.toLowerCase()));
}
