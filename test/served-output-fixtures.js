import { mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from 'fs';
import { join, normalize } from 'path';
import http from 'node:http';

// A built Vite-style dist on disk with planted credentials, a static server
// for it with an SPA fallback, and a PostgREST imitation for the RLS probe.

export const REF = 'abcdefghijklmnopqrst';

export function makeJwt(payload) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b({ alg: 'HS256', typ: 'JWT' })}.${b(payload)}.${'Q2xvdWRzaWduYXR1cmVYeXo'.repeat(2)}`;
}

export const SECRETS = {
  serviceRole: makeJwt({ iss: 'supabase', ref: REF, role: 'service_role', iat: 1700000000, exp: 2000000000 }),
  stripeLive: ['sk', 'live', 'PretendTestValue0000Zz9'].join('_'),
  openaiInMap: `sk-proj-${'Zx9'.repeat(12)}`,
  envFileKey: `sk-ant-api03-${'Yb7Q'.repeat(8)}`,
  tokenInHiddenMap: `ghp_${'Pq4W'.repeat(9)}`,
};
export const ANON = makeJwt({ iss: 'supabase', ref: REF, role: 'anon', iat: 1700000000, exp: 2000000000 });

/** Writes dist/ under root; asset URLs carry basePath, as a Vite build with base set does. */
export function buildDist(root, { basePath = '/' } = {}) {
  const dist = join(root, 'dist');
  const base = basePath.endsWith('/') ? basePath : `${basePath}/`;
  mkdirSync(join(dist, 'assets'), { recursive: true });
  writeFileSync(join(dist, 'index.html'),
    '<!doctype html><html><head>\n' +
    `<script type="module" crossorigin src="${base}assets/index-a1b2c3.js"></script>\n` +
    `<link rel="stylesheet" href="${base}assets/index-d4e5f6.css">\n` +
    '</head><body><input placeholder="Search"><div id="root"></div></body></html>\n');
  writeFileSync(join(dist, 'assets', 'index-a1b2c3.js'),
    `import{v as e}from"./vendor-9z8y7x.js";const t="https://${REF}.supabase.co",n="${ANON}";` +
    `const admin="${SECRETS.serviceRole}";` +
    `const pay=new Stripe("${SECRETS.stripeLive}");` +
    'e(t,n).from("profiles").select("*");e(t,n).from("notes").select("*");' +
    `fetch(t+"/rest/v1/notes",{headers:{Authorization:"Bearer ${ANON}"}});` +
    'const lazy=()=>import("./lazy-k3j4.js");\n');
  mkdirSync(join(dist, 'maps'), { recursive: true });
  writeFileSync(join(dist, 'assets', 'vendor-9z8y7x.js'), 'export const v=(a,b)=>({from:()=>({select(){}})});\n//# sourceMappingURL=../maps/vendor.map\n');
  writeFileSync(join(dist, 'maps', 'vendor.map'), JSON.stringify({
    version: 3, sources: ['../src/lib/ai.ts'], names: [], mappings: 'AAAA',
    sourcesContent: [`export const client = new OpenAI({ apiKey: "${SECRETS.openaiInMap}" });\n`],
  }));
  writeFileSync(join(dist, 'assets', 'lazy-k3j4.js'), 'export default function(){return 1}\n');
  writeFileSync(join(dist, 'assets', 'lazy-k3j4.js.map'), JSON.stringify({
    version: 3, sources: ['../src/gh.ts'], names: [], mappings: 'AAAA',
    sourcesContent: [`const octokit = new Octokit({ auth: "${SECRETS.tokenInHiddenMap}" });\n`],
  }));
  writeFileSync(join(dist, 'assets', 'index-d4e5f6.css'), 'body{margin:0}\n');
  writeFileSync(join(dist, '.env'), `VITE_SUPABASE_URL=https://${REF}.supabase.co\nANTHROPIC_API_KEY=${SECRETS.envFileKey}\n`);
  return dist;
}

/** A static server for a dir with an SPA fallback: an unknown path answers index.html with 200. */
export function serveDir(dir, port = 0) {
  const types = { '.js': 'text/javascript', '.css': 'text/css', '.map': 'application/json', '.html': 'text/html' };
  const s = http.createServer((req, res) => {
    const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = normalize(join(dir, p));
    if (file.startsWith(dir) && existsSync(file) && statSync(file).isFile()) {
      const ext = file.slice(file.lastIndexOf('.'));
      res.writeHead(200, { 'content-type': types[ext] || 'text/plain' });
      return res.end(readFileSync(file));
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(readFileSync(join(dir, 'index.html')));
  });
  return new Promise((resolve, reject) => {
    s.once('error', reject);
    s.listen(port, '127.0.0.1', () => resolve(s));
  });
}

/**
 * PostgREST imitation: /rest/v1/ lists profiles, notes and an rpc; profiles
 * returns a row to the anon key, notes answers 401. Every request is logged.
 */
export function postgrestMock({ openapiStatus = 200 } = {}) {
  const requests = [];
  const s = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, apikey: req.headers.apikey, authorization: req.headers.authorization });
    const u = new URL(req.url, 'http://x');
    const json = (code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.method !== 'GET') return json(405, { message: 'read-only mock' });
    if (req.headers.apikey !== ANON) return json(401, { message: 'Invalid API key' });
    if (u.pathname === '/rest/v1/') {
      if (openapiStatus !== 200) return json(openapiStatus, { message: 'no' });
      return json(200, { swagger: '2.0', paths: { '/': {}, '/profiles': {}, '/notes': {}, '/rpc/do_thing': {} }, definitions: { profiles: {} } });
    }
    if (u.pathname === '/rest/v1/profiles') return json(200, [{ id: 1, email: 'row-content-must-not-leak@example.test' }]);
    if (u.pathname === '/rest/v1/notes') return json(401, { message: 'permission denied for table notes' });
    return json(404, { message: 'relation does not exist' });
  });
  return new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve({ server: s, requests, url: `http://127.0.0.1:${s.address().port}` })));
}
