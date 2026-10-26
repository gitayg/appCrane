import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';

// Adopt an app: static analysis of the four hand-made exports under
// test/fixtures/adopt, the secret scanner, the archive reader's refusals and
// the generated build files. Nothing here runs a project's code.

const { buildReport } = await import('../server/services/adopt/report.js');
const { readProjectZip, ArchiveRefused } = await import('../server/services/adopt/archive.js');
const { scaffoldFor } = await import('../server/services/adopt/report.js');
const { parseRepoUrl, downloadGithubZip } = await import('../server/services/adopt/sources.js');
const { validateDockerfile } = await import('../server/services/dockerfileValidator.js');
const { makeZip, dirEntries, dirFiles, fakeJwt } = await import('./fixtures/adopt/makeZip.js');

const FIX = fileURLToPath(new URL('./fixtures/adopt/', import.meta.url));
const fixture = (name) => dirFiles(join(FIX, name));
const envKeys = (r) => r.env.map((v) => v.key).sort();
const ids = (items) => items.map((i) => i.id);

const SERVICE_ROLE = fakeJwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'service_role', iat: 1700000000, exp: 2000000000 });
const ANON = fakeJwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'anon', iat: 1700000000, exp: 2000000000 });

test('Lovable export: Vite SPA, Supabase auth + database, edge-function env kept apart', () => {
  const r = buildReport(fixture('lovable-vite-supabase'), { name: 'todos' });
  assert.equal(r.project.origin.tool, 'lovable');
  assert.equal(r.project.origin.confidence, 'high');
  assert.equal(r.project.framework, 'vite-spa');
  assert.equal(r.project.kind, 'spa');
  assert.equal(r.project.output_dir, 'dist');
  assert.match(r.project.build, /vite build --base "\$\{APP_BASE_PATH:-\.\/\}"/);
  assert.equal(r.project.port.container, 3000);
  assert.deepEqual(envKeys(r), ['VITE_SUPABASE_PUBLISHABLE_KEY', 'VITE_SUPABASE_URL']);
  assert.ok(r.env.every((v) => v.scope === 'client' && v.build_time), JSON.stringify(r.env));
  assert.deepEqual(r.supabase_edge_env, ['OPENAI_API_KEY']);
  const sb = r.backends.supabase;
  assert.equal(sb.used, true);
  assert.equal(sb.auth, true);
  assert.deepEqual(sb.auth_methods, ['signInWithPassword']);
  assert.equal(sb.database, true);
  assert.deepEqual(sb.tables, ['todos']);
  assert.equal(sb.migrations, true);
  assert.equal(sb.edge_functions, true);
  assert.ok(ids(r.changes).includes('supabase-auth'));
  assert.ok(ids(r.changes).includes('supabase-db'));
  assert.ok(ids(r.changes).includes('router-basename'));
  assert.match(r.changes.find((c) => c.id === 'supabase-auth').detail, /signed identity|verified identity/);
  assert.deepEqual(r.scaffold.map((s) => s.path).sort(), ['.dockerignore', 'Dockerfile', 'appcrane-serve.mjs', 'deployhub.json']);
  assert.equal(r.risks.length, 0);
  assert.equal(r.verdict, 'works_with_changes');
});

test('v0 export: Next.js app router on pnpm, server and client env split, health route added', () => {
  const r = buildReport(fixture('v0-next'), { name: 'pricing' });
  assert.equal(r.project.origin.tool, 'v0');
  assert.equal(r.project.framework, 'next');
  assert.equal(r.project.kind, 'ssr');
  assert.equal(r.project.package_manager, 'pnpm');
  assert.equal(r.project.build, 'pnpm run build');
  assert.equal(r.project.start, 'npx next start -p 3000');
  const byKey = Object.fromEntries(r.env.map((v) => [v.key, v]));
  assert.deepEqual(Object.keys(byKey).sort(), ['NEXT_PUBLIC_ANALYTICS_ID', 'OPENAI_API_KEY']);
  assert.equal(byKey.OPENAI_API_KEY.scope, 'server');
  assert.equal(byKey.OPENAI_API_KEY.build_time, false);
  assert.equal(byKey.NEXT_PUBLIC_ANALYTICS_ID.scope, 'client');
  assert.equal(byKey.NEXT_PUBLIC_ANALYTICS_ID.build_time, true);
  assert.equal(r.backends.supabase.used, false);
  assert.ok(r.backends.ai_providers.includes('Vercel AI SDK'));
  assert.ok(ids(r.changes).includes('next-subpath'));
  assert.deepEqual(r.scaffold.map((s) => s.path).sort(), ['.dockerignore', 'Dockerfile', 'app/api/health/route.js', 'deployhub.json']);
});

test('Bolt zip: .bolt marker found through the zip reader, Supabase anon env, uploaded .env values never in the report', () => {
  const entries = [
    ...dirEntries(join(FIX, 'bolt-vite'), 'project/'),
    { name: 'project/.env', data: `VITE_SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co\nVITE_SUPABASE_ANON_KEY=${ANON}\n` },
  ];
  const { files, stripped } = readProjectZip(makeZip(entries));
  assert.equal(stripped, 'project');
  assert.ok(files.has('.bolt/config.json'));
  const r = buildReport(files, { name: 'bookings' });
  assert.equal(r.project.origin.tool, 'bolt');
  assert.deepEqual(r.project.origin.evidence, ['.bolt/ directory', 'template bolt-vite-react-ts']);
  assert.equal(r.project.framework, 'vite-spa');
  assert.deepEqual(envKeys(r), ['VITE_SUPABASE_ANON_KEY', 'VITE_SUPABASE_URL']);
  assert.ok(r.env.every((v) => v.value_in_upload === true));
  assert.equal(r.backends.supabase.database, true);
  assert.deepEqual(r.backends.supabase.tables, ['bookings']);
  assert.equal(r.backends.supabase.auth, false);
  const json = JSON.stringify(r);
  assert.ok(!json.includes(ANON), 'an uploaded .env value reached the report');
  assert.equal(r.verdict, 'ready');
});

test('Replit export: Express server with build, port 5000 flagged, health endpoint required, server env', () => {
  const r = buildReport(fixture('replit-express'), { name: 'inventory' });
  assert.equal(r.project.origin.tool, 'replit');
  assert.equal(r.project.framework, 'node-server');
  assert.equal(r.project.kind, 'server');
  assert.equal(r.project.build, 'npm run build');
  assert.equal(r.project.start, 'npm run start');
  assert.deepEqual(r.project.port.literal_ports, [5000]);
  assert.equal(r.project.port.replit_local_port, 5000);
  assert.equal(r.project.port.reads_env_port, false);
  assert.deepEqual(r.project.replit.deployment, { run: 'npm run start', build: 'npm run build' });
  assert.deepEqual(envKeys(r), ['DATABASE_URL', 'SESSION_SECRET']);
  assert.ok(r.env.every((v) => v.scope === 'server' && !v.build_time));
  assert.ok(r.backends.databases.includes('postgres'));
  const port = r.changes.find((c) => c.id === 'port');
  assert.ok(port && port.blocking && port.request, JSON.stringify(r.changes));
  assert.ok(r.changes.find((c) => c.id === 'health')?.blocking);
  assert.equal(r.verdict, 'needs_changes');
});

test('a Supabase service-role key in client code is critical; the same key in a server route is high; an anon key is info', () => {
  const files = fixture('bolt-vite');
  files.set('src/lib/supabaseAdmin.ts', Buffer.from(`import { createClient } from '@supabase/supabase-js';\nexport const admin = createClient('https://abcdefghijklmnopqrst.supabase.co', '${SERVICE_ROLE}');\n`));
  const r = buildReport(files, { name: 'leaky' });
  const sr = r.risks.find((x) => x.rule === 'supabase-service-role-key');
  assert.ok(sr, JSON.stringify(r.risks));
  assert.equal(sr.severity, 'critical');
  assert.equal(sr.side, 'client');
  assert.equal(sr.request, true);
  assert.equal(r.risk_counts.critical, 1);
  assert.equal(r.verdict, 'critical_risks');
  assert.ok(!JSON.stringify(r).includes(SERVICE_ROLE), 'the key itself reached the report');

  const server = fixture('replit-express');
  server.set('server/admin.ts', Buffer.from(`export const key = '${SERVICE_ROLE}';\n`));
  server.set('client/src/anon.ts', Buffer.from(`export const anon = '${ANON}';\n`));
  const r2 = buildReport(server, { name: 'srv' });
  assert.equal(r2.risks.find((x) => x.rule === 'supabase-service-role-key').severity, 'high');
  assert.equal(r2.risks.find((x) => x.rule === 'supabase-anon-key').severity, 'info');
  assert.equal(r2.risk_counts.critical, 0);
});

test('zip-slip and other unsafe entry names refuse the whole archive', () => {
  for (const name of ['../evil.txt', 'a/../../evil.txt', '/etc/passwd', 'C:/x.txt', 'a\\..\\b.txt', 'ok/\0.txt']) {
    const zip = makeZip([{ name: 'package.json', data: '{}' }, { name, data: 'x' }]);
    assert.throws(() => readProjectZip(zip), (e) => e instanceof ArchiveRefused && e.code === 'ARCHIVE_UNSAFE_PATH', name);
  }
});

test('symlinks are skipped (never followed); node_modules, .git and build output are not imported', () => {
  const { files, skipped } = readProjectZip(makeZip([
    { name: 'index.html', data: '<html></html>' },
    { name: 'link', data: '/etc/passwd', symlink: true },
    { name: 'node_modules/x/index.js', data: 'x' },
    { name: '.git/config', data: 'x' },
    { name: '.next/cache/a', data: 'x' },
  ]));
  assert.deepEqual([...files.keys()], ['index.html']);
  assert.deepEqual(skipped, [{ path: 'link', reason: 'symlink (not followed)' }]);
});

test('size limits: archive bytes, per-file bytes, total bytes and file count', () => {
  const base = { maxArchiveBytes: 1e6, maxTotalBytes: 1e6, maxFileBytes: 1e6, maxEntries: 100, maxFiles: 100 };
  const zip = makeZip([{ name: 'index.html', data: 'x'.repeat(5000) }, { name: 'b.txt', data: 'y'.repeat(5000) }]);
  assert.throws(() => readProjectZip(zip, { ...base, maxArchiveBytes: 1000 }), { code: 'ARCHIVE_TOO_LARGE' });
  assert.throws(() => readProjectZip(zip, { ...base, maxTotalBytes: 7000 }), { code: 'ARCHIVE_TOO_LARGE' });
  assert.throws(() => readProjectZip(zip, { ...base, maxFiles: 1 }), { code: 'ARCHIVE_TOO_MANY_FILES' });
  assert.throws(() => readProjectZip(zip, { ...base, maxEntries: 1 }), { code: 'ARCHIVE_TOO_MANY_ENTRIES' });
  const mixed = makeZip([{ name: 'index.html', data: 'x'.repeat(5000) }, { name: 'small.txt', data: 'ok' }]);
  const r = readProjectZip(mixed, { ...base, maxFileBytes: 4000 });
  assert.deepEqual([...r.files.keys()], ['small.txt']);
  assert.deepEqual(r.skipped, [{ path: 'index.html', reason: 'over 4000 bytes' }]);
});

test('a deflated entry that lies about its size stops at the per-file cap instead of filling memory', () => {
  const zip = makeZip([
    { name: 'index.html', data: '<html></html>' },
    { name: 'bomb.txt', data: Buffer.alloc(8 * 1024 * 1024), deflate: true, declaredSize: 10 },
  ]);
  const r = readProjectZip(zip, { maxArchiveBytes: 1e6, maxTotalBytes: 1e6, maxFileBytes: 64 * 1024, maxEntries: 10, maxFiles: 10 });
  assert.deepEqual([...r.files.keys()], ['index.html']);
  assert.deepEqual(r.skipped, [{ path: 'bomb.txt', reason: `over ${64 * 1024} bytes` }]);
});

test('generated Dockerfiles pass the deployer\'s own Dockerfile validation (port 3000, non-root, no ENV secrets)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adopt-df-'));
  try {
    for (const name of ['lovable-vite-supabase', 'v0-next', 'bolt-vite', 'replit-express']) {
      const df = scaffoldFor(fixture(name), name).find((f) => f.path === 'Dockerfile');
      assert.ok(df, `${name}: no Dockerfile generated`);
      writeFileSync(join(dir, 'Dockerfile'), df.content);
      const v = validateDockerfile(dir, { expectedPort: 3000 });
      assert.deepEqual(v.errors, [], `${name}: ${v.errors.join('; ')}`);
      assert.deepEqual(v.warnings, [], `${name}: ${v.warnings.join('; ')}`);
      assert.match(df.content, /^ARG APP_BASE_PATH=\//m);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a project that already has a Dockerfile or deployhub.json keeps it', () => {
  const files = fixture('replit-express');
  files.set('Dockerfile', Buffer.from('FROM node:20\nUSER node\nEXPOSE 3000\n'));
  files.set('deployhub.json', Buffer.from('{"name":"x"}'));
  assert.deepEqual(scaffoldFor(files, 'x').map((f) => f.path), []);
});

test('tool project URLs are answered with the export step; GitHub URLs parse; a foreign redirect is refused', async () => {
  for (const [url, tool] of [['https://lovable.dev/projects/abc', 'lovable'], ['https://bolt.new/~/sb1-x', 'bolt'], ['https://v0.app/chat/xyz', 'v0'], ['https://replit.com/@u/app', 'replit']]) {
    assert.throws(() => parseRepoUrl(url), (e) => e.code === 'TOOL_URL_NOT_RESOLVABLE' && e.tool === tool && /GitHub/.test(e.message), url);
  }
  assert.deepEqual(parseRepoUrl('https://github.com/acme/todo-app/tree/dev'), { owner: 'acme', repo: 'todo-app', ref: 'dev', label: 'acme/todo-app@dev' });
  assert.throws(() => parseRepoUrl('https://github.com/acme/todo/tree/..%2F..'), { code: 'VALIDATION' });

  const realFetch = global.fetch;
  try {
    global.fetch = async () => ({ status: 302, headers: new Headers({ location: 'https://evil.example/zip' }) });
    await assert.rejects(downloadGithubZip({ owner: 'a', repo: 'b', ref: null }), /unexpected host/);
    global.fetch = async () => ({ status: 404, headers: new Headers() });
    await assert.rejects(downloadGithubZip({ owner: 'a', repo: 'b', ref: null }), { code: 'REPO_NOT_FOUND' });
  } finally { global.fetch = realFetch; }
});
