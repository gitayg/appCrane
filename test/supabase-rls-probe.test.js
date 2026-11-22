import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { probeSupabaseRls, supabaseUrlForRef } from '../server/services/supabaseRlsProbe.js';
import { postgrestMock, ANON, SECRETS, REF } from './served-output-fixtures.js';

// The RLS probe against a local PostgREST imitation, never a real project.

const mocks = [];
after(() => { for (const m of mocks) { m.server.closeAllConnections?.(); m.server.close(); } });

test('reports the table that returns rows to anon and not the one that answers 401; GET only, anon key only', async () => {
  const m = await postgrestMock();
  mocks.push(m);
  const r = await probeSupabaseRls({ baseUrl: m.url, anonKey: ANON });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.listed_from, ['openapi']);
  assert.deepEqual(r.tables.map((t) => `${t.name}:${t.status}`).sort(), ['notes:not_readable', 'profiles:readable']);
  assert.ok(!JSON.stringify(r).includes('row-content-must-not-leak'), 'row contents are not kept');
  assert.ok(m.requests.length >= 3);
  for (const q of m.requests) {
    assert.equal(q.method, 'GET');
    assert.equal(q.apikey, ANON);
    assert.equal(q.authorization, `Bearer ${ANON}`);
  }
  const reads = m.requests.filter((q) => q.url !== '/rest/v1/').map((q) => q.url).sort();
  assert.deepEqual(reads, ['/rest/v1/notes?select=*&limit=1', '/rest/v1/profiles?select=*&limit=1']);
});

test('a closed OpenAPI root falls back to the tables the bundle queries', async () => {
  const m = await postgrestMock({ openapiStatus: 401 });
  mocks.push(m);
  const r = await probeSupabaseRls({ baseUrl: m.url, anonKey: ANON, tables: ['profiles'] });
  assert.equal(r.openapi_status, 401);
  assert.deepEqual(r.listed_from, ['bundle']);
  assert.deepEqual(r.tables.map((t) => `${t.name}:${t.status}`), ['profiles:readable']);
  const none = await probeSupabaseRls({ baseUrl: m.url, anonKey: ANON });
  assert.equal(none.ok, false, 'nothing listed is not a clean result');
});

test('refuses a service_role key before any request is made', async () => {
  const m = await postgrestMock();
  mocks.push(m);
  await assert.rejects(() => probeSupabaseRls({ baseUrl: m.url, anonKey: SECRETS.serviceRole }), /anon or publishable key only/);
  assert.equal(m.requests.length, 0);
});

test('only https://<ref>.supabase.co is ever a target', () => {
  assert.equal(supabaseUrlForRef(REF), `https://${REF}.supabase.co`);
  assert.equal(supabaseUrlForRef('127.0.0.1'), null);
  assert.equal(supabaseUrlForRef('evil.example/x'), null);
});
