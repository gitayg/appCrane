import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Integrity guard for server/services/appCatalog.json — the curated list behind
// the self-hostable app catalogue.
//
// This file has no owner and no CI that reads it, which is exactly the shape of
// data that rots. The MCP connector catalogue in this repo did precisely that:
// it drifted 22 tools behind the platform, silently, because nothing failed when
// it fell out of date. The fix there was a guard test, so this is the same guard
// for the same failure mode.
//
// Deliberately NETWORK-FREE. Whether an image still resolves is a question for a
// live registry and would make this suite flaky and rate-limited; this asserts
// the invariants that a human edit can break without noticing.

const CATALOG = JSON.parse(
  readFileSync(new URL('../server/services/appCatalog.json', import.meta.url), 'utf8'),
);

test('the catalogue is a non-empty array of objects', () => {
  assert.ok(Array.isArray(CATALOG), 'catalogue must be an array');
  assert.ok(CATALOG.length > 0, 'catalogue must not be empty');
});

test('every entry carries the fields the page and the deploy path need', () => {
  for (const e of CATALOG) {
    for (const k of ['name', 'slug', 'category', 'repo', 'short']) {
      assert.equal(typeof e[k], 'string', `${e.slug || '(no slug)'}: ${k} must be a string`);
      assert.ok(e[k].trim(), `${e.slug || '(no slug)'}: ${k} must not be blank`);
    }
    // owner/repo, because catalogService builds a GitHub URL out of it. A value
    // of any other shape is how a manifest field becomes an SSRF vector.
    assert.match(e.repo, /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/, `${e.slug}: repo must be owner/repo`);
  }
});

test('slugs are unique — a duplicate silently shadows an entry in any keyed lookup', () => {
  const seen = new Map();
  for (const e of CATALOG) {
    assert.ok(!seen.has(e.slug), `duplicate slug: ${e.slug}`);
    seen.set(e.slug, true);
  }
});

test('image is a non-empty string or explicitly null, never an empty string', () => {
  // null means "this project publishes no usable first-party image", which the
  // page reads to offer the GitHub path only. An empty string would pass a
  // truthiness check somewhere and render a Deploy button that cannot work.
  for (const e of CATALOG) {
    if (e.image === null) continue;
    assert.equal(typeof e.image, 'string', `${e.slug}: image must be a string or null`);
    assert.ok(e.image.trim(), `${e.slug}: image must be null rather than blank`);
    assert.ok(!e.image.startsWith('library/'),
      `${e.slug}: 'library/x' is Docker Hub's internal namespace for official images; the pullable reference is 'x'`);
  }
});

test('no volatile figures are committed', () => {
  // Stars, pull counts and versions are true the day they are written and
  // misleading a month later. They are fetched live and cached by
  // catalogService; committing one guarantees the page eventually lies.
  const VOLATILE = ['stars', 'pulls', 'version', 'release', 'last', 'pushed', 'archived', 'status'];
  for (const e of CATALOG) {
    for (const k of VOLATILE) {
      assert.ok(!(k in e), `${e.slug}: '${k}' is volatile and must not be committed — fetch it live`);
    }
  }
});

test('no entry ships an image that is one component of a multi-container app', () => {
  // Such an image resolves, so registry validation passes, but deploying it
  // alone produces a container that starts and cannot work: it wants a database,
  // a worker, or a separate frontend. Seven entries were removed for this
  // (Plane, Saleor, Huly, AppFlowy, Bigcapital, Taiga, metasfresh). This guard
  // stops one being reintroduced by a well-meaning addition.
  //
  // 'element-web' is deliberately NOT caught: Element Web is the whole product,
  // not a fragment of one, and runs standalone.
  const COMPONENTISH = /(^|[/_-])(server|backend|back|frontend|webapi|webui|cloud)($|[/_:-])/i;
  for (const e of CATALOG) {
    if (!e.image) continue;
    const name = e.image.split(':')[0];
    assert.ok(!COMPONENTISH.test(name),
      `${e.slug}: image '${e.image}' looks like one component of a multi-container app. `
      + 'Deploying it alone yields a broken app. Remove the entry, or set image to null and '
      + 'offer the GitHub path only.');
  }
});

test('entries stay sorted by category then name', () => {
  // Plain codepoint comparison, not localeCompare: localeCompare is
  // case-insensitive and locale-aware, so it orders 'Commerce' before 'CRM'
  // while the file is generated in codepoint order. It also varies with the
  // runtime's ICU data, which is not something a test should depend on.
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  const sorted = [...CATALOG].sort(
    (a, b) => cmp(a.category, b.category) || cmp(a.name.toLowerCase(), b.name.toLowerCase()),
  );
  assert.deepEqual(CATALOG.map((e) => e.slug), sorted.map((e) => e.slug),
    'keep the file sorted so diffs stay readable and additions land in an obvious place');
});

// ---------------------------------------------------------------------------
// Install hints: port, health, url_env, secrets
// ---------------------------------------------------------------------------
//
// All four are OPTIONAL, and null is the correct value for anything that could
// not be established from the image's own EXPOSE, the upstream docs, or the
// image's README. These tests therefore assert SHAPE, never coverage: a test
// that demanded a port on every entry would be answered by guessing one, and a
// guessed port fails the deploy health check and destroys the container — worse
// than the blank field the operator would otherwise fill in.

const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SECRET_ENCODINGS = new Set(['base64', 'base64url', 'hex']);

test('every declared port is an integer in the real port range', () => {
  for (const e of CATALOG) {
    if (e.port === undefined || e.port === null) continue;
    assert.equal(typeof e.port, 'number', `${e.slug}: port must be a number`);
    assert.ok(Number.isInteger(e.port), `${e.slug}: port must be a whole number, got ${e.port}`);
    assert.ok(e.port >= 1 && e.port <= 65535, `${e.slug}: port must be 1-65535, got ${e.port}`);
  }
});

test('every declared health path is a rooted path', () => {
  // routes/apps.js and mcpTools.js both refuse a health_path that does not
  // start with '/', so a manifest value that does not would be dropped or
  // rejected at install time rather than used.
  for (const e of CATALOG) {
    if (e.health === undefined || e.health === null) continue;
    assert.equal(typeof e.health, 'string', `${e.slug}: health must be a string`);
    assert.ok(e.health.startsWith('/'), `${e.slug}: health must start with '/', got ${JSON.stringify(e.health)}`);
    assert.ok(!/\s/.test(e.health), `${e.slug}: health must not contain whitespace`);
  }
});

test('every declared secret is a generatable declaration and never a value', () => {
  for (const e of CATALOG) {
    if (e.secrets === undefined || e.secrets === null) continue;
    assert.ok(Array.isArray(e.secrets), `${e.slug}: secrets must be an array`);
    assert.ok(e.secrets.length > 0, `${e.slug}: secrets must be omitted rather than empty`);
    const names = new Set();
    for (const s of e.secrets) {
      assert.ok(s && typeof s === 'object' && !Array.isArray(s), `${e.slug}: each secret must be an object`);
      assert.match(String(s.env), ENV_NAME_RE,
        `${e.slug}: secret env must be an environment-variable identifier, got ${JSON.stringify(s.env)}`);
      assert.ok(!names.has(s.env), `${e.slug}: secret ${s.env} is declared twice`);
      names.add(s.env);
      // 16 bytes is 128 bits, the floor for a key worth generating; 256 is far
      // past every documented requirement here and exists so a typo cannot ask
      // the browser for a megabyte of entropy.
      assert.equal(typeof s.bytes, 'number', `${e.slug}: ${s.env} must declare bytes`);
      assert.ok(Number.isInteger(s.bytes) && s.bytes >= 16 && s.bytes <= 256,
        `${e.slug}: ${s.env} bytes must be a whole number 16-256, got ${s.bytes}`);
      assert.ok(SECRET_ENCODINGS.has(s.encoding),
        `${e.slug}: ${s.env} encoding must be one of ${[...SECRET_ENCODINGS].join('/')}, got ${JSON.stringify(s.encoding)}`);
      if (s.prefix !== undefined) {
        assert.equal(typeof s.prefix, 'string', `${e.slug}: ${s.env} prefix must be a string`);
      }
      // A committed value would be the same secret on every install of every
      // AppCrane on earth, which is the failure this whole field exists to
      // avoid. The manifest describes the shape; the browser draws the bytes.
      for (const forbidden of ['value', 'default', 'secret']) {
        assert.ok(!(forbidden in s),
          `${e.slug}: ${s.env} carries '${forbidden}' — a secret must be generated per install, never committed`);
      }
    }
  }
});

test('every declared url_env names environment variables', () => {
  for (const e of CATALOG) {
    if (e.url_env === undefined || e.url_env === null) continue;
    const list = Array.isArray(e.url_env) ? e.url_env : [e.url_env];
    assert.ok(list.length > 0, `${e.slug}: url_env must be omitted rather than empty`);
    for (const v of list) {
      assert.match(String(v), ENV_NAME_RE,
        `${e.slug}: url_env must name an environment variable, got ${JSON.stringify(v)}`);
    }
  }
});

test('no entry declares a secret or url_env that collides with its own database variables', () => {
  // A collision is silent and total: the install dialog writes one `vars`
  // object, so whichever key is assigned last wins and the app gets a random
  // 32 bytes where its DB_PASSWORD should be, or a database password where its
  // APP_KEY should be. Either way it does not start, and nothing says why.
  for (const e of CATALOG) {
    const needs = e.needs && typeof e.needs === 'object' && !Array.isArray(e.needs) ? e.needs : null;
    const dbNames = new Set();
    for (const v of Object.values(needs?.env || {})) if (typeof v === 'string' && v) dbNames.add(v);
    if (typeof needs?.url_env === 'string' && needs.url_env) dbNames.add(needs.url_env);
    if (dbNames.size === 0) continue;

    for (const s of e.secrets || []) {
      assert.ok(!dbNames.has(s.env),
        `${e.slug}: secret ${s.env} collides with a needs.env database variable of the same name`);
    }
    const urls = e.url_env === undefined || e.url_env === null
      ? [] : Array.isArray(e.url_env) ? e.url_env : [e.url_env];
    for (const v of urls) {
      assert.ok(!dbNames.has(v),
        `${e.slug}: url_env ${v} collides with a needs.env database variable of the same name`);
    }
  }
});

test('the BookStack entry carries the four settings its install actually needed', () => {
  // The known-good case, verified against a live install: container_port 80
  // (linuxserver/* serves nginx on 80, not AppCrane's default 3000), health
  // /status (Laravel /api/health does not exist; /status answers
  // {"database":true,...}), APP_KEY (without it the container prints "The
  // application key is missing, halting init!" and dies) and APP_URL (or every
  // absolute link is built against the wrong base behind the stripped prefix).
  // Each of those was a failed deploy before it was a manifest field, so this
  // test is the record that they are all four still there.
  const bs = CATALOG.find(e => e.slug === 'bookstack');
  assert.ok(bs, 'the catalogue must still carry a bookstack entry');
  assert.equal(bs.port, 80, 'BookStack serves nginx on 80');
  assert.equal(bs.health, '/status', 'BookStack answers 200 at /status');
  assert.equal(bs.url_env, 'APP_URL', 'BookStack builds absolute links from APP_URL');
  const appKey = (bs.secrets || []).find(s => s.env === 'APP_KEY');
  assert.ok(appKey, 'BookStack must declare an APP_KEY secret');
  assert.equal(appKey.bytes, 32, 'a Laravel application key is 32 random bytes');
  assert.equal(appKey.encoding, 'base64');
  assert.equal(appKey.prefix, 'base64:', 'Laravel requires the base64: prefix on APP_KEY');
});

test('the catalogue carries no personal or employer identifiers', () => {
  // This repo is public and was cleaned of exactly this in v2.59.0. A catalogue
  // entry is an easy place to reintroduce one via a copied URL.
  const raw = readFileSync(new URL('../server/services/appCatalog.json', import.meta.url), 'utf8');
  assert.ok(!/@(?!example\.com)[a-z0-9.-]+\.[a-z]{2,}/i.test(raw.replace(/https?:\/\/[^"]*/g, '')),
    'catalogue contains what looks like an email address');
});
