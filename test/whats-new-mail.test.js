import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'net';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

// After an AppCrane upgrade, app owners and platform admins get one
// "What's new" mail per release. Pinned here: the first boot is silent, a bump
// mails exactly the right people with exactly the right versions' notes, and
// restarts, crashes mid-send, racing processes, downgrades and the off switch
// cannot produce a second mail or a backlog.

const inbox = [];
const smtp = net.createServer((sock) => {
  let buf = '', inData = false, data = '';
  let envelope = { to: [] };
  sock.write('220 fake ESMTP\r\n');
  sock.on('error', () => {});
  sock.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    for (;;) {
      const i = buf.indexOf('\r\n');
      if (i < 0) break;
      const line = buf.slice(0, i);
      buf = buf.slice(i + 2);
      if (inData) {
        if (line === '.') {
          inData = false;
          inbox.push({ raw: data, envelope });
          data = ''; envelope = { to: [] };
          sock.write('250 Ok\r\n');
        } else data += (line.startsWith('..') ? line.slice(1) : line) + '\r\n';
        continue;
      }
      const cmd = line.split(/[ :]/)[0].toUpperCase();
      const addr = line.match(/<([^>]*)>/)?.[1];
      if (cmd === 'EHLO' || cmd === 'HELO') sock.write('250-fake\r\n250 8BITMIME\r\n');
      else if (cmd === 'MAIL') sock.write('250 Ok\r\n');
      else if (cmd === 'RCPT') { envelope.to.push(addr); sock.write('250 Ok\r\n'); }
      else if (cmd === 'DATA') { inData = true; sock.write('354 go\r\n'); }
      else if (cmd === 'QUIT') { sock.write('221 Bye\r\n'); sock.end(); }
      else sock.write('250 Ok\r\n');
    }
  });
});
await new Promise((res) => smtp.listen(0, '127.0.0.1', res));
process.env.SMTP_HOST = '127.0.0.1';
process.env.SMTP_PORT = String(smtp.address().port);
for (const k of ['SMTP_USER', 'SMTP_PASS', 'GRAPH_TENANT_ID', 'GRAPH_CLIENT_ID', 'GRAPH_CLIENT_SECRET', 'CRANE_DOMAIN']) delete process.env[k];
process.env.BASE_URL = 'https://dashboard.example.test';

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-whats-new-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { enqueueEmail, startEmailWorker, stopEmailWorker } = await import('../server/services/emailQueue.js');
const { announceWhatsNew, whatsNewRecipients, renderWhatsNew, K, SOURCE } = await import('../server/services/whatsNewMail.js');
const { mergeCuratedNotes } = await import('../server/services/releaseNotes.js');

initDb();
const db = getDb();

after(() => { stopEmailWorker(); smtp.close(); });

let seq = 0;
function mkUser(name, email, role = 'user', extra = {}) {
  const id = db.prepare('INSERT INTO users (name, email, role, api_key_hash) VALUES (?,?,?,?)')
    .run(name, email, role, `hash-wn-${++seq}`).lastInsertRowid;
  if (extra.active === 0) db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(id);
  if (extra.kind) db.prepare('UPDATE users SET kind = ? WHERE id = ?').run(extra.kind, id);
  return id;
}
let slot = 300;
function mkApp(slug, ownerId) {
  const appId = db.prepare('INSERT INTO apps (name, slug, slot, source_type, branch, created_by) VALUES (?,?,?,?,?,?)')
    .run(slug, slug, ++slot, 'managed', 'main', ownerId).lastInsertRowid;
  db.prepare(`INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')
    ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = 'owner'`).run(appId, ownerId);
  return appId;
}
function grant(appId, userId, role) {
  db.prepare(`INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
    ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role`).run(appId, userId, role);
}

const owner1 = mkUser('Olga', 'olga@example.com');
const owner2 = mkUser('Omar', 'omar@example.com');
const admin = mkUser('Ada', 'ada@example.com', 'platform_admin');
const adminOwner = mkUser('Abe', 'abe@example.com', 'platform_admin');
const member = mkUser('Mel', 'mel@example.com');
const plainMember = mkUser('Pam', 'pam@example.com');
const gone = mkUser('Gone', 'gone@example.com', 'user', { active: 0 });
const goneAdmin = mkUser('GoneAdmin', 'goneadmin@example.com', 'platform_admin', { active: 0 });
const bot = mkUser('Bot', 'bot@example.com', 'user', { kind: 'agent' });
const botAdmin = mkUser('BotAdmin', 'botadmin@example.com', 'platform_admin', { kind: 'agent' });
const noMail = mkUser('NoMail', null);
const blankMail = mkUser('Blank', '');

const a1 = mkApp('alpha', owner1);
mkApp('beta', owner2);
mkApp('gamma', owner1);
mkApp('delta', adminOwner);
mkApp('eps', gone);
mkApp('zeta', bot);
mkApp('eta', noMail);
mkApp('theta', blankMail);
grant(a1, member, 'admin');
grant(a1, plainMember, 'user');

const EXPECTED = ['abe@example.com', 'ada@example.com', 'olga@example.com', 'omar@example.com'];

const NOTES = [
  { version: '3.0.1', commit_message: 'not shipped here yet' },
  { version: '3.0.0', commit_message: 'big <b>release</b> & more' },
  { version: '2.9.9', commit_message: 'a fix' },
  { version: '2.9.8', commit_message: 'already announced' },
  { version: '2.9.7', commit_message: 'older still' },
];
const notes = async () => NOTES;

const rows = () => db.prepare('SELECT * FROM email_queue WHERE source = ? ORDER BY id').all(SOURCE);
const recorded = () => db.prepare('SELECT value FROM settings WHERE key = ?').get(K.lastAnnounced)?.value ?? null;
const setSetting = (k, v) => db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(k, v);
const clear = () => db.prepare('DELETE FROM email_queue WHERE source = ?').run(SOURCE);

test('recipients: active human owners and platform admins with an e-mail, once each', () => {
  const got = whatsNewRecipients(db).map((u) => u.email).sort();
  assert.deepEqual(got, EXPECTED);
  for (const excluded of ['mel@example.com', 'pam@example.com', 'gone@example.com', 'goneadmin@example.com', 'bot@example.com', 'botadmin@example.com']) {
    assert.ok(!got.includes(excluded), `${excluded} must not be mailed`);
  }
});

test('first boot records the running version and sends nothing', async () => {
  const r = await announceWhatsNew({ db, version: '2.9.8', loadNotes: notes });
  assert.equal(r.status, 'recorded');
  assert.equal(recorded(), '2.9.8');
  assert.equal(rows().length, 0);
});

test('a version bump mails each owner/admin once with the notes in (last, current]', async () => {
  const r = await announceWhatsNew({ db, version: '3.0.0', loadNotes: notes });
  assert.equal(r.status, 'sent');
  assert.equal(r.sent, EXPECTED.length);
  const q = rows();
  assert.deepEqual(q.map((m) => m.to_email).sort(), EXPECTED);
  for (const m of q) {
    assert.equal(m.app_id, null);
    assert.equal(m.idempotency_key, `whats-new:3.0.0:${m.to_email}`);
    assert.equal(m.subject, "[AppCrane] What's new in v3.0.0 (since v2.9.8)");
    assert.match(m.body_text, /- v3\.0\.0: big <b>release<\/b> & more/);
    assert.match(m.body_text, /- v2\.9\.9: a fix/);
    assert.doesNotMatch(m.body_text, /3\.0\.1|already announced|older still/);
    assert.ok(m.body_text.indexOf('v3.0.0:') < m.body_text.indexOf('v2.9.9:'), 'newest first');
    assert.match(m.body_text, /https:\/\/dashboard\.example\.test/);
    assert.match(m.body_html, /big &lt;b&gt;release&lt;\/b&gt; &amp; more/);
    assert.doesNotMatch(m.body_html, /<b>release/);
  }
  assert.equal(recorded(), '3.0.0');
});

test('the queued mail is delivered over SMTP to each recipient', async () => {
  startEmailWorker();
  const deadline = Date.now() + 30_000;
  while (inbox.length < EXPECTED.length && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
  stopEmailWorker();
  assert.deepEqual(inbox.flatMap((m) => m.envelope.to).sort(), EXPECTED);
  for (const m of inbox) assert.match(m.raw, /What's new in v3\.0\.0/);
});

test('a restart at the same version sends nothing more', async () => {
  const before = rows().length;
  const r = await announceWhatsNew({ db, version: '3.0.0', loadNotes: notes });
  assert.equal(r.status, 'unchanged');
  assert.equal(rows().length, before);
});

test('a downgrade sends nothing and keeps the higher recorded version', async () => {
  const before = rows().length;
  const r = await announceWhatsNew({ db, version: '2.9.9', loadNotes: notes });
  assert.equal(r.status, 'unchanged');
  assert.equal(rows().length, before);
  assert.equal(recorded(), '3.0.0');
});

test('a crash mid-send resumes without mailing anyone twice', async () => {
  clear();
  setSetting(K.lastAnnounced, '3.0.0');
  // The previous process queued two of four and died before recording 3.0.1.
  for (const email of ['abe@example.com', 'olga@example.com']) {
    enqueueEmail({ to: email, subject: 's', text: 't', appId: null, idempotencyKey: `whats-new:3.0.1:${email}`, source: SOURCE });
  }
  const r = await announceWhatsNew({ db, version: '3.0.1', loadNotes: notes });
  assert.equal(r.sent, 2);
  assert.equal(r.skipped, 2);
  const per = new Map();
  for (const m of rows()) per.set(m.to_email, (per.get(m.to_email) || 0) + 1);
  assert.deepEqual([...per.keys()].sort(), EXPECTED);
  assert.ok([...per.values()].every((n) => n === 1), JSON.stringify([...per]));
  assert.equal(recorded(), '3.0.1');
});

test('the database refuses a second copy of the same release mail', () => {
  assert.throws(
    () => enqueueEmail({ to: 'ada@example.com', subject: 's', text: 't', appId: null, idempotencyKey: 'whats-new:3.0.1:ada@example.com', source: SOURCE }),
    /UNIQUE constraint failed/,
  );
});

test('two processes announcing the same upgrade at once send one mail per recipient', async () => {
  clear();
  setSetting(K.lastAnnounced, '3.0.1');
  const here = dirname(fileURLToPath(import.meta.url));
  const go = join(DATA_DIR, 'go');
  const child = join(mkdtempSync(join(tmpdir(), 'crane-whats-new-child-')), 'child.mjs');
  writeFileSync(child, `
    import { existsSync } from 'fs';
    const { initDb, getDb } = await import(${JSON.stringify(pathToFileURL(join(here, '..', 'server', 'db.js')).href)});
    const { announceWhatsNew } = await import(${JSON.stringify(pathToFileURL(join(here, '..', 'server', 'services', 'whatsNewMail.js')).href)});
    initDb();
    const r = await announceWhatsNew({ db: getDb(), version: '3.1.0', loadNotes: async () => {
      while (!existsSync(${JSON.stringify(go)})) await new Promise((r) => setTimeout(r, 5));
      return [{ version: '3.1.0', commit_message: 'raced' }];
    } });
    process.stdout.write(JSON.stringify(r));
  `);
  const run = () => new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [child], { env: { ...process.env }, stdio: ['ignore', 'pipe', 'inherit'] });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.on('exit', (code) => (code === 0 ? resolve(out) : reject(new Error(`child exited ${code}: ${out}`))));
  });
  const both = Promise.all([run(), run()]);
  await new Promise((r) => setTimeout(r, 1500));
  writeFileSync(go, '1');
  const results = (await both).map((o) => JSON.parse(o.slice(o.lastIndexOf('{'))));
  assert.equal(results.reduce((n, r) => n + r.sent, 0), EXPECTED.length, JSON.stringify(results));
  const per = new Map();
  for (const m of rows()) per.set(m.to_email, (per.get(m.to_email) || 0) + 1);
  assert.deepEqual([...per.keys()].sort(), EXPECTED);
  assert.ok([...per.values()].every((n) => n === 1), JSON.stringify([...per]));
  assert.equal(recorded(), '3.1.0');
});

test('turned off: nothing is sent, the recorded version still advances, and turning it back on sends no backlog', async () => {
  clear();
  setSetting(K.enabled, '0');
  const r = await announceWhatsNew({ db, version: '3.2.0', loadNotes: notes });
  assert.equal(r.status, 'disabled');
  assert.equal(rows().length, 0);
  assert.equal(recorded(), '3.2.0');
  setSetting(K.enabled, '1');
  const again = await announceWhatsNew({ db, version: '3.2.0', loadNotes: notes });
  assert.equal(again.status, 'unchanged');
  assert.equal(rows().length, 0);
});

test('no release notes available: the mail still goes out with the version and a dashboard link', async () => {
  for (const loadNotes of [async () => [], async () => { throw new Error('offline'); }]) {
    clear();
    const from = recorded();
    const to = `3.3.${seq++}`;
    const r = await announceWhatsNew({ db, version: to, loadNotes });
    assert.equal(r.sent, EXPECTED.length);
    for (const m of rows()) {
      assert.equal(m.subject, `[AppCrane] What's new in v${to} (since v${from})`);
      assert.match(m.body_text, new RegExp(`updated to v${to.replace(/\./g, '\\.')}`));
      assert.match(m.body_text, /release notes could not be read/);
      assert.match(m.body_text, /Dashboard: https:\/\/dashboard\.example\.test/);
    }
  }
});

test('many versions are capped with "and N more"; one version gets a single-version subject', async () => {
  clear();
  setSetting(K.lastAnnounced, '4.0.0');
  const many = Array.from({ length: 20 }, (_, i) => ({ version: `4.0.${i + 1}`, commit_message: `change ${i + 1}` }));
  await announceWhatsNew({ db, version: '4.0.20', loadNotes: async () => many });
  const m = rows()[0];
  assert.equal((m.body_text.match(/^- v4\.0\.\d+:/gm) || []).length, 15);
  assert.match(m.body_text, /- and 5 more/);
  clear();
  await announceWhatsNew({ db, version: '4.0.21', loadNotes: async () => [{ version: '4.0.21', commit_message: 'one' }] });
  assert.equal(rows()[0].subject, "[AppCrane] What's new in v4.0.21");
});

test('curated notes are used; a version missing from them falls back to its commit subject', async () => {
  clear();
  setSetting(K.lastAnnounced, '5.0.0');
  const subjects = [
    { version: '5.0.2', commit_message: 'security review pass 2 — host file reads through repo links' },
    { version: '5.0.1', commit_message: 'raw subject kept' },
  ];
  const loadNotes = async () => mergeCuratedNotes(subjects, { '5.0.2': ['You can rename an app.', 'Env vars open masked.'] });
  await announceWhatsNew({ db, version: '5.0.2', loadNotes });
  const m = rows()[0];
  assert.match(m.body_text, /- v5\.0\.2:\n {4}- You can rename an app\.\n {4}- Env vars open masked\.\n/);
  assert.doesNotMatch(m.body_text, /security review pass 2/);
  assert.match(m.body_text, /- v5\.0\.1: raw subject kept/);
  assert.match(m.body_html, /<li[^>]*>You can rename an app\.<\/li>/);
  assert.match(m.body_html, /<li[^>]*>raw subject kept<\/li>/);
});

test('the mail is AppCrane-branded and escapes notes and names', () => {
  const { html, text } = renderWhatsNew({
    from: '1.0.0', to: '1.0.1', name: 'Eve <script>',
    notes: [{ version: '1.0.1', lines: ['<img src=x onerror=alert(1)> & more'] }],
  });
  for (const colour of ['#1a1d27', '#3b82f6', '#2563eb']) assert.ok(html.includes(colour), `brand colour ${colour} missing`);
  assert.match(html, />App<\/span><span[^>]*>Crane<\/span>/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt; &amp; more/);
  assert.match(html, /Hi Eve &lt;script&gt;,/);
  assert.doesNotMatch(html, /<img|<script/);
  assert.doesNotMatch(html, /https?:\/\/(?!dashboard\.example\.test)/, 'no external images or fonts');
  assert.match(html, /You get this because you own an app on AppCrane or administer it\./);
  assert.match(text, /You get this because you own an app on AppCrane or administer it\./);
});
