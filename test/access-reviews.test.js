import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Periodic access reviews (services/accessReviews/, routes/accessReviews.js,
// migration 146), driven over real HTTP against an ephemeral server.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-access-reviews-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const ar = await import('../server/services/accessReviews/index.js');
initDb();
const db = getDb();

function mkUser(name, role = 'user') {
  const key = generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid);
  return { id, key, name };
}
const admin1 = mkUser('admin1', 'platform_admin');
const admin2 = mkUser('admin2', 'platform_admin');
const ownerA = mkUser('ownera');
const appAdminA = mkUser('appadmina');
const memberA = mkUser('membera');
const scimA = mkUser('scima');
const ownerB = mkUser('ownerb');
const memberB = mkUser('memberb');
const outsider = mkUser('outsider');

const mkApp = (slug, slot) => Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')").run(slug.toUpperCase(), slug, slot).lastInsertRowid);
const appA = mkApp('rev-a', 801);
const appB = mkApp('rev-b', 802);
const appEmpty = mkApp('rev-empty', 803);
const role = db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)');
role.run(appA, ownerA.id, 'owner');
role.run(appA, appAdminA.id, 'admin');
role.run(appA, memberA.id, 'user');
role.run(appA, scimA.id, 'user');
role.run(appA, outsider.id, 'none');
role.run(appB, ownerB.id, 'owner');
role.run(appB, memberB.id, 'user');
db.prepare("INSERT INTO app_visits (user_id, app_id, day) VALUES (?, ?, '2026-10-01'), (?, ?, '2026-10-15')").run(memberA.id, appA, memberA.id, appA);
const grp = Number(db.prepare("INSERT INTO scim_groups (display_name) VALUES ('eng')").run().lastInsertRowid);
db.prepare('INSERT INTO scim_group_members (group_id, user_id) VALUES (?, ?)').run(grp, scimA.id);
db.prepare("INSERT INTO scim_group_app_roles (group_id, app_id, app_role) VALUES (?, ?, 'user')").run(grp, appA);
db.prepare("INSERT INTO scim_group_access (app_id, user_id, app_role, created_membership, created_role) VALUES (?, ?, 'user', 1, 1)").run(appA, scimA.id);

const api = express();
api.use(express.json());
api.use('/api', (await import('../server/routes/accessReviews.js')).default);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const call = async (method, path, who, body) => {
  const r = await fetch(`${BASE}${path}`, { method, headers: { 'X-API-Key': who.key, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) {}
  return { status: r.status, body: json, text };
};
const roleOf = (appId, userId) => db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, userId)?.app_role ?? null;
const mails = (pattern) => db.prepare("SELECT * FROM email_queue WHERE source = 'access-review' AND idempotency_key LIKE ? ORDER BY id").all(pattern);
const itemFor = (review, userId) => review.items.find(i => i.user_id === userId);
const DAY = 86_400_000;

let campaign;
let reviewA;
let reviewB;
let platformReview;

test('a campaign lists every user with a role on each app, how it was granted and last access; owners review their app, admins the platform', async () => {
  const r = await call('POST', '/api/access-reviews/campaigns', admin1, {});
  assert.equal(r.status, 201, r.text);
  campaign = r.body.campaign;
  const detail = await call('GET', `/api/access-reviews/campaigns/${campaign.id}`, admin1);
  assert.equal(detail.status, 200);
  const reviews = detail.body.reviews;
  reviewA = reviews.find(x => x.app_id === appA);
  reviewB = reviews.find(x => x.app_id === appB);
  platformReview = reviews.find(x => x.kind === 'platform');
  assert.ok(!reviews.find(x => x.app_id === appEmpty), 'an app nobody has a role on has nothing to review');
  assert.deepEqual(reviewA.items.map(i => [i.user_id, i.role]).sort(), [[ownerA.id, 'owner'], [appAdminA.id, 'admin'], [memberA.id, 'user'], [scimA.id, 'user']].sort());
  assert.deepEqual(reviewB.items.map(i => [i.user_id, i.role]).sort(), [[ownerB.id, 'owner'], [memberB.id, 'user']].sort());
  assert.deepEqual(platformReview.items.map(i => i.user_id).sort(), [admin1.id, admin2.id].sort());
  assert.equal(itemFor(reviewA, scimA.id).granted_via, 'scim');
  assert.equal(itemFor(reviewA, memberA.id).granted_via, 'direct');
  assert.equal(itemFor(reviewA, memberA.id).last_access_at, '2026-10-15 00:00:00');
  assert.deepEqual(reviewA.reviewers.map(x => x.user_id), [ownerA.id]);
  assert.deepEqual(reviewB.reviewers.map(x => x.user_id), [ownerB.id]);
  assert.deepEqual(platformReview.reviewers.map(x => x.user_id).sort(), [admin1.id, admin2.id].sort());
  assert.equal(mails('access-review:start:%').length, 4, 'one start mail per reviewer (ownerA, ownerB, two admins)');
  const second = await call('POST', '/api/access-reviews/campaigns', admin1, {});
  assert.equal(second.status, 409);
});

test('authz: only the app owners review their app; platform admins see every review but decide only their own', async () => {
  assert.equal((await call('GET', `/api/access-reviews/reviews/${reviewA.id}`, ownerB)).status, 404);
  assert.equal((await call('POST', `/api/access-reviews/items/${itemFor(reviewA, memberA.id).id}/decision`, ownerB, { decision: 'remove' })).status, 404);
  assert.equal((await call('POST', `/api/access-reviews/items/${itemFor(reviewA, memberA.id).id}/decision`, memberA, { decision: 'keep' })).status, 404);
  assert.equal((await call('GET', '/api/access-reviews/campaigns', ownerA)).status, 403);
  assert.equal((await call('GET', `/api/access-reviews/campaigns/${campaign.id}/report`, ownerA)).status, 403);
  const mine = await call('GET', '/api/access-reviews/mine', ownerA);
  assert.deepEqual(mine.body.reviews.map(r => r.id), [reviewA.id]);
  assert.deepEqual((await call('GET', '/api/access-reviews/mine', memberA)).body.reviews, []);
  const asAdmin = await call('GET', `/api/access-reviews/reviews/${reviewA.id}`, admin1);
  assert.equal(asAdmin.status, 200);
  assert.equal(asAdmin.body.review.can_decide, false);
  assert.equal((await call('POST', `/api/access-reviews/items/${itemFor(reviewA, memberA.id).id}/decision`, admin1, { decision: 'remove' })).status, 403);
  assert.equal(roleOf(appA, memberA.id), 'user');
});

test('Remove and Change apply at once through the role-change path and are audited and recorded as events', async () => {
  const rm = await call('POST', `/api/access-reviews/items/${itemFor(reviewA, memberA.id).id}/decision`, ownerA, { decision: 'remove', note: 'left the team' });
  assert.equal(rm.status, 200, rm.text);
  assert.equal(roleOf(appA, memberA.id), null);
  const ch = await call('POST', `/api/access-reviews/items/${itemFor(reviewA, appAdminA.id).id}/decision`, ownerA, { decision: 'change', new_role: 'user' });
  assert.equal(ch.status, 200, ch.text);
  assert.equal(roleOf(appA, appAdminA.id), 'user');
  const audits = db.prepare("SELECT * FROM audit_log WHERE action = 'access-review-decision' ORDER BY id").all().map(a => ({ ...a, d: JSON.parse(a.detail) }));
  assert.equal(audits.length, 2);
  assert.deepEqual(audits.map(a => [a.user_id, a.app_id, a.d.target_user_id, a.d.decision, a.d.new_role]),
    [[ownerA.id, appA, memberA.id, 'remove', 'none'], [ownerA.id, appA, appAdminA.id, 'change', 'user']]);
  const evs = db.prepare("SELECT * FROM events WHERE kind = 'access_review.decision' ORDER BY id").all();
  assert.deepEqual(evs.map(e => [e.user_id, e.subject_user_id, e.severity]), [[ownerA.id, memberA.id, 'warning'], [ownerA.id, appAdminA.id, 'warning']]);
  const again = await call('POST', `/api/access-reviews/items/${itemFor(reviewA, memberA.id).id}/decision`, ownerA, { decision: 'keep' });
  assert.equal(again.status, 409);
});

test('SCIM-granted access is flagged and cannot be removed or changed here; Keep is allowed', async () => {
  const item = itemFor(reviewA, scimA.id);
  assert.equal(item.scim_managed, true);
  assert.match(item.scim_message, /identity provider/);
  const rm = await call('POST', `/api/access-reviews/items/${item.id}/decision`, ownerA, { decision: 'remove' });
  assert.equal(rm.status, 409);
  assert.equal(rm.body.error.code, 'SCIM_MANAGED');
  assert.match(rm.body.error.message, /identity provider/);
  assert.equal(roleOf(appA, scimA.id), 'user');
  const ch = await call('POST', `/api/access-reviews/items/${item.id}/decision`, ownerA, { decision: 'change', new_role: 'admin' });
  assert.equal(ch.status, 409);
  assert.equal(roleOf(appA, scimA.id), 'user');
  assert.equal((await call('POST', `/api/access-reviews/items/${item.id}/decision`, ownerA, { decision: 'keep' })).status, 200);
});

test('the sole reviewer may keep their own access but never remove it; finishing every item completes the review', async () => {
  const self = itemFor(reviewA, ownerA.id);
  assert.equal((await call('POST', `/api/access-reviews/items/${self.id}/decision`, ownerA, { decision: 'remove' })).status, 403);
  assert.equal((await call('POST', `/api/access-reviews/items/${self.id}/decision`, ownerA, { decision: 'keep' })).status, 200);
  assert.equal(db.prepare('SELECT status FROM access_reviews WHERE id = ?').get(reviewA.id).status, 'completed');
  const selfAdmin = itemFor(platformReview, admin1.id);
  const r = await call('POST', `/api/access-reviews/items/${selfAdmin.id}/decision`, admin1, { decision: 'keep' });
  assert.equal(r.status, 403, 'another platform admin can review this one');
});

test('reminders before the due date and the overdue escalation each go out once; after grace, report-only mails the unreviewed list and closes', () => {
  db.prepare("UPDATE access_review_campaigns SET overdue_action = 'report' WHERE id = ?").run(campaign.id);
  const c = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(campaign.id);
  const due = Date.parse(c.due_at.replace(' ', 'T') + 'Z');
  const grace = Date.parse(c.grace_until.replace(' ', 'T') + 'Z');
  ar.runAccessReviewTick({ now: due - 10 * DAY });
  assert.equal(mails('access-review:reminder:%').length, 0, 'too early for a reminder');
  ar.runAccessReviewTick({ now: due - DAY });
  ar.runAccessReviewTick({ now: due - DAY + 3_600_000 });
  const reminded = mails('access-review:reminder:%').map(m => m.to_email).sort();
  assert.deepEqual(reminded, ['admin1@t.test', 'admin2@t.test', 'ownerb@t.test'], 'pending reviewers only (ownerA finished), once each');
  ar.runAccessReviewTick({ now: due + 3_600_000 });
  ar.runAccessReviewTick({ now: due + 7_200_000 });
  assert.deepEqual(mails('access-review:overdue:%').map(m => m.to_email).sort(), ['admin1@t.test', 'admin2@t.test']);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM events WHERE kind = 'access_review.overdue'").get().n, 1);
  ar.runAccessReviewTick({ now: grace + 3_600_000 });
  ar.runAccessReviewTick({ now: grace + 7_200_000 });
  const report = mails('access-review:unreviewed:%');
  assert.deepEqual(report.map(m => m.to_email).sort(), ['admin1@t.test', 'admin2@t.test']);
  assert.match(report[0].body_text, /REV-B: 2 unreviewed/);
  assert.equal(db.prepare('SELECT status FROM access_review_campaigns WHERE id = ?').get(campaign.id).status, 'closed');
  assert.equal(roleOf(appB, memberB.id), 'user', 'report only: unreviewed access is left unchanged');
});

test('the campaign report exports as CSV and JSON, and getAccessReviewEvidence returns it for the period', async () => {
  const csv = await call('GET', `/api/access-reviews/campaigns/${campaign.id}/report?format=csv`, admin1);
  assert.equal(csv.status, 200);
  const lines = csv.text.trim().split('\n');
  assert.match(lines[0], /^campaign_id,campaign_name/);
  assert.equal(lines.length, 1 + 4 + 2 + 2);
  assert.ok(lines.some(l => l.includes('membera@t.test') && l.includes(',remove,')));
  assert.ok(lines.some(l => l.includes('memberb@t.test') && l.includes(',unreviewed,')));
  const json = await call('GET', `/api/access-reviews/campaigns/${campaign.id}/report`, admin1);
  assert.equal(json.body.campaign.id, campaign.id);
  const ev = ar.getAccessReviewEvidence({ from: '2000-01-01', to: '2999-12-31' });
  assert.equal(ev.campaigns.length, 1);
  assert.equal(ev.csv.trim().split('\n').length, lines.length);
  assert.equal(ar.getAccessReviewEvidence({ from: '2000-01-01', to: '2000-12-31' }).campaigns.length, 0);
});

test('the cadence starts campaigns when enabled, and a classification level with its own cadence gets its own campaign', () => {
  db.prepare("INSERT INTO app_intake (app_id, data_classification, status) VALUES (?, 'restricted', 'approved') ON CONFLICT(app_id) DO UPDATE SET data_classification = 'restricted'").run(appB);
  ar.setPolicy(db, { enabled: true, cadence_days: 90, by_classification: { restricted: 30 } }, admin1.id);
  const now = Date.now() + 100 * DAY;
  const first = ar.runAccessReviewTick({ now });
  assert.equal(first.started.length, 2);
  const scopes = db.prepare('SELECT scope, id FROM access_review_campaigns WHERE id IN (' + first.started.join(',') + ')').all();
  const restricted = scopes.find(s => s.scope === 'restricted').id;
  const apps = db.prepare("SELECT app_id FROM access_reviews WHERE campaign_id = ? AND kind = 'app'").all(restricted).map(r => r.app_id);
  assert.deepEqual(apps, [appB]);
  const def = scopes.find(s => s.scope === 'default').id;
  const defApps = db.prepare("SELECT app_id FROM access_reviews WHERE campaign_id = ? AND kind = 'app'").all(def).map(r => r.app_id);
  assert.ok(!defApps.includes(appB) && defApps.includes(appA));
  assert.equal(ar.runAccessReviewTick({ now: now + DAY }).started.length, 0, 'open campaigns are not started again');
});
