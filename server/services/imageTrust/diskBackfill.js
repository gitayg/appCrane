// The one-time backfill for images that are on disk but were never signed:
// older releases a rollback would start, and anything built before signing
// existed. An image is signed only when AppCrane can show it is one of its own
// releases: a live or rolled-back deployments row of that app/env names it
// (a built image by its tag appcrane-<slug>-<env>:<commit>, an image app by the
// digest-pinned image_ref it recorded). Signed as trust on first use (origin
// 'backfill', provenance buildType running-image), never as build provenance.
// Everything else is listed with the reason it was not signed.

import { getDb } from '../../db.js';
import { attestImage } from './attest.js';
import { inspectImage, listAppcraneImages } from './dockerImage.js';
import { signedRowFor } from './store.js';

const ENVS = ['production', 'sandbox'];
const REPO_RE = /^appcrane-([a-z0-9][a-z0-9-]*)-(production|sandbox)$/;

/** Candidate images, before any signature lookup. */
async function candidates(db) {
  const apps = db.prepare('SELECT * FROM apps ORDER BY slug').all();
  const bySlug = new Map(apps.map((a) => [a.slug, a]));
  const deps = db.prepare(`SELECT id, app_id, env, commit_hash, image_ref, status FROM deployments
    WHERE status IN ('live', 'rolled_back') ORDER BY id DESC`).all();
  const { imageTagFor } = await import('../docker.js');
  const tagToDep = new Map();
  for (const d of deps) {
    const app = apps.find((a) => a.id === d.app_id);
    if (!app || !ENVS.includes(d.env) || !d.commit_hash || d.commit_hash === 'unknown') continue;
    const tag = imageTagFor(app.slug, d.env, d.commit_hash);
    if (!tagToDep.has(tag)) tagToDep.set(tag, d);
  }

  const out = [];
  const listed = await listAppcraneImages();
  if (listed.error) return { error: listed.error, items: [] };
  for (const img of listed.images) {
    const m = REPO_RE.exec(img.repository);
    const ref = `${img.repository}:${img.tag}`;
    const app = m ? bySlug.get(m[1]) : null;
    if (!m || !app) { out.push({ app: m?.[1] || null, env: m?.[2] || null, image_ref: ref, image_id: img.id, deployment_id: null, reason: 'no app of that name on this instance' }); continue; }
    const dep = tagToDep.get(ref);
    out.push({ app: app.slug, appRow: app, env: m[2], image_ref: ref, image_id: img.id, deployment_id: dep?.id ?? null, reason: dep ? null : 'no live or rolled-back deployment of this app names this tag' });
  }
  for (const d of deps) {
    const app = apps.find((a) => a.id === d.app_id);
    if (!app || app.source_type !== 'image' || !d.image_ref || !ENVS.includes(d.env)) continue;
    if (out.some((x) => x.app === app.slug && x.env === d.env && x.image_ref === d.image_ref)) continue;
    const info = await inspectImage(d.image_ref);
    if (info.error) continue;
    out.push({ app: app.slug, appRow: app, env: d.env, image_ref: d.image_ref, image_id: info.id, deployment_id: d.id, reason: null });
  }
  return { items: out };
}

/**
 * @param {{ db?: object, dryRun?: boolean, appendLog?: (l: string) => void }} [opts]
 * @returns {Promise<{ error?: string, images: Array<{ app: string|null, env: string|null, image_ref: string, image_id: string, deployment_id: number|null, state: 'signed'|'unsigned'|'unprovable'|'backfilled'|'error', detail?: string }> }>}
 */
export async function backfillDiskImages(opts = {}) {
  const db = opts.db || getDb();
  const { error, items } = await candidates(db);
  const images = [];
  const seen = new Set();
  // A provable tag first, so an image id that also carries an unprovable tag is still signed.
  for (const c of [...items].sort((a, b) => Number(!!a.reason) - Number(!!b.reason))) {
    const { appRow, reason, ...pub } = c;
    if (!appRow) { images.push({ ...pub, state: 'unprovable', detail: reason }); continue; }
    const key = `${appRow.id}|${c.env}|${c.image_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (signedRowFor(db, appRow.id, c.env, c.image_id)) { images.push({ ...pub, state: 'signed' }); continue; }
    if (reason) { images.push({ ...pub, state: 'unprovable', detail: reason }); continue; }
    if (opts.dryRun) { images.push({ ...pub, state: 'unsigned' }); continue; }
    const r = await attestImage({
      db, app: appRow, env: c.env, deploymentId: c.deployment_id, image: c.image_ref, imageId: c.image_id,
      origin: 'backfill', kind: 'backfill', allowPull: true, appendLog: opts.appendLog,
    });
    images.push({ ...pub, state: r.status === 'signed' ? 'backfilled' : 'error', ...(r.error ? { detail: r.error } : {}) });
  }
  return { ...(error ? { error } : {}), images };
}
