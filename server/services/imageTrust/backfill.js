// The migration path for images that were already running before signing
// existed: sign what each live app/env is running NOW, so enforce mode can be
// turned on without stopping them. Trust on first use, and recorded as such
// (origin 'backfill', SLSA buildType running-image): the provenance says this
// instance signed an image it found running, not that it watched it built.
//
// Also the census: `dryRun` reports, per live app/env, whether its running image
// is already signed, without signing anything.

import { getDb } from '../../db.js';
import { attestImage } from './attest.js';
import { containerImageId } from './dockerImage.js';
import { signedRowFor } from './store.js';

/**
 * @param {{ db?: object, dryRun?: boolean, appendLog?: (l: string) => void }} [opts]
 * @returns {Promise<Array<{ app: string, env: string, deployment_id: number, image_id: string|null, state: string, detail?: string }>>}
 */
export async function signCurrentImages(opts = {}) {
  const db = opts.db || getDb();
  const live = db.prepare(`SELECT d.id AS deployment_id, d.env, a.* FROM deployments d JOIN apps a ON a.id = d.app_id
    WHERE d.status = 'live' AND d.id = (SELECT MAX(id) FROM deployments x WHERE x.app_id = d.app_id AND x.env = d.env AND x.status = 'live')
    ORDER BY a.slug, d.env`).all();
  const out = [];
  for (const row of live) {
    const { deployment_id: deploymentId, env, ...app } = row;
    app.id = row.id;
    const c = await containerImageId(`appcrane-${app.slug}-${env}`);
    if (c.error) { out.push({ app: app.slug, env, deployment_id: deploymentId, image_id: null, state: 'no-container', detail: c.error }); continue; }
    if (signedRowFor(db, app.id, env, c.id)) { out.push({ app: app.slug, env, deployment_id: deploymentId, image_id: c.id, state: 'signed' }); continue; }
    if (opts.dryRun) { out.push({ app: app.slug, env, deployment_id: deploymentId, image_id: c.id, state: 'unsigned' }); continue; }
    const r = await attestImage({
      db, app, env, deploymentId, image: c.ref || c.id, imageId: c.id, origin: 'backfill', kind: 'backfill',
      allowPull: true, appendLog: opts.appendLog,
    });
    out.push({ app: app.slug, env, deployment_id: deploymentId, image_id: c.id, state: r.status === 'signed' ? 'backfilled' : 'error', ...(r.error ? { detail: r.error } : {}) });
  }
  return out;
}
