// Per-app identity signing secret (v2.97.0).
//
// /api/identity/verify signs the identity headers it issues with this secret;
// the deployer hands the same secret to the app as APPCRANE_IDENTITY_SECRET;
// appcrane-tenant's verifyIdentity() checks it. Each app AND environment has
// its own, so a compromised app can neither forge another app's identity nor
// replay its own signed headers somewhere else, and an app's sandbox (code
// still under review) cannot sign identity its production believes. The signing function itself lives in
// packages/tenant and is imported here, so both sides sign the same bytes.

import { randomBytes } from 'crypto';
import { encrypt, decrypt } from './encryption.js';
export { signIdentity } from '../../packages/tenant/index.js';

/** The secret for this app's `env`, created on first use. Stable afterwards. */
export function identitySecretFor(db, appId, env = 'production') {
  if (env !== 'production' && env !== 'sandbox') throw new Error(`identitySecretFor: unknown env '${env}'`);
  const read = () => db.prepare('SELECT secret_encrypted s FROM app_identity_secrets WHERE app_id = ? AND env = ?').get(appId, env)?.s;
  let enc = read();
  if (!enc) {
    if (!db.prepare('SELECT 1 FROM apps WHERE id = ?').get(appId)) throw new Error(`identitySecretFor: app ${appId} not found`);
    // INSERT OR IGNORE: two first uses racing both generate, one row wins,
    // and both read back the winner.
    db.prepare('INSERT OR IGNORE INTO app_identity_secrets (app_id, env, secret_encrypted) VALUES (?, ?, ?)')
      .run(appId, env, encrypt(randomBytes(32).toString('base64url')));
    enc = read();
  }
  return decrypt(enc);
}
