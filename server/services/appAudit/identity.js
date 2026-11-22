import { decrypt } from '../encryption.js';
import { verifyIdentity } from '../../../packages/tenant/index.js';

// An app may name the AppCrane user who acted only by forwarding the signed
// identity headers AppCrane gave it for that user's request. They are checked
// against THIS app's own identity secrets (production, then sandbox), so an app
// can neither invent a user nor reuse identity another app was given, and a
// signature older than five minutes is refused (IDENTITY_MAX_AGE_SEC).

function fail(message) {
  return Object.assign(new Error(message), { status: 401, code: 'IDENTITY_INVALID' });
}

/** { userId, env } for a forwarded identity, or throws 401 IDENTITY_INVALID. */
export function verifyForwardedIdentity(db, appId, identity, now = Date.now()) {
  const headers = {};
  for (const [k, v] of Object.entries(identity || {})) {
    if (typeof v === 'string' && /^x-appcrane-/i.test(k)) headers[k.toLowerCase()] = v;
  }
  const secrets = db.prepare("SELECT env, secret_encrypted FROM app_identity_secrets WHERE app_id = ? ORDER BY env = 'production' DESC").all(appId);
  for (const s of secrets) {
    let secret;
    try { secret = decrypt(s.secret_encrypted); } catch { continue; }
    let who;
    try { who = verifyIdentity(headers, { secret, now }); } catch { continue; }
    if (!who.userId) throw fail('the signed identity names no user');
    return { userId: Number(who.userId), env: s.env };
  }
  throw fail('identity is not a valid, current identity signature for this app');
}
