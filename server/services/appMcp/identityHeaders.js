// The identity an app receives on a request AppCrane makes for an MCP caller:
// the same X-AppCrane-* headers /api/identity/verify issues for a browser
// visit, built from the authenticated caller and signed with the app's own
// per-environment secret, so appcrane-tenant verifyIdentity() accepts them.
//
// Built from scratch for every request. Nothing the MCP client sent is
// forwarded, so a client cannot choose who the app thinks it is.

import { identitySecretFor, signIdentity, signIdentityV2 } from '../identitySignature.js';
import { roleKeysForUser } from '../appDefinedRoles.js';

export function identityHeadersFor(db, { app, env, user, appRole }) {
  const h = {};
  if (user.id != null) h['X-AppCrane-User-Id'] = String(user.id);
  if (user.email) {
    h['X-AppCrane-User'] = user.email;
    h['X-AppCrane-User-Email'] = user.email;
  }
  if (user.name) h['X-AppCrane-User-Name'] = encodeURIComponent(user.name);
  if (user.role) h['X-AppCrane-User-Role'] = user.role;
  h['X-AppCrane-App-Role'] = appRole;
  h['X-AppCrane-Is-Admin'] = appRole === 'admin' || appRole === 'owner' ? '1' : '0';
  const keys = roleKeysForUser(app.id, user.id);
  if (keys.length) h['X-AppCrane-App-Roles'] = keys.join(',');
  const ts = Math.floor(Date.now() / 1000);
  h['X-AppCrane-Identity-Ts'] = String(ts);
  const secret = identitySecretFor(db, app.id, env);
  h['X-AppCrane-Identity-Sig'] = signIdentity(secret, ts, (name) => h[name]);
  h['X-AppCrane-Identity-Sig-V2'] = signIdentityV2(secret, ts, (name) => h[name]);
  h['X-AppCrane-Auth-Mode'] = 'authenticated';
  h['X-AppCrane-Via'] = 'mcp';
  return h;
}
