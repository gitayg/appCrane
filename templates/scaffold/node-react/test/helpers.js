import { randomBytes } from 'node:crypto';
import { signIdentityV2 } from '../server/identity.js';

// A fresh secret per test run: nothing secret-shaped is committed, and a
// header set signed in one run cannot pass in another.
export const TEST_SECRET = randomBytes(32).toString('base64url');
process.env.APPCRANE_IDENTITY_SECRET = TEST_SECRET;

/** Headers exactly as AppCrane's proxy issues them, signed with `secret`. */
export function signedHeaders({ appRole = 'user', userId = '42', appRoles = null, secret = TEST_SECRET, ts = Math.floor(Date.now() / 1000), extra = {} } = {}) {
  const h = {
    'x-appcrane-auth-mode': 'authenticated',
    'x-appcrane-user': 'person@example.test',
    'x-appcrane-user-id': userId,
    'x-appcrane-user-email': 'person@example.test',
    'x-appcrane-user-name': encodeURIComponent('Test Person'),
    'x-appcrane-user-role': 'user',
    'x-appcrane-app-role': appRole,
    'x-appcrane-is-admin': appRole === 'admin' || appRole === 'owner' ? '1' : '0',
    ...(appRoles ? { 'x-appcrane-app-roles': appRoles } : {}),
    ...extra,
  };
  h['x-appcrane-identity-ts'] = String(ts);
  h['x-appcrane-identity-sig-v2'] = signIdentityV2(secret, ts, h);
  return h;
}
