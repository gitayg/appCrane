// Signed identity headers for LOCAL development and manual testing.
//
// Behind AppCrane the proxy signs every request with a secret only the
// platform and this app hold. Locally you choose your own throwaway secret:
//
//   export APPCRANE_IDENTITY_SECRET="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
//   npm start                      # in one shell
//   npm run dev:headers            # prints curl -H flags for a test user
//
// DEV_APP_ROLE (viewer|user|admin|owner) picks the role. Never put the
// production secret on your machine; it is not needed for any of this.

import { fileURLToPath } from 'node:url';
import { signIdentityV2 } from '../server/identity.js';

export function devIdentityHeaders({ secret = process.env.APPCRANE_IDENTITY_SECRET, appRole = process.env.DEV_APP_ROLE || 'owner' } = {}) {
  if (!secret) return {};
  const h = {
    'x-appcrane-auth-mode': 'authenticated',
    'x-appcrane-user': 'dev@example.test',
    'x-appcrane-user-id': '1',
    'x-appcrane-user-email': 'dev@example.test',
    'x-appcrane-user-name': encodeURIComponent('Local Developer'),
    'x-appcrane-user-role': 'user',
    'x-appcrane-app-role': appRole,
    'x-appcrane-is-admin': appRole === 'admin' || appRole === 'owner' ? '1' : '0',
  };
  const ts = Math.floor(Date.now() / 1000);
  h['x-appcrane-identity-ts'] = String(ts);
  h['x-appcrane-identity-sig-v2'] = signIdentityV2(secret, ts, h);
  return h;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const h = devIdentityHeaders();
  if (!Object.keys(h).length) {
    console.error('Set APPCRANE_IDENTITY_SECRET first (see the comment at the top of this file).');
    process.exit(1);
  }
  console.log(Object.entries(h).map(([k, v]) => `-H '${k}: ${v}'`).join(' '));
}
