// Infisical: machine identity universal auth (POST /api/v1/auth/universal-auth/login),
// then GET /api/v3/secrets/raw/<name>?workspaceId=&environment=&secretPath=.
import { StoreError, enc, joinUrl, requestJson } from '../http.js';

const DEFAULT_SITE = 'https://app.infisical.com';

async function token(conn, session, guarded) {
  if (session.infisicalToken) return session.infisicalToken;
  const site = conn.settings.site_url || DEFAULT_SITE;
  const { json } = await requestJson(joinUrl(site, 'api/v1/auth/universal-auth/login'), {
    method: 'POST', body: { clientId: conn.credentials.client_id, clientSecret: conn.credentials.client_secret }, guarded,
  }).catch((e) => { throw new StoreError(`universal auth login failed: ${e.message}`, e.status); });
  if (typeof json?.accessToken !== 'string' || !json.accessToken) throw new StoreError('universal auth login returned no token');
  session.infisicalToken = json.accessToken;
  return json.accessToken;
}

export async function read(conn, ref, { session, guarded }) {
  const t = await token(conn, session, guarded);
  const site = conn.settings.site_url || DEFAULT_SITE;
  const q = new URLSearchParams({ workspaceId: ref.project, environment: ref.environment, secretPath: ref.path });
  const { json } = await requestJson(joinUrl(site, `api/v3/secrets/raw/${enc([ref.name])}?${q}`), { headers: { Authorization: `Bearer ${t}` }, guarded });
  const value = json?.secret?.secretValue;
  if (typeof value !== 'string') throw new StoreError('the secret has no value');
  return value;
}
