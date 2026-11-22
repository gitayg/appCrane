// HashiCorp Vault: KV v2 (GET /v1/<mount>/data/<path>) or KV v1 (GET /v1/<mount>/<path>),
// with a token or an AppRole login (POST /v1/auth/<approle mount>/login).
import { StoreError, enc, joinUrl, requestJson } from '../http.js';

function nsHeader(conn) {
  return conn.settings.namespace ? { 'X-Vault-Namespace': conn.settings.namespace } : {};
}

async function token(conn, session, guarded) {
  if ((conn.settings.auth ?? 'token') === 'token') return conn.credentials.token;
  if (session.vaultToken) return session.vaultToken;
  const mount = conn.settings.approle_mount || 'approle';
  const { json } = await requestJson(joinUrl(conn.settings.address, `v1/auth/${enc([mount])}/login`), {
    method: 'POST', body: { role_id: conn.credentials.role_id, secret_id: conn.credentials.secret_id }, headers: nsHeader(conn), guarded,
  }).catch((e) => { throw new StoreError(`AppRole login failed: ${e.message}`, e.status); });
  const t = json?.auth?.client_token;
  if (typeof t !== 'string' || !t) throw new StoreError('AppRole login returned no token');
  session.vaultToken = t;
  return t;
}

export async function read(conn, ref, { session, guarded }) {
  const t = await token(conn, session, guarded);
  const v2 = (conn.settings.kv_version ?? 2) === 2;
  const tail = enc(ref.path.split('/'));
  const path = v2 ? `v1/${enc([ref.mount])}/data/${tail}` : `v1/${enc([ref.mount])}/${tail}`;
  const { json } = await requestJson(joinUrl(conn.settings.address, path), { headers: { 'X-Vault-Token': t, ...nsHeader(conn) }, guarded });
  const data = v2 ? json?.data?.data : json?.data;
  if (!data || typeof data !== 'object' || !Object.prototype.hasOwnProperty.call(data, ref.key)) throw new StoreError(`key ${ref.key} not found`);
  return data[ref.key];
}
