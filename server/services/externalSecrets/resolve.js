// Turning one ref+ reference into its value, for one app. Called only while a
// container's environment is being built; the value goes back to the caller
// and nowhere else. A failure is a fixed reason plus at most an HTTP status.
import { PROVIDERS, MALFORMED_EXTERNAL, parseExternalRef, prefixAllows } from './refs.js';
import { connectionForRef, openConnection } from './connections.js';
import * as vault from './providers/vault.js';
import * as infisical from './providers/infisical.js';
import * as onepassword from './providers/onepassword.js';
import * as awsssm from './providers/awsssm.js';

const READERS = { vault, infisical, onepassword, awsssm };

/** The connection row a reference would use, checked against its path_prefix. Throws with a reason. No network call. */
export function checkExternalRef(app, plain) {
  const ref = parseExternalRef(plain);
  if (!ref) throw Object.assign(new Error(MALFORMED_EXTERNAL), { code: 'SECRET_REF_MALFORMED' });
  const row = connectionForRef(app, ref);
  const settings = openConnection({ ...row, credentials_enc: null }).settings;
  if (!prefixAllows(settings.path_prefix, ref.canonical, app.slug)) {
    throw Object.assign(new Error(`connection ${row.name} only allows paths under ${settings.path_prefix.split('{slug}').join(app.slug)}`), { code: 'SECRET_REF_OUTSIDE_PREFIX' });
  }
  return { ref, row };
}

/** { value, provider, connection } — or throws an Error whose message is safe to show and log. */
export async function resolveExternalRef(app, plain, sessions = new Map()) {
  const { ref, row } = checkExternalRef(app, plain);
  const conn = openConnection(row);
  if (!sessions.has(conn.id)) sessions.set(conn.id, {});
  let value;
  try {
    value = await READERS[ref.provider].read(conn, ref, { session: sessions.get(conn.id), guarded: conn.scope === 'app' });
  } catch (e) {
    const reason = e?.name === 'StoreError' ? e.message : 'the store could not be read';
    throw Object.assign(new Error(`${PROVIDERS[ref.provider].label} (connection ${conn.name}): ${reason}`), { provider: ref.provider, connection: conn.name });
  }
  if (typeof value === 'number' || typeof value === 'boolean') value = String(value);
  if (typeof value !== 'string') {
    throw Object.assign(new Error(`${PROVIDERS[ref.provider].label} (connection ${conn.name}): the value is not text`), { provider: ref.provider, connection: conn.name });
  }
  return { value, provider: ref.provider, connection: conn.name };
}
