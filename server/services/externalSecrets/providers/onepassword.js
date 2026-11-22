// 1Password: a Connect server (REST, bearer token), or a service account token
// through the `op` CLI. A service account has no REST API; its only other client
// is @1password/sdk (WASM, a new dependency), so without `op` on the server that
// mode fails naming the missing binary.
import { execFile } from 'node:child_process';
import { StoreError, enc, joinUrl, requestJson } from '../http.js';

const ID_RE = /^[a-z0-9]{26}$/;
const quote = (s) => `"${s.replace(/["\\]/g, '\\$&')}"`;

async function findId(conn, path, kind, name, guarded) {
  const field = kind === 'vault' ? 'name' : 'title';
  const headers = { Authorization: `Bearer ${conn.credentials.token}` };
  const url = joinUrl(conn.settings.connect_url, `${path}?${new URLSearchParams({ filter: `${field} eq ${quote(name)}` })}`);
  const { json } = await requestJson(url, { headers, guarded });
  const hits = Array.isArray(json) ? json.filter((x) => x?.[field] === name) : [];
  if (hits.length === 1) return hits[0].id;
  if (hits.length > 1) throw new StoreError(`more than one ${kind} named ${name}`);
  if (ID_RE.test(name)) return name;
  throw new StoreError(`${kind} ${name} not found`);
}

async function viaConnect(conn, ref, guarded) {
  const headers = { Authorization: `Bearer ${conn.credentials.token}` };
  const vaultId = await findId(conn, 'v1/vaults', 'vault', ref.vault, guarded);
  const itemId = await findId(conn, `v1/vaults/${enc([vaultId])}/items`, 'item', ref.item, guarded);
  const { json } = await requestJson(joinUrl(conn.settings.connect_url, `v1/vaults/${enc([vaultId])}/items/${enc([itemId])}`), { headers, guarded });
  const sections = Array.isArray(json?.sections) ? json.sections : [];
  const sectionId = ref.section === null ? null : sections.find((s) => s?.label === ref.section || s?.id === ref.section)?.id;
  if (ref.section !== null && !sectionId) throw new StoreError(`section ${ref.section} not found`);
  const named = (Array.isArray(json?.fields) ? json.fields : []).filter((f) => f && (f.label === ref.field || f.id === ref.field));
  const inSection = ref.section === null ? named : named.filter((f) => f.section?.id === sectionId);
  // No section named: a field outside every section wins over same-named ones inside one.
  const fields = ref.section === null && inSection.length > 1 ? inSection.filter((f) => !f.section) : inSection;
  if (fields.length !== 1) throw new StoreError(fields.length ? `more than one field ${ref.field}` : `field ${ref.field} not found`);
  return fields[0].value;
}

function viaCli(conn, ref) {
  const bin = process.env.APPCRANE_OP_CLI || 'op';
  const target = `op://${[ref.vault, ref.item, ...(ref.section === null ? [] : [ref.section]), ref.field].join('/')}`;
  return new Promise((resolve, reject) => {
    execFile(bin, ['read', '--no-newline', target], {
      timeout: 15000, maxBuffer: 1024 * 1024, shell: false,
      env: { PATH: process.env.PATH || '/usr/bin:/bin', HOME: process.env.HOME || '/tmp', OP_SERVICE_ACCOUNT_TOKEN: conn.credentials.token },
    }, (err, stdout) => {
      if (err?.code === 'ENOENT') return reject(new StoreError('the 1Password CLI (op) is not installed on this server, and a service account token needs it'));
      if (err) return reject(new StoreError(`op read failed${typeof err.code === 'number' ? ` (exit ${err.code})` : ''}`));
      resolve(stdout);
    });
  });
}

export async function read(conn, ref, { guarded }) {
  return (conn.settings.mode ?? 'connect') === 'service_account' ? viaCli(conn, ref) : viaConnect(conn, ref, guarded);
}
