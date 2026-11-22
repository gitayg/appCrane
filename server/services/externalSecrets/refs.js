// The reference grammar for env var values held in an outside secret store.
//
//   ref+vault://<mount>/<path...>#<key>[?connection=<name>]   KV v2 (or v1) secret, one key
//   ref+infisical://<projectId>/<environment>[/<path...>]#<SECRET_NAME>
//   ref+op://<vault>/<item>[/<section>]/<field>               1Password secret reference
//   ref+awsssm:///<param/name>[#<json key>]                   SSM Parameter Store, decrypted
//
// `?connection=<name>` (before any #) picks a named connection; without it the
// app's own connection for the provider is used, else the platform's. Segments
// are a closed character set with no `.`/`..` and no percent-encoding, so the
// text cannot be steered into another path once a provider URL-encodes it.

export const EXTERNAL_PREFIX = 'ref+';

export const PROVIDERS = {
  vault: { scheme: 'vault', source: 'vault', label: 'HashiCorp Vault' },
  infisical: { scheme: 'infisical', source: 'infisical', label: 'Infisical' },
  onepassword: { scheme: 'op', source: 'onepassword', label: '1Password' },
  awsssm: { scheme: 'awsssm', source: 'aws_ssm', label: 'AWS SSM Parameter Store' },
};
const BY_SCHEME = Object.fromEntries(Object.entries(PROVIDERS).map(([id, p]) => [p.scheme, id]));

const MAX_REF = 1024;
const SEG_RE = /^[A-Za-z0-9_@+=,-][A-Za-z0-9_.@+=,-]{0,255}$/;
const OP_SEG_RE = /^[A-Za-z0-9_@+=,() -][A-Za-z0-9_.@+=,() -]{0,255}$/;
const KEY_RE = /^[A-Za-z0-9_.@+=-]{1,256}$/;
export const CONNECTION_NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const UNSAFE_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

export const MALFORMED_EXTERNAL = 'malformed reference: use ref+vault://<mount>/<path>#<key>, ref+infisical://<project>/<env>[/<path>]#<NAME>, '
  + 'ref+op://<vault>/<item>[/<section>]/<field> or ref+awsssm:///<name>[#<key>], optionally with ?connection=<name> before the #';

export function isExternalRef(plain) {
  return typeof plain === 'string' && plain.startsWith(EXTERNAL_PREFIX);
}

const segOk = (s, re = SEG_RE) => re.test(s) && s !== '.' && s !== '..' && !/^\s|\s$/.test(s);

function splitSegments(body, re) {
  if (!body) return null;
  const segs = body.split('/');
  return segs.every((s) => segOk(s, re)) ? segs : null;
}

/**
 * { provider, connection, ... } or null. Fields per provider:
 * vault { mount, path, key }, infisical { project, environment, path, name },
 * onepassword { vault, item, section, field }, awsssm { name, key }.
 * `canonical` is the store-side path a connection's path_prefix is matched on.
 */
export function parseExternalRef(plain) {
  if (!isExternalRef(plain) || plain.length > MAX_REF) return null;
  const m = /^ref\+([a-z]+):\/\/(.*)$/s.exec(plain);
  if (!m) return null;
  const provider = BY_SCHEME[m[1]];
  if (!provider) return null;
  let rest = m[2];
  let fragment = null;
  const hash = rest.indexOf('#');
  if (hash >= 0) { fragment = rest.slice(hash + 1); rest = rest.slice(0, hash); }
  let connection = null;
  const q = rest.indexOf('?');
  if (q >= 0) {
    const query = rest.slice(q + 1);
    rest = rest.slice(0, q);
    const cm = /^connection=([a-z0-9][a-z0-9-]{0,62})$/.exec(query);
    if (!cm) return null;
    connection = cm[1];
  }
  if (fragment !== null && (!KEY_RE.test(fragment) || UNSAFE_KEYS.has(fragment))) return null;

  if (provider === 'vault') {
    const segs = splitSegments(rest);
    if (!segs || segs.length < 2 || fragment === null) return null;
    const [mount, ...path] = segs;
    return { provider, connection, mount, path: path.join('/'), key: fragment, canonical: segs.join('/') };
  }
  if (provider === 'infisical') {
    const segs = splitSegments(rest);
    if (!segs || segs.length < 2 || fragment === null) return null;
    const [project, environment, ...path] = segs;
    return { provider, connection, project, environment, path: `/${path.join('/')}`, name: fragment, canonical: segs.join('/') };
  }
  if (provider === 'onepassword') {
    const segs = splitSegments(rest, OP_SEG_RE);
    if (!segs || segs.length < 3 || segs.length > 4 || fragment !== null) return null;
    const [vault, item, ...tail] = segs;
    const field = tail.pop();
    return { provider, connection, vault, item, section: tail[0] ?? null, field, canonical: `${vault}/${item}` };
  }
  // awsssm: ref+awsssm:///a/b (hierarchical) or ref+awsssm://name (flat).
  const hierarchical = rest.startsWith('/');
  const segs = splitSegments(hierarchical ? rest.slice(1) : rest);
  if (!segs || (!hierarchical && segs.length !== 1)) return null;
  const name = `${hierarchical ? '/' : ''}${segs.join('/')}`;
  if (name.length > 2048) return null;
  return { provider, connection, name, key: fragment, canonical: name };
}

export function providerOfRef(plain) {
  const m = /^ref\+([a-z]+):\/\//.exec(typeof plain === 'string' ? plain : '');
  return m ? BY_SCHEME[m[1]] ?? null : null;
}

/** The `source` an API reports for a reference value. */
export function externalSource(plain) {
  const p = providerOfRef(plain);
  return p ? PROVIDERS[p].source : 'external';
}

/** path_prefix with {slug} expanded, matched on whole segments. */
export function prefixAllows(prefix, canonical, slug) {
  if (!prefix) return true;
  const want = prefix.split('{slug}').join(slug).replace(/\/+$/, '');
  if (!want) return true;
  return canonical === want || canonical.startsWith(`${want}/`);
}
