// Which keys the platform secret may set on the server's environment.

// An allowlist, not a denylist: whoever can write the secret must not be able to
// set GIT_SSH_COMMAND, NODE_EXTRA_CA_CERTS, HTTPS_PROXY or the like on the server.
export const ALLOWED_PLATFORM_KEYS = Object.freeze([
  'ENCRYPTION_KEY', 'ANTHROPIC_API_KEY', 'SMTP_PASS', 'GRAPH_CLIENT_SECRET', 'GITHUB_TOKEN', 'CATALOG_GITHUB_TOKEN',
]);
const ENCRYPTION_KEY_RE = /^[0-9a-fA-F]{64}$/;

// The CloudFormation template creates the secret with this one generated key,
// so the template never holds a value. It is not configuration: never loaded.
export const PLACEHOLDER_KEY = 'PLACEHOLDER';

// What `crane secrets migrate` moves out of .env. Not ANTHROPIC_API_KEY: it
// lives encrypted in the database, and the boot moves it there from .env. It
// stays on the allowlist, so a platform secret that already holds it still
// loads (and the boot copies it into the database).
export const PLATFORM_SECRET_NAMES = ['ENCRYPTION_KEY'];

export const MAX_SECRET_BYTES = 65536;

export function assertAllowedKey(name) {
  if (!ALLOWED_PLATFORM_KEYS.includes(name)) {
    throw new Error(`the key name ${JSON.stringify(String(name).slice(0, 64))} is not allowed in the platform secret (allowed: ${ALLOWED_PLATFORM_KEYS.join(', ')})`);
  }
}

/** A secret string as a plain object. JSON.parse's own message quotes the input, so it never leaves here. */
export function parseSecretObject(text, label) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not a JSON object`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} is not a JSON object`);
  return parsed;
}

/** The keys to load from the platform secret. Throws naming keys, never values. */
export function validatedPlatformKeys(values, label) {
  const out = {};
  for (const [name, value] of Object.entries(values)) {
    if (name === PLACEHOLDER_KEY) continue;
    assertAllowedKey(name);
    if (typeof value !== 'string' || !value) throw new Error(`${label}: ${name} must be a non-empty string`);
    if (name === 'ENCRYPTION_KEY' && !ENCRYPTION_KEY_RE.test(value)) throw new Error(`${label}: ENCRYPTION_KEY must be 64 hex characters`);
    out[name] = value;
  }
  return out;
}

export function assertSecretSize(text, label) {
  if (Buffer.byteLength(text, 'utf8') > MAX_SECRET_BYTES) throw new Error(`${label} is larger than Secrets Manager's ${MAX_SECRET_BYTES} byte limit`);
}
