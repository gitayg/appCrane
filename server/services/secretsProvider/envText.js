// .env text, read the way server/index.js reads it: trimmed, # comments
// skipped, split on the first =, the first non-empty value wins.

function lineKey(line) {
  const t = line.trim();
  if (!t || t.startsWith('#')) return null;
  const i = t.indexOf('=');
  return i === -1 ? null : t.slice(0, i).trim();
}

/** { NAME: value } as the server would load it, empty values included. */
export function parseEnvText(text) {
  const out = {};
  for (const line of text.split('\n')) {
    const k = lineKey(line);
    if (k == null) continue;
    const t = line.trim();
    if (!out[k]) out[k] = t.slice(t.indexOf('=') + 1).trim();
  }
  return out;
}

/** The text with every line setting one of `names` gone; nothing else changes. */
export function withoutKeys(text, names) {
  return text.split('\n').filter((line) => !names.includes(lineKey(line))).join('\n');
}

/** The text with `pairs` set: existing lines of those names go, the new ones are appended. */
export function withKeys(text, pairs) {
  let base = withoutKeys(text, Object.keys(pairs));
  if (base && !base.endsWith('\n')) base += '\n';
  return base + Object.entries(pairs).map(([k, v]) => `${k}=${v}\n`).join('');
}

const PROVIDER_SETTING = /^(APPCRANE_SECRETS_|AWS_)/;

/**
 * The CLI does not load .env, the server does. Gives this process the same
 * provider settings the server would see, without overriding what is set, and
 * only when a provider is configured: without one nothing is touched.
 */
export function applyProviderSettings(text, env = process.env) {
  const parsed = parseEnvText(text);
  if (!env.APPCRANE_SECRETS_PROVIDER && !parsed.APPCRANE_SECRETS_PROVIDER) return;
  for (const [k, v] of Object.entries(parsed)) {
    if (PROVIDER_SETTING.test(k) && !env[k]) env[k] = v;
  }
}

/** migrate runs before a provider is configured: only the AWS_* settings the server would see. */
export function applyAwsSettings(text, env = process.env) {
  for (const [k, v] of Object.entries(parseEnvText(text))) {
    if (k.startsWith('AWS_') && !env[k]) env[k] = v;
  }
}
