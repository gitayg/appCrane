// Read-only helpers over an in-memory project tree (Map<path, Buffer>).

const TEXT_EXT = /\.(?:[cm]?[jt]sx?|json|html?|css|scss|vue|svelte|astro|py|toml|ya?ml|md|txt|cfg|ini|env[^/]*|example|sample|template|nix|sh|sql|graphql|gql|prisma|rb|go|php)$/i;
const MAX_SCAN_BYTES = 1024 * 1024;

export function textOf(files, path) {
  const b = files.get(path);
  return b ? b.toString('utf8') : null;
}

export function jsonOf(files, path) {
  const t = textOf(files, path);
  if (t == null) return null;
  try { return JSON.parse(t); } catch { return null; }
}

export function has(files, path) {
  return files.has(path);
}

export function hasDir(files, dir) {
  const prefix = dir.endsWith('/') ? dir : `${dir}/`;
  for (const p of files.keys()) if (p.startsWith(prefix)) return true;
  return false;
}

export function isEnvFile(path) {
  const base = path.split('/').pop();
  return base.startsWith('.env');
}

export function isEnvTemplate(path) {
  return /^\.env\.(?:example|sample|template|dist|defaults)$/i.test(path.split('/').pop());
}

/** Source files worth scanning: text, not huge, not a lockfile. */
export function* scannable(files) {
  for (const [path, buf] of files) {
    if (buf.length > MAX_SCAN_BYTES) continue;
    const base = path.split('/').pop();
    if (/^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|Pipfile\.lock)$/.test(base)) continue;
    if (!TEXT_EXT.test(base) && !isEnvFile(path) && base !== 'Dockerfile' && base !== '.replit') continue;
    yield [path, buf.toString('utf8')];
  }
}

export function allDeps(pkg) {
  return { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
}
