import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

/**
 * Validate that a committed `dist/index.html` references files that actually
 * exist in the same `dist/` directory.
 *
 * Failure mode this catches: developer runs `vite build`, commits dist/, then
 * later edits source without re-building. index.html now references hashed
 * filenames (e.g. `/assets/index-9f3a.js`) that don't exist on disk anymore.
 * AppCrane builds + deploys fine, container is up, /api/health is green —
 * but users see a white page because the script tags 404.
 *
 * This runs BEFORE the docker build so a known-stale dist fails fast with
 * `DIST_OUT_OF_SYNC` and a fixable error message, instead of going "live"
 * with a broken frontend.
 *
 * Skips external URLs (http://, //, data:, mailto:, tel:, fragments).
 *
 * Returns { valid, errors, warnings, foundDistAt }. `foundDistAt` is null
 * when no committed dist was found anywhere — that's not an error, just a
 * signal that AppCrane will build the frontend itself.
 */
export function validateDistConsistency(releaseDir, { frontendDirs = ['client', 'frontend', 'web', 'app', 'apps/web', 'apps/frontend', '.'] } = {}) {
  const errors = [];
  const warnings = [];
  let foundDistAt = null;

  for (const dir of frontendDirs) {
    const distDir = dir === '.' ? join(releaseDir, 'dist') : join(releaseDir, dir, 'dist');
    const indexPath = join(distDir, 'index.html');
    if (!existsSync(indexPath)) continue;

    foundDistAt = dir === '.' ? 'dist' : `${dir}/dist`;

    let html;
    try {
      html = readFileSync(indexPath, 'utf8');
    } catch (e) {
      warnings.push(`Could not read ${foundDistAt}/index.html: ${e.message}`);
      break;
    }

    // Pull every src=/href= reference. Quote style and attribute quoting
    // varies; this is intentionally loose.
    const refs = [];
    const matcher = /\b(?:src|href)=["']([^"']+)["']/gi;
    for (const m of html.matchAll(matcher)) {
      const ref = m[1];
      if (/^(https?:|data:|\/\/|mailto:|tel:|#)/i.test(ref)) continue;
      refs.push(ref);
    }

    for (const ref of refs) {
      const clean = ref.replace(/^\/+/, '').split('?')[0].split('#')[0];
      if (!clean) continue;
      const filePath = join(distDir, clean);
      if (!existsSync(filePath)) {
        errors.push(`${foundDistAt}/index.html references "${ref}" but ${foundDistAt}/${clean} does not exist on disk`);
      }
    }

    // Only validate the first dist we find — apps don't typically have two.
    break;
  }

  if (errors.length) {
    errors.push(
      'Either run your bundler (`vite build` / `webpack build` / `npm run build`) and recommit ' +
      `${foundDistAt}/, or remove ${foundDistAt}/ from the repo and let AppCrane build the frontend on deploy.`
    );
  }

  return { valid: errors.length === 0, errors, warnings, foundDistAt };
}
