// Golden-path scaffold templates for new managed apps (templates/scaffold/<id>).
//
// Each template is a complete starter repository: identity middleware that
// verifies AppCrane's signed X-AppCrane-* headers and refuses unsigned ones,
// a role check, /api/health in the deploy gate's {status, version} shape,
// a test suite, env.example (names only), a README and a CLAUDE.md for coding
// agents. appcrane_create_managed_app({ template }) commits one as the new
// repository's first push.
//
// Two placeholders are substituted: __APP_SLUG__ (already validated as a
// slug, so safe anywhere) and __APP_NAME__ (free text, so escaped for the file
// it lands in, and only allowed in files whose escaping is known).

import { readdirSync, readFileSync, lstatSync } from 'fs';
import { join, resolve, dirname, extname } from 'path';
import { fileURLToPath } from 'url';
import { isEnvFilePath } from './envFilePushGuard.js';

export const SCAFFOLD_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'templates', 'scaffold');
export const SCAFFOLD_TEMPLATE_IDS = Object.freeze(['node-react', 'python-fastapi', 'static-site']);

const MANIFEST = 'template.json';
const SKIP_DIRS = new Set(['node_modules', 'dist', '__pycache__', '.pytest_cache', '.venv', 'venv']);
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;
const MAX_NAME = 100;

const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const NAME_ESCAPERS = {
  '.json': (s) => JSON.stringify(s).slice(1, -1),
  '.html': escapeHtml,
  '.md': escapeHtml,
};

function templateDir(id) {
  if (!SCAFFOLD_TEMPLATE_IDS.includes(id)) {
    throw new Error(`unknown template '${id}': use one of ${SCAFFOLD_TEMPLATE_IDS.join(', ')}`);
  }
  return join(SCAFFOLD_ROOT, id);
}

/** [{ id, name, description, stack }] for every template. */
export function listScaffoldTemplates() {
  return SCAFFOLD_TEMPLATE_IDS.map((id) => {
    const m = JSON.parse(readFileSync(join(templateDir(id), MANIFEST), 'utf8'));
    return { id, name: m.name, description: m.description, stack: m.stack || [], test_command: m.test_command || null };
  });
}

function walk(root, rel = '') {
  const out = [];
  for (const d of readdirSync(join(root, rel), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const p = rel ? `${rel}/${d.name}` : d.name;
    if (d.isSymbolicLink()) throw new Error(`template file ${p} is a symbolic link`);
    if (d.isDirectory()) {
      if (!SKIP_DIRS.has(d.name)) out.push(...walk(root, p));
    } else if (d.isFile() && p !== MANIFEST) {
      out.push(p);
    }
  }
  return out;
}

function cleanName(name, slug) {
  const s = String(name ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, MAX_NAME);
  return s || slug;
}

/** Throw for a `template` argument that names no template; undefined/null pass. */
export function assertScaffoldTemplateId(id) {
  if (id === undefined || id === null) return;
  if (typeof id !== 'string' || !SCAFFOLD_TEMPLATE_IDS.includes(id)) {
    throw new Error(`template must be one of ${SCAFFOLD_TEMPLATE_IDS.join(', ')}`);
  }
}

/**
 * Commit the rendered template to a just-created managed app's repository as
 * one commit. No deploy is started: the caller tells the agent to deploy.
 * Never throws: a failure is returned, because the app itself was created.
 */
export async function seedManagedAppFromTemplate(app, templateId, { name, actorId = null } = {}) {
  try {
    const files = renderScaffoldTemplate(templateId, { slug: app.slug, name: name ?? app.name });
    const { pushFilesToManagedRepo } = await import('./managedRepo.js');
    const r = await pushFilesToManagedRepo(app, files, {
      actorId,
      deployOnPush: false,
      branch: app.branch || undefined,
      message: `scaffold: ${templateId} template for ${app.slug}`,
    });
    return { id: templateId, seeded: true, files: files.length, commit: r?.commit?.sha || null };
  } catch (e) {
    return { id: templateId, seeded: false, error: e.message };
  }
}

/**
 * The template's files with placeholders filled in, as the
 * pushFilesToManagedRepo input shape: [{ path, content }], sorted by path.
 */
export function renderScaffoldTemplate(id, { slug, name } = {}) {
  if (typeof slug !== 'string' || !SLUG_RE.test(slug)) throw new Error('slug must be lowercase letters, digits and dashes');
  const root = templateDir(id);
  const appName = cleanName(name, slug);
  return walk(root).map((path) => {
    if (isEnvFilePath(path)) throw new Error(`template ${id} contains a .env file (${path}); name it env.example`);
    if (lstatSync(join(root, path)).size > 512 * 1024) throw new Error(`template file ${path} is over 512 KB`);
    let content = readFileSync(join(root, path), 'utf8');
    if (content.includes('__APP_NAME__')) {
      const esc = NAME_ESCAPERS[extname(path)];
      if (!esc) throw new Error(`template ${id}: ${path} uses __APP_NAME__ but its file type has no known escaping`);
      content = content.split('__APP_NAME__').join(esc(appName));
    }
    content = content.split('__APP_SLUG__').join(slug);
    return { path, content };
  });
}
