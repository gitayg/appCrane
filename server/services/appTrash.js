import crypto from 'crypto';
import { lstatSync, mkdirSync, renameSync, rmSync } from 'fs';
import { join, relative, resolve, sep } from 'path';
import { AppError } from '../utils/errors.js';

// Directories AppCrane moves aside instead of removing: a deleted app's data
// directory, Crane-hosted repository and other per-app directories (APP_DIR_KINDS),
// and orphans an admin clears from the
// Reconcile page. Everything lands in DATA_DIR/trash (same filesystem, so the
// move is a rename) and is recorded in app_trash (migration 275). Nothing here
// removes data on a timer: after RETENTION_DAYS a platform admin may purge.

export const RETENTION_DAYS = 30;

export const dataRoot = () => resolve(process.env.DATA_DIR || './data');
export const trashRoot = () => join(dataRoot(), 'trash');

// The only trees a trash move may take a directory from, and the per-app
// directory each holds for a slug. backups/ also holds the platform's own
// nightly archives (backups/local), key-rotation snapshots and dot-prefixed
// work dirs, which are never an app's.
const MOVABLE_ROOTS = ['apps', 'repos', 'backups', 'app-containers', 'attestations', 'appstudio-npm-cache'];
const NOT_AN_APP_DIR = { backups: (name) => name === 'local' || name.startsWith('key-rotation-') || name.startsWith('.') };

export const SLUG_DIR_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;

// kind -> [tree, directory name for a slug]
export const APP_DIR_KINDS = {
  app_dir: ['apps', (s) => s],
  repo: ['repos', (s) => `${s}.git`],
  backups: ['backups', (s) => s],
  coder_workspace: ['app-containers', (s) => s],
  attestations: ['attestations', (s) => s],
  npm_cache: ['appstudio-npm-cache', (s) => s],
};
export const KIND_OF_TREE = Object.fromEntries(Object.entries(APP_DIR_KINDS).map(([k, [tree]]) => [tree, k]));

/** True when `name` under `tree` may be an app's directory (not one of the platform's own). */
export function isAppDirName(tree, name) {
  const slug = tree === 'repos' ? (name.endsWith('.git') ? name.slice(0, -4) : '') : name;
  return MOVABLE_ROOTS.includes(tree) && SLUG_DIR_RE.test(slug) && !NOT_AN_APP_DIR[tree]?.(name);
}

/** Every per-app directory a slug has under DATA_DIR, as [kind, absolute path]; `refused` holds names that are the platform's own. */
export function appDirsFor(slug) {
  const out = [];
  const refused = [];
  for (const [kind, [tree, nameOf]] of Object.entries(APP_DIR_KINDS)) {
    const name = nameOf(slug);
    if (!isAppDirName(tree, name)) { refused.push({ kind, path: `${tree}/${name}` }); continue; }
    out.push([kind, join(dataRoot(), tree, name)]);
  }
  return { dirs: out, refused };
}

function inside(root, p) {
  return p.startsWith(root + sep);
}

export function assertMovable(path) {
  const p = resolve(path);
  const ok = MOVABLE_ROOTS.some((r) => {
    const root = join(dataRoot(), r);
    return inside(root, p) && !relative(root, p).includes(sep) && isAppDirName(r, relative(root, p));
  });
  if (!ok) throw new AppError(`Only an app's directory directly under DATA_DIR/${MOVABLE_ROOTS.join(', DATA_DIR/')} can be moved to the trash`, 400, 'NOT_MOVABLE');
  const st = lstatSync(p, { throwIfNoEntry: false });
  if (!st) throw new AppError('That directory is no longer there', 404, 'NOT_FOUND');
  if (!st.isDirectory()) throw new AppError('Not a directory (links are never followed)', 400, 'NOT_MOVABLE');
  return p;
}

/**
 * Move one directory into the trash and record it. Returns the app_trash row.
 * `detail` is stored as detail_json; a function is called with the trash path.
 */
export function moveToTrash(db, { kind, path, slug = null, appId = null, reason, userId = null, detail = null }) {
  const from = assertMovable(path);
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, '');
  const name = `${stamp}-${kind}-${String(slug || 'x').replace(/[^a-z0-9-]/g, '')}-${crypto.randomBytes(4).toString('hex')}`;
  mkdirSync(trashRoot(), { recursive: true, mode: 0o700 });
  const to = join(trashRoot(), name);
  renameSync(from, to);
  const d = typeof detail === 'function' ? detail(to) : detail;
  const id = db.prepare(`
    INSERT INTO app_trash (kind, slug, app_id, original_path, trash_path, reason, moved_by, expires_at, detail_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', ?), ?)
  `).run(kind, slug, appId, from, to, reason, userId, `+${RETENTION_DAYS} days`, d ? JSON.stringify(d) : null).lastInsertRowid;
  return db.prepare('SELECT * FROM app_trash WHERE id = ?').get(id);
}

export function listTrash(db) {
  return db.prepare('SELECT * FROM app_trash WHERE purged_at IS NULL AND restored_at IS NULL ORDER BY id DESC').all()
    .map(({ detail_json, ...r }) => ({
      ...r, original_path: relative(dataRoot(), r.original_path), trash_path: relative(dataRoot(), r.trash_path),
      detail: detail_json ? JSON.parse(detail_json) : null,
    }));
}

/** Permanently remove one trash entry whose retention has passed. */
export function purgeTrash(db, id) {
  const row = db.prepare("SELECT *, expires_at <= datetime('now') AS expired FROM app_trash WHERE id = ?").get(id);
  if (!row || row.purged_at || row.restored_at) throw new AppError('No such trash entry', 404, 'NOT_FOUND');
  if (!row.expired) throw new AppError(`Kept until ${row.expires_at} UTC; it can be purged after that`, 409, 'NOT_EXPIRED');
  const p = resolve(row.trash_path);
  if (!inside(resolve(trashRoot()), p)) throw new AppError('Trash entry points outside the trash directory', 500, 'PATH_TRAVERSAL');
  rmSync(p, { recursive: true, force: true });
  db.prepare("UPDATE app_trash SET purged_at = datetime('now') WHERE id = ?").run(id);
  return { id, purged: true };
}
