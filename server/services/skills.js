// Skills service: storage, CRUD, and per-dispatch mount preparation.
//
// On disk: DATA_DIR/skills/<slug>/  → the skill's bundle (SKILL.md + assets)
// At dispatch time: prepareSkillsMount() builds a temp dir of symlinks to
// the currently enabled skills, returns its path. That path gets bind-mounted
// into the container as ~/.claude/skills/ so Claude Code's native loader
// picks them up. No prompt injection.

import { mkdirSync, existsSync, rmSync, symlinkSync, readdirSync, statSync, writeFileSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import { randomUUID } from 'crypto';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

function dataDir() {
  return resolve(process.env.DATA_DIR || './data');
}

function skillsRoot() {
  return join(dataDir(), 'skills');
}

function runtimeRoot() {
  return join(dataDir(), 'skills-runtime');
}

export function skillDir(slug) {
  return join(skillsRoot(), slug);
}

// Slug rules: lowercase alphanumeric + dashes, must start with alpha.
// Same rules as app slugs to stay consistent across the product.
export function isValidSlug(slug) {
  return typeof slug === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(slug);
}

export function slugify(input) {
  return String(input || '')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-')
    .slice(0, 64) || 'skill';
}

// ── CRUD ─────────────────────────────────────────────────────────

export function listSkills() {
  return getDb().prepare(
    'SELECT id, slug, name, description, enabled, uploaded_by, uploaded_at FROM skills ORDER BY name'
  ).all();
}

export function getSkill(slug) {
  return getDb().prepare(
    'SELECT id, slug, name, description, enabled, uploaded_by, uploaded_at FROM skills WHERE slug = ?'
  ).get(slug) || null;
}

// Read SKILL.md content (for preview in the UI).
export function readSkillMd(slug) {
  const p = join(skillDir(slug), 'SKILL.md');
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

// Parse the YAML frontmatter at the top of a SKILL.md.
//
// Anthropic's skill format is flat top-level scalars (name, description,
// when_to_use, …) — that's all this needs to handle. Supports plain
// `key: value`, single/double quoted values, and basic block scalars
// (`key: |` and `key: >`). Returns {} for files without a frontmatter.
//
// Used to auto-fill the description field when the upload form left it
// blank — a properly-authored skill shouldn't lose its description just
// because the operator skipped a UI field.
export function parseSkillFrontmatter(content) {
  if (typeof content !== 'string') return {};
  const m = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!m) return {};
  const out = {};
  const lines = m[1].split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith('#')) { i++; continue; }
    const kv = line.match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/);
    if (!kv) { i++; continue; }
    const key = kv[1];
    let val = kv[2];
    if (val === '|' || val === '>') {
      // Block scalar — gather subsequent indented lines.
      const fold = val === '>';
      const buf = [];
      i++;
      while (i < lines.length && /^\s+/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s+/, ''));
        i++;
      }
      val = fold ? buf.join(' ').trim() : buf.join('\n').trim();
    } else {
      i++;
      // Strip matching surrounding quotes.
      const q = val.match(/^(['"])([\s\S]*)\1$/);
      if (q) val = q[2];
      val = val.trim();
    }
    out[key] = val;
  }
  return out;
}

// Create a skill from inline markdown content (paste flow).
// Returns the created row.
export function createSkillFromMarkdown({ slug, name, description, content, uploadedBy }) {
  if (!isValidSlug(slug)) throw new Error('invalid slug');
  if (!name?.trim()) throw new Error('name required');
  if (!content?.trim()) throw new Error('content required');

  const dir = skillDir(slug);
  if (existsSync(dir)) throw new Error('skill already exists');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'SKILL.md'), content);

  // Fall back to the SKILL.md frontmatter description if the upload form
  // left the field empty — a properly-authored skill ships with one.
  const fm = parseSkillFrontmatter(content);
  const finalDescription = (description?.trim() || fm.description?.trim() || null);

  const db = getDb();
  db.prepare(
    'INSERT INTO skills (slug, name, description, uploaded_by) VALUES (?, ?, ?, ?)'
  ).run(slug, name.trim(), finalDescription, uploadedBy || null);

  log.info(`Skills: created '${slug}' from markdown (${content.length} chars)`);
  return getSkill(slug);
}

// Create a skill from a zip buffer (drag-zip flow). Caller passes the
// extracted file map { 'SKILL.md': Buffer, 'scripts/foo.py': Buffer, ... }.
export function createSkillFromFiles({ slug, name, description, files, uploadedBy }) {
  if (!isValidSlug(slug)) throw new Error('invalid slug');
  if (!name?.trim()) throw new Error('name required');
  if (!files || typeof files !== 'object') throw new Error('files required');
  if (!files['SKILL.md']) throw new Error('SKILL.md missing from upload');

  const dir = skillDir(slug);
  if (existsSync(dir)) throw new Error('skill already exists');
  mkdirSync(dir, { recursive: true });

  for (const [relPath, buf] of Object.entries(files)) {
    // Path safety: reject anything that escapes the skill dir.
    if (relPath.includes('..') || relPath.startsWith('/')) {
      rmSync(dir, { recursive: true, force: true });
      throw new Error(`unsafe path in upload: ${relPath}`);
    }
    const dest = join(dir, relPath);
    mkdirSync(join(dest, '..'), { recursive: true });
    writeFileSync(dest, buf);
  }

  // Fall back to SKILL.md frontmatter for description when the form was empty.
  const skillMd = files['SKILL.md'];
  const skillMdText = Buffer.isBuffer(skillMd) ? skillMd.toString('utf8') : String(skillMd || '');
  const fm = parseSkillFrontmatter(skillMdText);
  const finalDescription = (description?.trim() || fm.description?.trim() || null);

  const db = getDb();
  db.prepare(
    'INSERT INTO skills (slug, name, description, uploaded_by) VALUES (?, ?, ?, ?)'
  ).run(slug, name.trim(), finalDescription, uploadedBy || null);

  log.info(`Skills: created '${slug}' from ${Object.keys(files).length} files`);
  return getSkill(slug);
}

export function updateSkill(slug, { enabled, name, description }) {
  const db = getDb();
  const row = getSkill(slug);
  if (!row) throw new Error('skill not found');

  const fields = [];
  const values = [];
  if (typeof enabled === 'boolean') { fields.push('enabled = ?'); values.push(enabled ? 1 : 0); }
  if (typeof name === 'string')      { fields.push('name = ?');    values.push(name.trim()); }
  if (typeof description === 'string') { fields.push('description = ?'); values.push(description.trim() || null); }
  if (!fields.length) return row;

  values.push(slug);
  db.prepare(`UPDATE skills SET ${fields.join(', ')} WHERE slug = ?`).run(...values);
  return getSkill(slug);
}

export function deleteSkill(slug) {
  const row = getSkill(slug);
  if (!row) return false;
  try { rmSync(skillDir(slug), { recursive: true, force: true }); } catch (_) {}
  getDb().prepare('DELETE FROM skills WHERE slug = ?').run(slug);
  log.info(`Skills: deleted '${slug}'`);
  return true;
}

// ── App ↔ Skill assignment ───────────────────────────────────────

/** App slugs this skill is assigned to. */
export function listAppsForSkill(skillSlug) {
  return getDb()
    .prepare('SELECT app_slug FROM app_skills WHERE skill_slug = ? ORDER BY app_slug')
    .all(skillSlug)
    .map(r => r.app_slug);
}

/** Skill slugs assigned to this app. */
export function listSkillsForApp(appSlug) {
  return getDb()
    .prepare('SELECT skill_slug FROM app_skills WHERE app_slug = ? ORDER BY skill_slug')
    .all(appSlug)
    .map(r => r.skill_slug);
}

/**
 * Replace the set of apps assigned to a skill. Validates each slug
 * against the apps table. Returns the new list.
 */
export function setAppsForSkill(skillSlug, appSlugs) {
  if (!getSkill(skillSlug)) throw new Error('skill not found');
  if (!Array.isArray(appSlugs)) throw new Error('app_slugs must be an array');
  const db = getDb();
  const known = new Set(db.prepare('SELECT slug FROM apps').all().map(r => r.slug));
  const cleaned = [...new Set(appSlugs.map(s => String(s).trim()).filter(Boolean))];
  for (const s of cleaned) {
    if (!known.has(s)) throw new Error(`unknown app: ${s}`);
  }
  db.transaction(() => {
    db.prepare('DELETE FROM app_skills WHERE skill_slug = ?').run(skillSlug);
    const ins = db.prepare('INSERT INTO app_skills (app_slug, skill_slug) VALUES (?, ?)');
    for (const s of cleaned) ins.run(s, skillSlug);
  })();
  log.info(`Skills: ${skillSlug} assigned to ${cleaned.length} app(s)`);
  return cleaned;
}

// ── Mount preparation ────────────────────────────────────────────

// Build a fresh dir of symlinks pointing to all currently enabled skills.
// Returns { dir, cleanup } or null if no skills apply to this app.
//
// Caller bind-mounts `dir` into the container as ~/.claude/skills/ and is
// responsible for invoking cleanup() when done. For long-lived session
// containers (Builder/Ask) the cleanup happens on session stop.
//
// `appSlug` filters by the app_skills join — only skills that are
// (a) enabled globally AND (b) assigned to this app land in the mount.
// Passing no slug returns null (no mount) — every legitimate caller
// knows which app it's running for, so this catches accidental misuse
// rather than silently leaking the global set.
export function prepareSkillsMount(appSlug) {
  if (!appSlug) return null;
  const enabled = getDb().prepare(`
    SELECT s.slug FROM skills s
    JOIN app_skills aps ON aps.skill_slug = s.slug
    WHERE s.enabled = 1 AND aps.app_slug = ?
  `).all(appSlug);
  if (!enabled.length) return null;

  mkdirSync(runtimeRoot(), { recursive: true });
  const dir = join(runtimeRoot(), randomUUID());
  mkdirSync(dir);

  let linked = 0;
  for (const { slug } of enabled) {
    const src = skillDir(slug);
    if (!existsSync(src)) continue; // orphan DB row; skip
    try {
      symlinkSync(src, join(dir, slug));
      linked++;
    } catch (err) {
      log.warn(`Skills: symlink failed for ${slug}: ${err.message}`);
    }
  }

  if (!linked) {
    try { rmSync(dir, { recursive: true, force: true }); } catch (_) {}
    return null;
  }

  return {
    dir,
    cleanup() {
      try { rmSync(dir, { recursive: true, force: true }); } catch (_) {}
    },
  };
}

// Sweep stale runtime dirs older than 24h on startup. Best-effort.
export function sweepStaleRuntimes() {
  try {
    if (!existsSync(runtimeRoot())) return;
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    for (const entry of readdirSync(runtimeRoot())) {
      const p = join(runtimeRoot(), entry);
      try {
        if (statSync(p).mtimeMs < cutoff) rmSync(p, { recursive: true, force: true });
      } catch (_) {}
    }
  } catch (_) {}
}
