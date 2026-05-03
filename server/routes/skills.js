// Skills CRUD + upload routes.
// All admin-only — skills are global infrastructure shared across apps.

import { Router } from 'express';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import {
  listSkills, getSkill, createSkillFromMarkdown, createSkillFromFiles,
  updateSkill, deleteSkill, slugify, isValidSlug, readSkillMd,
  listAppsForSkill, setAppsForSkill,
} from '../services/skills.js';
import log from '../utils/logger.js';

const router = Router();
router.use(requireAuth, requireAdmin);

// GET /api/skills — list all skills, each with its assigned app slugs
router.get('/', (req, res) => {
  const skills = listSkills().map(s => ({ ...s, apps: listAppsForSkill(s.slug) }));
  res.json({ skills });
});

// GET /api/skills/:slug — fetch one with SKILL.md preview + app assignments
router.get('/:slug', (req, res) => {
  const skill = getSkill(req.params.slug);
  if (!skill) throw new AppError('skill not found', 404, 'NOT_FOUND');
  res.json({ skill, content: readSkillMd(req.params.slug), apps: listAppsForSkill(req.params.slug) });
});

// PUT /api/skills/:slug/apps — replace app assignment list. Body: { app_slugs: string[] }
router.put('/:slug/apps', auditMiddleware('skill.assign'), (req, res) => {
  const { app_slugs } = req.body || {};
  try {
    const apps = setAppsForSkill(req.params.slug, app_slugs ?? []);
    res.json({ apps });
  } catch (e) {
    res.status(400).json({ error: { code: 'ASSIGN_FAILED', message: e.message } });
  }
});

// POST /api/skills — create from inline markdown OR multipart zip
// JSON body: { name, slug?, description?, content }
// Multipart: file field 'bundle' (zip) + form fields name, slug?, description?
router.post('/', auditMiddleware('skill.create'), async (req, res) => {
  const ct = (req.headers['content-type'] || '').toLowerCase();

  if (ct.startsWith('multipart/')) {
    const multer = (await import('multer')).default;
    const upload = multer({
      storage: multer.memoryStorage(),
      limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB cap on a bundle
    }).single('bundle');

    return upload(req, res, async (err) => {
      if (err) return res.status(400).json({ error: { code: 'UPLOAD_FAILED', message: err.message } });
      if (!req.file) return res.status(400).json({ error: { code: 'NO_FILE', message: 'bundle file required' } });

      const name = (req.body.name || '').trim();
      const slug = (req.body.slug || slugify(name)).trim();
      const description = (req.body.description || '').trim() || null;
      if (!name)             return res.status(400).json({ error: { code: 'VALIDATION', message: 'name required' } });
      if (!isValidSlug(slug)) return res.status(400).json({ error: { code: 'VALIDATION', message: 'invalid slug' } });

      // Accept either a zip bundle (multi-file skill) or a single .md file
      // (the common case — most skills are just a SKILL.md). Detect by extension.
      const fname = (req.file.originalname || '').toLowerCase();
      let files;
      try {
        if (fname.endsWith('.md') || fname.endsWith('.markdown')) {
          files = { 'SKILL.md': req.file.buffer.toString('utf8') };
        } else {
          files = await unzipBuffer(req.file.buffer);
        }
      } catch (e) {
        return res.status(400).json({ error: { code: 'UNZIP_FAILED', message: e.message } });
      }

      try {
        const skill = createSkillFromFiles({ slug, name, description, files, uploadedBy: req.user?.id });
        return res.status(201).json({ skill });
      } catch (e) {
        return res.status(400).json({ error: { code: 'CREATE_FAILED', message: e.message } });
      }
    });
  }

  // JSON body: paste-markdown flow
  const { name, content } = req.body || {};
  const slug = (req.body?.slug || slugify(name)).trim();
  const description = (req.body?.description || '').trim() || null;
  if (!name?.trim())       throw new AppError('name required', 400, 'VALIDATION');
  if (!content?.trim())    throw new AppError('content required', 400, 'VALIDATION');
  if (!isValidSlug(slug))  throw new AppError('invalid slug', 400, 'VALIDATION');

  try {
    const skill = createSkillFromMarkdown({ slug, name, description, content, uploadedBy: req.user?.id });
    res.status(201).json({ skill });
  } catch (e) {
    res.status(400).json({ error: { code: 'CREATE_FAILED', message: e.message } });
  }
});

// PUT /api/skills/:slug — toggle enabled / rename / re-describe
router.put('/:slug', auditMiddleware('skill.update'), (req, res) => {
  try {
    const skill = updateSkill(req.params.slug, req.body || {});
    res.json({ skill });
  } catch (e) {
    if (e.message === 'skill not found') throw new AppError(e.message, 404, 'NOT_FOUND');
    throw new AppError(e.message, 400, 'VALIDATION');
  }
});

// DELETE /api/skills/:slug
router.delete('/:slug', auditMiddleware('skill.delete'), (req, res) => {
  if (!deleteSkill(req.params.slug)) throw new AppError('skill not found', 404, 'NOT_FOUND');
  res.sendStatus(204);
});

// ── Helpers ──────────────────────────────────────────────────────

// Minimal zip extractor — uses adm-zip if present, otherwise unzipper.
// We keep file content in memory; the caller writes them to disk safely.
async function unzipBuffer(buf) {
  let AdmZip;
  try {
    AdmZip = (await import('adm-zip')).default;
  } catch (_) {
    throw new Error('adm-zip not installed; run npm install adm-zip');
  }
  const zip = new AdmZip(buf);
  const entries = zip.getEntries();
  const files = {};
  for (const e of entries) {
    if (e.isDirectory) continue;
    // Strip a single leading top-level dir so users can zip either
    // 'my-skill/SKILL.md' or just 'SKILL.md'.
    const parts = e.entryName.split('/');
    const rel = parts.length > 1 && entries.every(x => x.entryName === parts[0] || x.entryName.startsWith(parts[0] + '/'))
      ? parts.slice(1).join('/')
      : e.entryName;
    if (!rel) continue;
    if (rel.includes('..')) throw new Error(`unsafe path: ${e.entryName}`);
    files[rel] = e.getData();
  }
  if (!Object.keys(files).length) throw new Error('zip is empty');
  return files;
}

export default router;
