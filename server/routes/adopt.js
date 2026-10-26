import { Router } from 'express';
import multer from 'multer';
import { requireAuth } from '../middleware/auth.js';
import { adoptLimits } from '../services/adopt/archive.js';
import { TOOL_GUIDES } from '../services/adopt/sources.js';
import { adoptAnalyzed, adoptionView, analyzeSource, assertMayAdopt, getAdoption } from '../services/adopt/flow.js';

// Adopt an app: /api/adopt. Every route needs a signed-in caller allowed to
// create apps (platform.create_app, the same permission POST /api/apps
// checks); an analysis is readable and adoptable only by the person who ran it.
// No :slug route here: the app does not exist until adopt creates it, and the
// creator becomes its owner.

const router = Router();
router.use(requireAuth);

function send(res, e) {
  const status = e.statusCode || e.status || (/^Forbidden/.test(e.message || '') ? 403 : 500);
  const body = { code: e.code && typeof e.code === 'string' ? e.code : status === 403 ? 'FORBIDDEN' : 'ADOPT_FAILED', message: e.message };
  if (e.tool) body.tool = e.tool;
  if (e.appSlug) body.app = e.appSlug;
  res.status(status).json({ error: body });
}

const guard = (fn) => async (req, res) => {
  try { await fn(req, res); } catch (e) { send(res, e); }
};

router.get('/sources', guard(async (req, res) => {
  assertMayAdopt(req.user);
  const l = adoptLimits();
  res.json({
    tools: TOOL_GUIDES.map((g) => ({ tool: g.tool, label: g.label, steps: g.steps })),
    limits: { max_archive_bytes: l.maxArchiveBytes, max_total_bytes: l.maxTotalBytes, max_file_bytes: l.maxFileBytes, max_files: l.maxFiles },
  });
}));

function receiveZip(req, res) {
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: adoptLimits().maxArchiveBytes, files: 1, fields: 10, fieldSize: 4096 },
    fileFilter: (_req, file, cb) => {
      if (/\.zip$/i.test(file.originalname || '')) cb(null, true);
      else cb(Object.assign(new Error('Upload a .zip file.'), { statusCode: 400, code: 'INVALID_FILE' }));
    },
  }).single('file');
  return new Promise((resolveUpload, reject) => {
    upload(req, res, (err) => {
      if (!err) return resolveUpload(req.file);
      if (err.code === 'LIMIT_FILE_SIZE') {
        return reject(Object.assign(new Error(`The archive is over the ${adoptLimits().maxArchiveBytes} byte limit.`), { statusCode: 413, code: 'ARCHIVE_TOO_LARGE' }));
      }
      reject(Object.assign(err, { statusCode: err.statusCode || 400, code: typeof err.code === 'string' ? err.code : 'UPLOAD_ERROR' }));
    });
  });
}

/** POST /api/adopt/analyze — JSON { github_url, ref?, github_token?, use_github_app? } or multipart field "file" (.zip). */
router.post('/analyze', guard(async (req, res) => {
  assertMayAdopt(req.user);
  let source;
  if (req.is('multipart/form-data')) {
    const file = await receiveZip(req, res);
    if (!file) throw Object.assign(new Error('No file uploaded (field name: file).'), { statusCode: 400, code: 'NO_FILE' });
    source = { kind: 'zip', buffer: file.buffer, filename: file.originalname };
  } else {
    const b = req.body || {};
    source = { kind: 'github', url: b.github_url, ref: b.ref, github_token: b.github_token, use_github_app: b.use_github_app === true };
  }
  const out = await analyzeSource(req.user, source);
  res.status(201).json(out);
}));

router.get('/:id', guard(async (req, res) => {
  assertMayAdopt(req.user);
  res.json(adoptionView(getAdoption(req.user, req.params.id)));
}));

/** POST /api/adopt/:id/adopt — { name, slug, description?, env_vars?: { KEY: value }, intake?, open_requests?, acknowledge_risks?, stage: 'sandbox' } */
router.post('/:id/adopt', guard(async (req, res) => {
  const b = req.body || {};
  const result = await adoptAnalyzed(req.user, {
    id: req.params.id, name: b.name, slug: b.slug, description: b.description, stage: b.stage ?? 'sandbox',
    env_vars: b.env_vars, intake: b.intake, open_requests: b.open_requests === true, acknowledge_risks: b.acknowledge_risks === true,
  });
  res.status(201).json(result);
}));

export default router;
