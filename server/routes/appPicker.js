import { Router } from 'express';
import { readFileSync } from 'fs';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { craneDomain, resolveAppHost } from './appHandoff.js';

// App host: GET /__appcrane/picker     hidden page the dashboard frames during a pick
//           GET /__appcrane/picker.js  its script (server/assets/app-picker.js)
//
// With app isolation the dashboard cannot see inside an app's frame, so the
// Request and coder pickers fell back to "this page". This page is on the
// app's own host, so it can run the picker in the app's frame and post the
// picked element to the dashboard. Only the platform host may frame it, and it
// posts only to the platform host.
export const appPickerRouter = Router();

const SCRIPT = readFileSync(new URL('../assets/app-picker.js', import.meta.url), 'utf8');

function platformOrigin(req) {
  const domain = craneDomain();
  if (!/^[a-z0-9.-]+$/.test(domain) || !resolveAppHost(getDb(), req.headers.host)) throw new AppError('Not found', 404, 'NOT_FOUND');
  return `https://${domain}`;
}

appPickerRouter.get('/picker', (req, res) => {
  const platform = platformOrigin(req);
  res.removeHeader('X-Frame-Options');
  res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'self'; frame-ancestors ${platform}`);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.type('html').send(
    `<!doctype html><meta charset="utf-8"><meta name="appcrane-platform" content="${platform}">` +
    `<script src="/__appcrane/picker.js"></script>`,
  );
});

appPickerRouter.get('/picker.js', (req, res) => {
  platformOrigin(req);
  res.setHeader('Cache-Control', 'no-cache');
  res.type('application/javascript').send(SCRIPT);
});
