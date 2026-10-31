import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import * as mfa from '../services/mfa.js';
import {
  DEFAULT_DEPS, LAST_RUN_KEY, checkItems, detectRunMode, publicRun,
  isRunning, claimRun, releaseRun, runScript, readLastRun, writeLastRun,
} from '../services/hostHardening.js';
import log from '../utils/logger.js';

// Settings > Job Health > Host limits (platform admin). Mounted at
// /api/settings ahead of the generic settings router.

const ipOf = (req) => req.ip || req.socket?.remoteAddress || 'unknown';
// MFA belongs to the person signed in, not a view-as target.
const realUser = (db, req) => db.prepare('SELECT * FROM users WHERE id = ?').get((req.real_user || req.user).id);

async function statusBody(db, user, d, run) {
  const r = run || await detectRunMode(d);
  const supported = d.platform === 'linux';
  const body = {
    supported,
    items: await checkItems(d),
    run: publicRun(r),
    mfa_required: mfa.isEnrolled(db, user.id),
    running: isRunning(),
    last_run: readLastRun(db),
  };
  if (!supported) body.reason = r.reason;
  return body;
}

export function createHostHardeningRouter(deps = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const router = Router();

  router.get('/host-hardening', requireAuth, requirePlatformAdmin, async (req, res) => {
    const db = getDb();
    res.json(await statusBody(db, realUser(db, req), d));
  });

  router.post('/host-hardening/apply', requireAuth, requirePlatformAdmin, async (req, res) => {
    const db = getDb();
    const user = realUser(db, req);
    if (!claimRun()) throw new AppError('Host limits are already being applied', 409, 'RUNNING');
    let run;
    let mfaState;
    let proceed = false;
    try {
      run = await detectRunMode(d);
      if (!run.argv) {
        return res.status(400).json({
          error: { code: 'MANUAL_ONLY', message: run.reason || 'Apply is not available on this host', command: run.command },
          command: run.command,
        });
      }
      if (mfa.isEnrolled(db, user.id)) {
        const code = String(req.body?.mfa_code ?? '').trim();
        if (!code) throw new AppError('Enter your two-factor code to apply host limits', 403, 'MFA_REQUIRED');
        const v = mfa.verifyCode(db, user, code, { ip: ipOf(req) });
        if (!v.ok) {
          if (v.reason === 'rate_limited') {
            throw new AppError(`Too many wrong codes. Try again in ${Math.ceil(v.retry_after_s / 60)} minute(s).`, 429, 'RATE_LIMITED');
          }
          throw new AppError('That two-factor code is not valid', 403, 'MFA_INVALID');
        }
        mfaState = v.method;
      } else {
        mfaState = 'not-enrolled';
      }
      proceed = true;
    } finally {
      if (!proceed) releaseRun();
    }

    const started = Date.now();
    let result;
    try {
      logAudit(user.id, null, 'host-hardening-started', { mode: run.mode, mfa: mfaState, ip: ipOf(req) });
      result = await runScript(run.argv, d);
      const ok = result.exit_code === 0;
      const lastRun = { at: new Date().toISOString(), ok, exit_code: result.exit_code, by: user.name || user.email || `user ${user.id}` };
      writeLastRun(db, lastRun, user.id);
      logAudit(user.id, null, ok ? 'host-hardening-applied' : 'host-hardening-failed', {
        mode: run.mode, mfa: mfaState, exit_code: result.exit_code, timed_out: result.timed_out,
        duration_ms: Date.now() - started, ip: ipOf(req),
      });
    } catch (e) {
      log.warn(`[host-hardening] apply failed: ${e.message}`);
      throw e;
    } finally {
      releaseRun();
    }
    res.json({ ok: result.exit_code === 0, exit_code: result.exit_code, output: result.output, status: await statusBody(db, user, d) });
  });

  // The last run is written only by Apply. Mounted ahead of the generic
  // PUT /api/settings/:key, which would otherwise let anyone with the
  // settings page forge it; req.params.key is decoded, so an encoded name
  // cannot slip past.
  router.put('/:key', (req, res, next) => {
    if (req.params.key !== LAST_RUN_KEY) return next();
    requireAuth(req, res, (err) => {
      if (err) return next(err);
      requirePlatformAdmin(req, res, (err2) => {
        if (err2) return next(err2);
        next(new AppError('The last host-limits run is recorded by Apply only', 403, 'FORBIDDEN'));
      });
    });
  });

  return router;
}

export default createHostHardeningRouter();
