// The 2.125.14 upgrade asks every app that trusts X-AppCrane-* identity headers
// without checking the v2 signature to start checking it (migration 160).
//
// The proxy strips forged identity headers, so through it they are safe; an app
// that skips the signature check believes any identity sent on a path that skips
// the proxy, and X-AppCrane-Auth-Via is covered only by the v2 signature.
//
// A boot-time scan reads each environment's live release (apps/<slug>/<env>/current):
// an app is asked when some source file reads an identity header and no file
// mentions the v2 signature. One request per app, ever: the partial UNIQUE index
// turns the second insert into a no-op, so a restart, a second environment or a
// request the owner already closed files nothing. Each new request e-mails the
// app's owners and admins like any request a person files. An app deployed from
// a prebuilt image has no source here, so it is never asked.

import { opendir, readFile, stat } from 'fs/promises';
import { join, relative, resolve } from 'path';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { notifyAppAdminsOfNewRequest } from './requestNotify.js';

export const IDENTITY_UPGRADE_REQUESTER = 'AppCrane upgrade';
export const REQUEST_KIND = 'identity-v2';
const ENVS = ['production', 'sandbox'];
const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'target', '__pycache__', 'venv', '.venv']);
const SOURCE_EXT = /\.(m?js|cjs|jsx|ts|tsx|py|rs|go|rb|php|java|kt|cs)$/i;
const MAX_FILES = 20000;
const MAX_BYTES = 1024 * 1024;
const READS_IDENTITY = /x[-_]appcrane[-_](user|auth[-_]via|is[-_]admin|app[-_]roles?)\b/i;
const CHECKS_V2 = /identity[-_]sig[-_]v2|requireV2/i;

async function* sourceFiles(root) {
  let seen = 0;
  const stack = [root];
  while (stack.length) {
    let dir;
    try { dir = await opendir(stack.pop()); } catch { continue; }
    for await (const e of dir) {
      const p = join(dir.path, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(p); continue; }
      if (!e.isFile() || !SOURCE_EXT.test(e.name)) continue;
      if (++seen > MAX_FILES) return;
      yield p;
    }
  }
}

/** Where a release reads identity headers, and whether it checks the v2 signature. */
export async function scanRelease(root) {
  const reads = [];
  let checksV2 = false;
  for await (const file of sourceFiles(root)) {
    let text;
    try {
      if ((await stat(file)).size > MAX_BYTES) continue;
      text = await readFile(file, 'utf8');
    } catch { continue; }
    if (CHECKS_V2.test(text)) checksV2 = true;
    if (!READS_IDENTITY.test(text)) continue;
    const line = text.split('\n').findIndex((l) => READS_IDENTITY.test(l)) + 1;
    reads.push(`${relative(root, file)}:${line}`);
  }
  return { reads: reads.sort(), checksV2 };
}

export function requestMessage(where) {
  return [
    "Security: verify AppCrane's v2 identity signature before trusting X-AppCrane-* headers",
    '',
    `This app reads X-AppCrane-* identity headers (${where}) but does not check the v2 signature that covers them. Through the AppCrane proxy they are safe, because forged copies are stripped there. Any route that skips the proxy can send any identity, and the app would believe it.`,
    '',
    'What to change:',
    '1. Treat a request as signed in only if X-AppCrane-Identity-Sig-V2 checks out:',
    '   - Take these lines, joined with "\\n":',
    '       appcrane-identity-v2',
    '       <X-AppCrane-Identity-Ts>',
    '       then one "name:value" line per header, in this order: x-appcrane-user, x-appcrane-user-id, x-appcrane-user-email, x-appcrane-user-name, x-appcrane-user-role, x-appcrane-app-role, x-appcrane-is-admin, x-appcrane-app-roles, x-appcrane-auth-via',
    '       (the name in lowercase; an absent header gives an empty value)',
    '   - HMAC-SHA256 that text with the APPCRANE_IDENTITY_SECRET env var.',
    '   - base64url-encode the result.',
    '   - Compare it to X-AppCrane-Identity-Sig-V2 using a constant-time comparison.',
    '   - Reject the request if Ts is more than 300 seconds old.',
    '   In Node, appcrane-tenant 1.3.0 does all of this: verifyIdentity(req, { requireV2: true }). It is in the AppCrane repo at packages/tenant and is not on npm.',
    '2. X-AppCrane-Auth-Via is "app-key" when a script signed in with a personal app key. Trust it only after step 1 passes. If the v2 signature is absent, treat the request as unknown, not as a browser session.',
    '',
    'AppCrane sends the v2 signature from version 2.125.14 onward, and APPCRANE_IDENTITY_SECRET is already set in this app\'s containers. Details are in the onboarding guide (appcrane_get_guide), under "Trust model".',
  ].join('\n');
}

/** Scan every app's live releases and file the requests not filed before. Returns the new request ids. */
export async function fileIdentityUpgradeRequests({ db = getDb(), notify = notifyAppAdminsOfNewRequest } = {}) {
  const dataDir = resolve(process.env.DATA_DIR || './data');
  const insert = db.prepare(`
    INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, kind)
    VALUES (?, NULL, ?, ?, 'new', ?)
    ON CONFLICT DO NOTHING
  `);
  const filed = db.prepare('SELECT 1 FROM enhancement_requests WHERE app_slug = ? AND kind = ?');
  const opened = [];
  for (const app of db.prepare("SELECT slug, source_type FROM apps WHERE source_type IS NOT 'image' ORDER BY id").all()) {
    if (filed.get(app.slug, REQUEST_KIND)) continue;
    const reads = new Set();
    let checksV2 = false;
    for (const env of ENVS) {
      const r = await scanRelease(join(dataDir, 'apps', app.slug, env, 'current'));
      r.reads.forEach((w) => reads.add(w));
      checksV2 ||= r.checksV2;
    }
    if (!reads.size || checksV2) continue;
    const list = [...reads];
    const where = list.slice(0, 5).join(', ') + (list.length > 5 ? `, and ${list.length - 5} more` : '');
    const res = insert.run(app.slug, IDENTITY_UPGRADE_REQUESTER, requestMessage(where), REQUEST_KIND);
    if (!res.changes) continue;
    const id = Number(res.lastInsertRowid);
    opened.push(id);
    notify(id);
  }
  if (opened.length) log.info(`[identity-upgrade] filed ${opened.length} request(s) to check the v2 identity signature`);
  return opened;
}

export function startIdentityUpgradeRequests(delayMs = 60_000) {
  const t = setTimeout(() => {
    fileIdentityUpgradeRequests().catch((e) => log.warn(`[identity-upgrade] ${e.message}`));
  }, delayMs);
  t.unref?.();
}
