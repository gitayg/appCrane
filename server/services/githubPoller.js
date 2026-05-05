/**
 * GitHub PR poller — closes the request lifecycle bridge.
 *
 * Convention: when a developer (or their MCP agent) opens a PR that
 * implements an enhancement request, they include "Closes appcrane#<id>"
 * in the PR body. This poller scans recent PRs across all GitHub-backed
 * apps every N minutes and progresses requests through the lifecycle:
 *
 *   PR opened referencing #<id>:
 *     - Update enhancement_requests.pr_url
 *     - Move bucket from triage → in_progress (if not already further along)
 *
 *   PR merged referencing #<id>:
 *     - Move bucket → shipped
 *
 *   PR closed without merging:
 *     - Leaves the request alone — could be intentional (rejected approach).
 *
 * Outbound only — never receives webhooks. Substitute for webhooks in
 * environments where AppCrane is firewalled. Polling cadence is controlled
 * by APPCRANE_PR_POLL_MS (default 5 min).
 */

import { getDb } from '../db.js';
import { decrypt } from './encryption.js';
import { applyBucket, bucketize } from './requestStatus.js';
import log from '../utils/logger.js';

const POLL_MS = parseInt(process.env.APPCRANE_PR_POLL_MS || '300000', 10);
const PER_PAGE = 30;
const CLOSES_RE = /\bclos(?:es?|ed|ing)\s+appcrane#(\d+)\b/gi;
let _running = false;
let _lastPolledAt = null;

function parseRepo(url) {
  const m = (url || '').match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?\/?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function ghHeaders(token) {
  const h = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'AppCrane-PRPoller',
  };
  if (token) h.Authorization = `token ${token}`;
  return h;
}

async function fetchRecentPRs(app) {
  const repo = parseRepo(app.github_url);
  if (!repo) return [];
  let token = null;
  if (app.github_token_encrypted) {
    try { token = decrypt(app.github_token_encrypted); } catch (_) { token = null; }
  }
  const url = `https://api.github.com/repos/${repo.owner}/${repo.repo}/pulls?state=all&sort=updated&direction=desc&per_page=${PER_PAGE}`;
  try {
    const res = await fetch(url, { headers: ghHeaders(token), signal: AbortSignal.timeout(12000) });
    if (!res.ok) {
      log.warn(`PR poller: ${app.slug} GET pulls → HTTP ${res.status}`);
      return [];
    }
    return await res.json();
  } catch (e) {
    log.warn(`PR poller: ${app.slug} fetch failed: ${e.message}`);
    return [];
  }
}

function extractRequestIds(body) {
  if (!body) return [];
  const ids = new Set();
  let m;
  CLOSES_RE.lastIndex = 0;
  while ((m = CLOSES_RE.exec(body)) !== null) ids.add(parseInt(m[1], 10));
  return [...ids];
}

async function processApp(app) {
  const db = getDb();
  const prs = await fetchRecentPRs(app);
  for (const pr of prs) {
    const ids = extractRequestIds(pr.body);
    if (!ids.length) continue;
    for (const id of ids) {
      const enh = db.prepare(
        'SELECT id, app_slug, status, validated_at, pr_url FROM enhancement_requests WHERE id = ? AND app_slug = ?'
      ).get(id, app.slug);
      if (!enh) continue;
      const currentBucket = bucketize(enh.status, enh.validated_at);

      const wantPrUrl = pr.html_url;
      if (enh.pr_url !== wantPrUrl) {
        db.prepare('UPDATE enhancement_requests SET pr_url = ?, branch_name = COALESCE(branch_name, ?) WHERE id = ?')
          .run(wantPrUrl, pr.head?.ref || null, id);
      }

      const merged = pr.merged_at != null;
      if (merged) {
        if (currentBucket !== 'shipped' && currentBucket !== 'validated') {
          applyBucket(db, id, 'shipped', null);
          log.info(`PR poller: appcrane#${id} → shipped (PR ${pr.number} on ${app.slug} merged)`);
        }
      } else if (pr.state === 'open') {
        if (currentBucket === 'triage') {
          applyBucket(db, id, 'in_progress', null);
          log.info(`PR poller: appcrane#${id} → in_progress (PR ${pr.number} on ${app.slug} opened)`);
        }
      }
    }
  }
}

async function tick() {
  const db = getDb();
  const apps = db.prepare("SELECT slug, github_url, github_token_encrypted FROM apps WHERE github_url IS NOT NULL AND github_url != ''").all();
  for (const app of apps) {
    try { await processApp(app); }
    catch (e) { log.warn(`PR poller: ${app.slug} processing error: ${e.message}`); }
  }
  _lastPolledAt = new Date().toISOString();
}

export function startGithubPoller() {
  if (_running) return;
  _running = true;
  log.info(`GitHub PR poller starting (interval: ${POLL_MS}ms)`);
  setTimeout(() => tick().catch(e => log.error(`PR poller tick: ${e.message}`)), 30000);
  setInterval(() => {
    tick().catch(e => log.error(`PR poller tick: ${e.message}`));
  }, POLL_MS);
}

export function pollerStatus() {
  return { running: _running, last_polled_at: _lastPolledAt, interval_ms: POLL_MS };
}
