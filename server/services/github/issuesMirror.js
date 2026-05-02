import { decrypt } from '../encryption.js';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';

const QA_LOG_LABEL = 'appcrane:qa-log';
const QA_LOG_TITLE = 'AppCrane Q&A Log';
const REQUEST_LABEL = 'appcrane:request';

function parseRepo(githubUrl) {
  const m = githubUrl.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function buildHeaders(token) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'AppCrane-IssuesMirror',
    'Content-Type': 'application/json',
  };
  if (token) headers.Authorization = `token ${token}`;
  return headers;
}

function getToken(app) {
  if (!app?.github_token_encrypted) return null;
  try { return decrypt(app.github_token_encrypted); } catch (_) { return null; }
}

async function ensureLabel({ owner, repo, headers, name, color, description }) {
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/labels/${encodeURIComponent(name)}`, { headers });
  if (res.ok) return;
  if (res.status !== 404) return;
  await fetch(`https://api.github.com/repos/${owner}/${repo}/labels`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name, color, description }),
  }).catch(() => {});
}

/**
 * Mirror an enhancement request as a new GitHub Issue.
 * Stores the issue number on the row so future status updates can find it.
 */
export async function mirrorRequest(app, request) {
  if (!app?.github_url) return null;
  const repo = parseRepo(app.github_url);
  if (!repo) return null;
  const token = getToken(app);
  if (!token) return null;

  const headers = buildHeaders(token);
  await ensureLabel({ ...repo, headers, name: REQUEST_LABEL, color: '8a63d2', description: 'Enhancement request mirrored from AppCrane' });
  await ensureLabel({ ...repo, headers, name: `appcrane:id-${request.id}`, color: 'ededed', description: `AppCrane request #${request.id}` });

  const submitter = request.user_name || 'unknown';
  const body = [
    request.message,
    '',
    '---',
    `Submitted by **${submitter}** via AppCrane portal.`,
    `App: \`${app.slug}\` · Request ID: \`${request.id}\` · Created: ${request.created_at || 'now'}`,
  ].join('\n');

  const title = `[Request #${request.id}] ${request.message.split('\n')[0].slice(0, 80)}`;

  try {
    const res = await fetch(`https://api.github.com/repos/${repo.owner}/${repo.repo}/issues`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ title, body, labels: [REQUEST_LABEL, `appcrane:id-${request.id}`] }),
    });
    const data = await res.json();
    if (!res.ok) {
      log.warn(`issuesMirror: failed to create issue for request #${request.id}: ${data.message || res.status}`);
      return null;
    }
    log.info(`issuesMirror: created issue #${data.number} for request #${request.id} in ${repo.owner}/${repo.repo}`);
    return { issueNumber: data.number, issueUrl: data.html_url };
  } catch (err) {
    log.warn(`issuesMirror: network error mirroring request #${request.id}: ${err.message}`);
    return null;
  }
}

async function findRequestIssue({ owner, repo, headers, requestId }) {
  const label = `appcrane:id-${requestId}`;
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues?state=all&labels=${encodeURIComponent(label)}&per_page=5`,
    { headers }
  );
  if (!res.ok) return null;
  const arr = await res.json();
  return Array.isArray(arr) && arr[0] ? arr[0] : null;
}

/**
 * Close the GitHub issue mirroring a request, adding a resolution comment.
 */
export async function closeRequest(app, request, { resolution, prUrl } = {}) {
  if (!app?.github_url) return;
  const repo = parseRepo(app.github_url);
  if (!repo) return;
  const token = getToken(app);
  if (!token) return;

  const headers = buildHeaders(token);
  try {
    const issue = await findRequestIssue({ ...repo, headers, requestId: request.id });
    if (!issue) return;

    const lines = [];
    if (resolution) lines.push(resolution);
    if (prUrl) lines.push(`Linked PR: ${prUrl}`);
    lines.push(`Status set to **${request.status || 'done'}** in AppCrane.`);

    await fetch(`https://api.github.com/repos/${repo.owner}/${repo.repo}/issues/${issue.number}/comments`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ body: lines.join('\n') }),
    }).catch(() => {});

    await fetch(`https://api.github.com/repos/${repo.owner}/${repo.repo}/issues/${issue.number}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ state: 'closed' }),
    }).catch(() => {});

    log.info(`issuesMirror: closed issue #${issue.number} for request #${request.id}`);
  } catch (err) {
    log.warn(`issuesMirror: failed to close issue for request #${request.id}: ${err.message}`);
  }
}

async function findOrCreateQaLog({ owner, repo, headers }) {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues?state=all&labels=${encodeURIComponent(QA_LOG_LABEL)}&per_page=5`,
    { headers }
  );
  if (res.ok) {
    const arr = await res.json();
    const existing = Array.isArray(arr) ? arr.find(i => i.title === QA_LOG_TITLE) : null;
    if (existing) {
      if (existing.state === 'closed') {
        await fetch(`https://api.github.com/repos/${owner}/${repo}/issues/${existing.number}`, {
          method: 'PATCH', headers, body: JSON.stringify({ state: 'open' }),
        }).catch(() => {});
      }
      return existing.number;
    }
  }

  await ensureLabel({ owner, repo, headers, name: QA_LOG_LABEL, color: '0e8a16', description: 'Persistent AppCrane Ask Q&A log' });

  const body = [
    'This issue is a persistent log of questions asked through the AppCrane "Learn" panel.',
    'Each comment below records one question and the answer Claude produced.',
    '',
    'Managed automatically by AppCrane — do not delete.',
  ].join('\n');

  const create = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues`, {
    method: 'POST', headers,
    body: JSON.stringify({ title: QA_LOG_TITLE, body, labels: [QA_LOG_LABEL] }),
  });
  if (!create.ok) return null;
  const data = await create.json();
  return data.number || null;
}

/**
 * Append a Q&A entry to the persistent AppCrane Q&A log issue.
 * Creates the issue lazily on the first ask.
 */
export async function mirrorAsk(app, { question, answer, userName, sessionId }) {
  if (!app?.github_url) return;
  const repo = parseRepo(app.github_url);
  if (!repo) return;
  const token = getToken(app);
  if (!token) return;

  const headers = buildHeaders(token);
  try {
    const issueNumber = await findOrCreateQaLog({ ...repo, headers });
    if (!issueNumber) return;

    const truncatedAnswer = answer.length > 6000 ? answer.slice(0, 6000) + '\n\n_(truncated)_' : answer;
    const body = [
      `### Q (${userName || 'user'} · session ${sessionId})`,
      question,
      '',
      '### A',
      truncatedAnswer,
    ].join('\n');

    await fetch(`https://api.github.com/repos/${repo.owner}/${repo.repo}/issues/${issueNumber}/comments`, {
      method: 'POST', headers,
      body: JSON.stringify({ body }),
    }).catch(() => {});

    log.info(`issuesMirror: appended Q&A to issue #${issueNumber} (${repo.owner}/${repo.repo})`);
  } catch (err) {
    log.warn(`issuesMirror: failed to mirror ask: ${err.message}`);
  }
}

/** Resolve an app row by slug — small helper for callers without a row in hand. */
export function getAppForMirror(slug) {
  if (!slug) return null;
  return getDb().prepare('SELECT slug, github_url, github_token_encrypted FROM apps WHERE slug = ?').get(slug);
}
