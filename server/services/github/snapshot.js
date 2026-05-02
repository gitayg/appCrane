import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { decrypt } from '../encryption.js';
import log from '../../utils/logger.js';

const COMMITS_LIMIT  = 50;
const PRS_LIMIT      = 30;
const ISSUES_LIMIT   = 30;
const RELEASES_LIMIT = 5;

function parseRepo(githubUrl) {
  const m = githubUrl.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

function buildHeaders(token) {
  const h = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'AppCrane-Snapshot',
  };
  if (token) h.Authorization = `token ${token}`;
  return h;
}

async function fetchJson(url, headers) {
  try {
    const r = await fetch(url, { headers });
    if (!r.ok) return null;
    return await r.json();
  } catch (_) { return null; }
}

function trim(s, max) {
  if (!s) return '';
  s = String(s).trim();
  if (s.length <= max) return s;
  return s.slice(0, max).trim() + '…';
}

function formatCommits(commits) {
  if (!Array.isArray(commits) || !commits.length) return '_(no commits)_';
  return commits.map(c => {
    const sha   = (c.sha || '').slice(0, 7);
    const date  = (c.commit?.author?.date || '').slice(0, 10);
    const who   = c.commit?.author?.name || c.author?.login || 'unknown';
    const first = (c.commit?.message || '').split('\n')[0];
    return `- \`${sha}\` ${date} · ${who} — ${trim(first, 110)}`;
  }).join('\n');
}

function formatPrs(prs) {
  if (!Array.isArray(prs) || !prs.length) return '_(no open pull requests)_';
  return prs.map(p =>
    `- #${p.number} · ${trim(p.title, 90)} — ${p.user?.login || 'unknown'} (${p.html_url})`
  ).join('\n');
}

function formatIssues(issues, label) {
  const filtered = (issues || []).filter(i => !i.pull_request);
  if (!filtered.length) return `_(no open issues with label \`${label}\`)_`;
  return filtered.map(i => {
    const body = trim(i.body || '', 220).replace(/\n+/g, ' ');
    return `### #${i.number} · ${trim(i.title, 100)}\n${body}\n_${i.html_url}_`;
  }).join('\n\n');
}

function formatReleases(releases) {
  if (!Array.isArray(releases) || !releases.length) return '_(no releases)_';
  return releases.map(r => {
    const date = (r.published_at || r.created_at || '').slice(0, 10);
    const body = trim((r.body || '').replace(/\r\n/g, '\n'), 600);
    return `### ${r.tag_name || r.name || 'untagged'} · ${date}\n${body || '_(no release notes)_'}`;
  }).join('\n\n');
}

const POINTER_BODY = `# AppCrane workspace pointer

Read \`.appcrane/github-snapshot.md\` first. It contains:
- Recent commits on the default branch
- Open pull requests
- Open feature requests (issues labeled \`appcrane:request\`)
- Recent releases

This snapshot is generated on the host before this container starts and reflects
the GitHub state at that moment. It is NOT updated during the session — for
anything fresher, use \`git log\` / \`git status\` directly.
`;

function buildMarkdown({ app, repo, commits, prs, issues, releases, generatedAt }) {
  return [
    `# GitHub snapshot — ${repo.owner}/${repo.repo}`,
    '',
    `_App slug: \`${app.slug}\` · Generated: ${generatedAt}_`,
    '',
    'This file was written by AppCrane on the host before the container started.',
    'It is the source of truth for what has happened on this project recently.',
    'Use it instead of asking the user "what did we do last time?".',
    '',
    `## Recent commits (default branch, up to ${COMMITS_LIMIT})`,
    '',
    formatCommits(commits),
    '',
    `## Open pull requests (up to ${PRS_LIMIT})`,
    '',
    formatPrs(prs),
    '',
    `## Open feature requests (label: appcrane:request, up to ${ISSUES_LIMIT})`,
    '',
    formatIssues(issues, 'appcrane:request'),
    '',
    `## Recent releases (up to ${RELEASES_LIMIT})`,
    '',
    formatReleases(releases),
    '',
  ].join('\n');
}

function writeMinimalSnapshot(workspaceDir, reason) {
  try {
    const dir = join(workspaceDir, '.appcrane');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'github-snapshot.md'),
      `# GitHub snapshot unavailable\n\n${reason}\n\nRely on \`git log\` and \`git status\` for project history.\n`,
      { mode: 0o644 });
    writeFileSync(join(dir, 'CLAUDE.md'), POINTER_BODY, { mode: 0o644 });
  } catch (_) {}
}

/**
 * Fetch project state from GitHub and write it to <workspaceDir>/.appcrane/.
 * Runs on the HOST — the GitHub token never enters the container.
 * Fails open: if anything goes wrong, the workspace still gets a stub snapshot.
 */
export async function writeSnapshot(app, workspaceDir, onLog) {
  if (!app?.github_url) {
    writeMinimalSnapshot(workspaceDir, 'This app has no GitHub repository connected.');
    return false;
  }

  const repo = parseRepo(app.github_url);
  if (!repo) {
    writeMinimalSnapshot(workspaceDir, `Could not parse GitHub URL: ${app.github_url}`);
    return false;
  }

  let token = null;
  if (app.github_token_encrypted) {
    try { token = decrypt(app.github_token_encrypted); } catch (_) {}
  }
  const headers = buildHeaders(token);
  const branch  = app.branch || 'main';
  const base = `https://api.github.com/repos/${repo.owner}/${repo.repo}`;

  onLog?.(`[snapshot] Fetching GitHub state for ${repo.owner}/${repo.repo}…`);

  const [commits, prs, issues, releases] = await Promise.all([
    fetchJson(`${base}/commits?sha=${encodeURIComponent(branch)}&per_page=${COMMITS_LIMIT}`, headers),
    fetchJson(`${base}/pulls?state=open&per_page=${PRS_LIMIT}&sort=updated&direction=desc`, headers),
    fetchJson(`${base}/issues?state=open&labels=appcrane:request&per_page=${ISSUES_LIMIT}&sort=updated&direction=desc`, headers),
    fetchJson(`${base}/releases?per_page=${RELEASES_LIMIT}`, headers),
  ]);

  const md = buildMarkdown({
    app, repo,
    commits: commits || [],
    prs:     prs || [],
    issues:  issues || [],
    releases: releases || [],
    generatedAt: new Date().toISOString(),
  });

  try {
    const dir = join(workspaceDir, '.appcrane');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'github-snapshot.md'), md, { mode: 0o644 });
    writeFileSync(join(dir, 'CLAUDE.md'), POINTER_BODY, { mode: 0o644 });
  } catch (err) {
    log.warn(`snapshot: failed to write ${workspaceDir}/.appcrane: ${err.message}`);
    return false;
  }

  const counts = {
    commits:  Array.isArray(commits) ? commits.length : 0,
    prs:      Array.isArray(prs) ? prs.length : 0,
    issues:   Array.isArray(issues) ? (issues || []).filter(i => !i.pull_request).length : 0,
    releases: Array.isArray(releases) ? releases.length : 0,
  };
  onLog?.(`[snapshot] Wrote .appcrane/github-snapshot.md (${counts.commits} commits, ${counts.prs} PRs, ${counts.issues} requests, ${counts.releases} releases)`);
  log.info(`snapshot: ${repo.owner}/${repo.repo} → ${workspaceDir}/.appcrane (${counts.commits}c/${counts.prs}p/${counts.issues}i/${counts.releases}r)`);
  return true;
}
