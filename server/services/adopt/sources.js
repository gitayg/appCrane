import { fetchToBuffer, assertFetchable } from '../remoteFetch.js';
import { githubApiBase, githubWebBase } from '../githubApp.js';
import { parseGithubRepo } from '../githubCredential.js';
import { adoptLimits, ArchiveRefused } from './archive.js';

// Where a project comes from. A GitHub repository is downloaded as GitHub's
// own zipball and goes through exactly the same archive checks as an upload.

export class SourceError extends Error {
  constructor(code, message, status = 400, extra = {}) {
    super(message);
    this.code = code;
    this.statusCode = status;
    Object.assign(this, extra);
  }
}

// None of these tools publishes a way to go from a project URL to its code
// without the owner's sign-in, so a pasted tool URL is answered with the
// export step instead of a guess.
export const TOOL_GUIDES = [
  { tool: 'lovable', label: 'Lovable', hosts: /(?:^|\.)lovable\.(?:dev|app)$/, steps: 'In Lovable open the project, choose GitHub > Connect to GitHub and let it create the repository, then paste that repository URL here. Lovable keeps it in two-way sync. Paid plans can also download the code as a zip.' },
  { tool: 'bolt', label: 'Bolt.new', hosts: /(?:^|\.)bolt\.new$/, steps: 'In Bolt use the GitHub integration to push the project to a repository and paste its URL here, or use Download (top right) and upload the zip.' },
  { tool: 'v0', label: 'v0', hosts: /(?:^|\.)v0\.(?:dev|app)$/, steps: 'In v0 connect the project to GitHub (the repository becomes the source of truth) and paste the repository URL here, or download the ZIP from the project menu and upload it.' },
  { tool: 'replit', label: 'Replit', hosts: /(?:^|\.)(?:replit\.com|repl\.co|replit\.app|replit\.dev)$/, steps: 'In Replit open the Git pane, connect a GitHub repository and push, then paste the repository URL here. Or download the project as a zip and upload it.' },
  { tool: 'figma-make', label: 'Figma Make', hosts: /(?:^|\.)figma\.(?:com|site)$/, steps: 'In Figma Make use Push to GitHub (a one-way push that creates the repository) and paste its URL here, or use Download code and upload the zip.' },
];

export function toolGuideFor(rawUrl) {
  let host;
  try { host = new URL(rawUrl).hostname.toLowerCase(); } catch { return null; }
  return TOOL_GUIDES.find((g) => g.hosts.test(host)) || null;
}

const NAME_RE = /^[A-Za-z0-9_.-]{1,100}$/;
const REF_RE = /^[A-Za-z0-9._/-]{1,200}$/;

/** { owner, repo, ref } from a GitHub URL, or a SourceError. */
export function parseRepoUrl(rawUrl, ref) {
  const url = String(rawUrl || '').trim();
  if (!url) throw new SourceError('VALIDATION', 'A repository URL is required.');
  const guide = toolGuideFor(url);
  if (guide) {
    throw new SourceError('TOOL_URL_NOT_RESOLVABLE',
      `${guide.label} project links cannot be imported directly: ${guide.label} only hands its code to the project owner. ${guide.steps}`,
      400, { tool: guide.tool });
  }
  const parsed = parseGithubRepo(url);
  if (!parsed) throw new SourceError('VALIDATION', `Not a GitHub repository URL. Expected ${githubWebBase()}/<owner>/<repo>.`);
  const repo = parsed.repo.replace(/\.git$/, '');
  if (!NAME_RE.test(parsed.owner) || !NAME_RE.test(repo)) throw new SourceError('VALIDATION', 'The repository owner or name has unexpected characters.');
  let wantedRef = ref ? String(ref).trim() : '';
  if (!wantedRef) {
    const m = new URL(url).pathname.match(/\/tree\/(.+?)\/?$/);
    if (m) wantedRef = decodeURIComponent(m[1]);
  }
  if (wantedRef && (!REF_RE.test(wantedRef) || wantedRef.includes('..'))) throw new SourceError('VALIDATION', 'The branch or tag name has unexpected characters.');
  return { owner: parsed.owner, repo, ref: wantedRef || null, label: `${parsed.owner}/${repo}${wantedRef ? `@${wantedRef}` : ''}` };
}

function allowedDownloadHost(location) {
  const api = new URL(githubApiBase());
  const host = new URL(location).hostname;
  if (api.hostname === 'api.github.com') return host === 'codeload.github.com';
  return host === api.hostname;
}

/**
 * Download the repository zipball. GitHub answers the API call with a redirect
 * to a short-lived download URL; that URL is checked (host and address) and
 * fetched without following further redirects.
 */
export async function downloadGithubZip({ owner, repo, ref }, token = null) {
  const path = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/zipball${ref ? `/${ref.split('/').map(encodeURIComponent).join('/')}` : ''}`;
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'AppCrane-adopt', 'X-GitHub-Api-Version': '2022-11-28' };
  if (token) headers.Authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(`${githubApiBase()}${path}`, { headers, redirect: 'manual', signal: AbortSignal.timeout(30000) });
  } catch (e) {
    throw new SourceError('GITHUB_UNREACHABLE', `Could not reach GitHub: ${e.message}`, 502);
  }
  if (res.status === 404 || res.status === 403 || res.status === 401) {
    throw new SourceError('REPO_NOT_FOUND',
      token ? 'GitHub refused the download with that token: check the repository URL and that the token can read the repository.'
        : 'The repository was not found. If it is private, supply a GitHub token that can read it.', 404);
  }
  if (res.status < 300 || res.status >= 400) throw new SourceError('GITHUB_ERROR', `GitHub answered HTTP ${res.status} for the download.`, 502);
  const location = res.headers.get('location');
  if (!location) throw new SourceError('GITHUB_ERROR', 'GitHub gave no download location.', 502);
  if (!allowedDownloadHost(location)) throw new SourceError('GITHUB_ERROR', 'GitHub redirected the download to an unexpected host.', 502);
  await assertFetchable(location);
  const buf = await fetchToBuffer(location);
  const { maxArchiveBytes } = adoptLimits();
  if (buf.length > maxArchiveBytes) {
    throw new ArchiveRefused('ARCHIVE_TOO_LARGE', `The repository archive is ${buf.length} bytes, over the ${maxArchiveBytes} byte limit.`);
  }
  return buf;
}
