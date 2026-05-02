import { decrypt } from '../encryption.js';
import log from '../../utils/logger.js';

const RELEASES_LIMIT = 25;

function parseRepo(githubUrl) {
  const m = githubUrl.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

function buildHeaders(token) {
  const h = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'AppCrane-Releases',
  };
  if (token) h.Authorization = `token ${token}`;
  return h;
}

function getToken(app) {
  if (!app?.github_token_encrypted) return null;
  try { return decrypt(app.github_token_encrypted); } catch (_) { return null; }
}

async function fetchJson(url, headers) {
  try {
    const r = await fetch(url, { headers });
    if (!r.ok) return null;
    return await r.json();
  } catch (_) { return null; }
}

async function fetchText(url, headers) {
  try {
    const r = await fetch(url, { headers });
    if (!r.ok) return null;
    return await r.text();
  } catch (_) { return null; }
}

/**
 * Fetch the latest releases plus CHANGELOG.md from the default branch.
 * Returns { repo, releases, changelog, fetchedAt, error }.
 */
export async function fetchReleasesAndChangelog(app) {
  if (!app?.github_url) {
    return { repo: null, releases: [], changelog: null, error: 'No GitHub URL configured for this app.' };
  }
  const repo = parseRepo(app.github_url);
  if (!repo) {
    return { repo: null, releases: [], changelog: null, error: `Could not parse GitHub URL: ${app.github_url}` };
  }
  const token = getToken(app);
  const headers = buildHeaders(token);
  const branch = app.branch || 'main';
  const base = `https://api.github.com/repos/${repo.owner}/${repo.repo}`;

  const [releases, changelog] = await Promise.all([
    fetchJson(`${base}/releases?per_page=${RELEASES_LIMIT}`, headers),
    fetchText(`https://raw.githubusercontent.com/${repo.owner}/${repo.repo}/${encodeURIComponent(branch)}/CHANGELOG.md`, headers),
  ]);

  const cleaned = Array.isArray(releases) ? releases.map(r => ({
    tag: r.tag_name || '',
    name: r.name || r.tag_name || '',
    publishedAt: r.published_at || r.created_at || '',
    author: r.author?.login || '',
    url: r.html_url || '',
    isDraft: !!r.draft,
    isPrerelease: !!r.prerelease,
    body: r.body || '',
  })) : [];

  return {
    repo,
    releases: cleaned,
    changelog: changelog || null,
    fetchedAt: new Date().toISOString(),
    error: null,
  };
}

// ── Tiny safe markdown → HTML renderer ───────────────────────────────────
//
// Escapes ALL input first, then re-introduces only a strict allowlist of
// formatting (headings, bold, italic, inline code, fenced code, lists,
// links to http(s) URLs). The output is wrapped in a sandboxed iframe by
// the route handler, so even a parser bug can't execute scripts.

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderInline(s) {
  // Bold first (greedy match so ** doesn't break * inside it)
  s = s.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  // Italic
  s = s.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, '$1<em>$2</em>');
  // Inline code
  s = s.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  // Links — only http(s) hrefs allowed; text re-escaped already
  s = s.replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, (_m, text, href) => {
    return `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`;
  });
  return s;
}

export function renderMarkdown(text) {
  if (!text) return '';
  const escaped = escapeHtml(text);
  const lines = escaped.split('\n');
  const out = [];
  let inCode = false;
  let inList = false;

  const closeList = () => { if (inList) { out.push('</ul>'); inList = false; } };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (inCode) {
      if (/^```/.test(line)) {
        out.push('</code></pre>');
        inCode = false;
      } else {
        out.push(line);
      }
      continue;
    }

    if (/^```/.test(line)) {
      closeList();
      out.push('<pre><code>');
      inCode = true;
      continue;
    }

    const h = line.match(/^(#{1,6})\s+(.+)$/);
    if (h) {
      closeList();
      const level = h[1].length;
      out.push(`<h${level}>${renderInline(h[2])}</h${level}>`);
      continue;
    }

    const li = line.match(/^[-*]\s+(.+)$/);
    if (li) {
      if (!inList) { out.push('<ul>'); inList = true; }
      out.push(`<li>${renderInline(li[1])}</li>`);
      continue;
    }

    if (line.trim() === '') {
      closeList();
      continue;
    }

    closeList();
    out.push(`<p>${renderInline(line)}</p>`);
  }

  if (inCode) out.push('</code></pre>');
  closeList();
  return out.join('\n');
}

/**
 * Build the full HTML page served at GET /api/coder/:slug/releases/view.
 * The host page iframes this with sandbox="allow-popups". A meta-CSP
 * pins script execution off so any markdown-renderer slip can't escalate.
 */
export function renderReleasesPage({ app, releases, changelog, fetchedAt, error }) {
  const title = `${app.name || app.slug} — Release notes`;

  const meta = [
    `<meta charset="utf-8">`,
    `<meta name="viewport" content="width=device-width,initial-scale=1.0">`,
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; font-src https: data:; connect-src 'none'">`,
    `<title>${escapeHtml(title)}</title>`,
  ].join('\n');

  const css = `
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e4e4e7;padding:24px;line-height:1.6;font-size:14px}
    h1{font-size:1.4rem;margin-bottom:6px;color:#fff}
    h2{font-size:1.1rem;margin:18px 0 8px;color:#e4e4e7;border-bottom:1px solid #2a2d3a;padding-bottom:4px}
    h3{font-size:1rem;margin:14px 0 6px;color:#cbd5e1}
    h4,h5,h6{font-size:.95rem;margin:12px 0 4px;color:#a1a1aa}
    p{margin:8px 0;color:#cbd5e1}
    code{background:#1a1d27;border:1px solid #2a2d3a;border-radius:4px;padding:1px 5px;font-family:Menlo,Consolas,monospace;font-size:.85em;color:#fbbf24}
    pre{background:#0a0c12;border:1px solid #2a2d3a;border-radius:6px;padding:12px;overflow-x:auto;margin:10px 0}
    pre code{background:none;border:none;padding:0;color:#e4e4e7;font-size:.82em}
    ul{padding-left:22px;margin:6px 0}
    li{margin:3px 0;color:#cbd5e1}
    a{color:#60a5fa;text-decoration:none}
    a:hover{text-decoration:underline}
    strong{color:#f4f4f5;font-weight:600}
    em{color:#e4e4e7}
    .meta{font-size:.78rem;color:#71717a;margin-bottom:18px;font-family:monospace}
    .release{border:1px solid #1e2130;border-radius:8px;padding:14px 18px;margin-bottom:14px;background:#13161f}
    .release-hdr{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:6px;padding-bottom:6px;border-bottom:1px solid #2a2d3a}
    .release-tag{font-family:monospace;font-size:.85rem;color:#fbbf24;background:#1a1d27;border:1px solid #2a2d3a;border-radius:4px;padding:2px 8px}
    .release-name{font-size:1.05rem;font-weight:600;color:#fff;flex:1;min-width:0}
    .release-date{font-size:.78rem;color:#71717a;font-family:monospace}
    .release-badge{font-size:.7rem;background:#3b1d1d;color:#fca5a5;border-radius:4px;padding:1px 6px;text-transform:uppercase;letter-spacing:.5px}
    .release-badge.draft{background:#1e293b;color:#94a3b8}
    .release-empty{color:#71717a;font-style:italic;font-size:.85rem;margin:6px 0}
    .section-empty{color:#71717a;font-style:italic;padding:18px;text-align:center;background:#13161f;border:1px dashed #2a2d3a;border-radius:8px}
    .err{background:#3b1d1d;border:1px solid #7f1d1d;color:#fca5a5;padding:12px 16px;border-radius:6px;margin-bottom:16px}
  `;

  const errBanner = error ? `<div class="err">${escapeHtml(error)}</div>` : '';

  let releasesSection;
  if (releases.length === 0) {
    releasesSection = `<div class="section-empty">No releases published on GitHub yet.</div>`;
  } else {
    releasesSection = releases.map(r => {
      const dateStr = r.publishedAt ? new Date(r.publishedAt).toISOString().slice(0, 10) : '';
      const badges = [];
      if (r.isDraft)      badges.push(`<span class="release-badge draft">draft</span>`);
      if (r.isPrerelease) badges.push(`<span class="release-badge">prerelease</span>`);
      const body = r.body ? renderMarkdown(r.body) : `<div class="release-empty">No release notes for this version.</div>`;
      const tag = r.tag ? `<span class="release-tag">${escapeHtml(r.tag)}</span>` : '';
      const name = r.name && r.name !== r.tag ? `<span class="release-name">${escapeHtml(r.name)}</span>` : '<span class="release-name"></span>';
      const dateEl = dateStr ? `<span class="release-date">${escapeHtml(dateStr)}</span>` : '';
      return `<section class="release">
        <header class="release-hdr">${tag}${name}${badges.join('')}${dateEl}</header>
        ${body}
      </section>`;
    }).join('\n');
  }

  const changelogSection = changelog
    ? `<h2>CHANGELOG.md (default branch)</h2>${renderMarkdown(changelog)}`
    : `<h2>CHANGELOG.md (default branch)</h2><div class="section-empty">No CHANGELOG.md found at the repo root.</div>`;

  const fetchedStr = fetchedAt ? new Date(fetchedAt).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '';

  return `<!doctype html><html lang="en"><head>${meta}<style>${css}</style></head><body>
<h1>${escapeHtml(title)}</h1>
<div class="meta">Source: ${escapeHtml(app.github_url || '')} · Fetched: ${escapeHtml(fetchedStr)}</div>
${errBanner}
<h2>Releases (newest first)</h2>
${releasesSection}
${changelogSection}
</body></html>`;
}
