import { useState, useEffect, useRef } from 'react'
import { adminApi } from '../adminApi'
import { PresenceAvatars } from '../components/runtime-topbar/PresenceAvatars'
import { RequestModal } from '../components/runtime-topbar/RequestModal'
import { WhatsNewModal, type WhatsNewChange } from '../components/WhatsNewModal'
import { usePeek, type PeekCtx } from '../hooks/usePeek'
import { BugPanel } from '../components/runtime-topbar/BugPanel'
import { defineCraneAppTopbar } from '../topbar-element/entry'
import { Icon } from '../components/icons'
import '../topbar-element/jsx.d.ts'

defineCraneAppTopbar()

interface App {
  slug: string
  name: string
  description?: string
  category?: string
  visibility?: string
  github_url?: string
  source_type?: string
  has_icon?: boolean
  has_github_token?: boolean
  resource_limits?: { max_ram_mb?: number; max_cpu_percent?: number }
  image_retention?: number
  frame_ancestors?: string | null
  owner?: { id: number; name: string; email: string } | null
  production?: { deploy?: { status?: string; version?: string }; health?: { status: string } }
  sandbox?: { deploy?: { status?: string; version?: string }; health?: { status: string } }
}

interface EnvVar {
  key: string
  value: string
}

interface FrameState {
  open: boolean
  url: string
  title: string
  slug?: string
  appName?: string
  env?: 'production' | 'sandbox'
  prodUrl?: string
  sandUrl?: string
  prodVersion?: string
  sandVersion?: string
  hasIcon?: boolean
  hasGithub?: boolean
}

interface PromptModal {
  open: boolean
  key?: string
  prompt?: string
  title?: string
}

type SortKey = 'name' | 'visibility' | 'category' | 'ram' | 'cpu' | 'images'

export function Applications() {
  const [apps, setApps] = useState<App[]>([])
  const [versions, setVersions] = useState<Record<string, { prod?: string; sand?: string }>>({})
  const [openEvars, setOpenEvars] = useState<Record<string, string | null>>({})
  const [evarData, setEvarData] = useState<Record<string, EnvVar[]>>({})
  const [frame, setFrame] = useState<FrameState>({ open: false, url: '', title: '' })
  const [framePanel, setFramePanel] = useState<'ask' | 'request' | 'bug' | null>(null)
  const [promptModal, setPromptModal] = useState<PromptModal>({ open: false })
  const [checkUpdateText, setCheckUpdateText] = useState<Record<string, string>>({})
  const [iconUrls, setIconUrls] = useState<Record<string, string>>({})

  // Filter / sort state for the table view (v1.27.41).
  const [filter, setFilter] = useState({ vis: '', name: '', tag: '', ramMin: '', cpuMin: '' })
  const [sort, setSort] = useState<{ key: SortKey; dir: 'asc' | 'desc' }>({ key: 'name', dir: 'asc' })

  // Tag editor: when user picks "+ New tag" in the Tag dropdown, switch
  // that row's tag cell into a free-text input. Map slug -> draft string.
  const [tagDraft, setTagDraft] = useState<Record<string, string>>({})

  // Drill-down state — sandbox + production controls live in an
  // expandable row below each app to keep the table compact (v1.27.47).
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  const iconInputRefs = useRef<Record<string, HTMLInputElement | null>>({})

  async function loadAll() {
    const ar = await adminApi.get<{ apps: App[] }>('/api/apps').catch(() => ({ apps: [] as App[] }))
    // Sort apps alphabetically by name (case-insensitive). The /api/apps
    // endpoint returns insertion order which makes the list hard to scan
    // once you have more than a handful.
    const a = (ar.apps ?? []).slice().sort((x, y) =>
      (x.name || '').toLowerCase().localeCompare((y.name || '').toLowerCase()),
    )
    setApps(a)
    fetchVersions(a)
    // Prefer the freshly-fetched icon state over what's in `prev` so a
    // newly-uploaded icon (or a deleted one) takes effect immediately.
    // The previous {...iconMap, ...prev} ordering let stale state win.
    // Cache-bust by appending the load timestamp; the icon endpoint
    // ignores query strings.
    const iconMap: Record<string, string> = {}
    const stamp = Date.now()
    for (const app of a) {
      if (app.has_icon) iconMap[app.slug] = `/api/apps/${app.slug}/icon?v=${stamp}`
    }
    setIconUrls(iconMap)
  }

  function fetchVersions(appList: App[]) {
    appList.forEach(app => {
      ['production', 'sandbox'].forEach(env => {
        adminApi
          .get<{ version?: string }>(`/api/apps/${app.slug}/live-version/${env}`)
          .then(r => {
            setVersions(prev => ({
              ...prev,
              [app.slug]: {
                ...prev[app.slug],
                [env === 'production' ? 'prod' : 'sand']: r?.version ?? '—',
              },
            }))
          })
          .catch(() => {})
      })
    })
  }

  useEffect(() => {
    loadAll()
  }, [])

  // MCP recently-active per app (last 5 min). Polls every 30s.
  const [mcpActive, setMcpActive] = useState<Record<string, { last_at: string; calls: number }>>({})
  useEffect(() => {
    let cancelled = false
    function refresh() {
      adminApi.get<{ active: { slug: string; last_at: string; calls: number }[] }>('/api/mcp/recent-activity?minutes=5')
        .then(r => {
          if (cancelled) return
          const m: Record<string, { last_at: string; calls: number }> = {}
          for (const row of r.active ?? []) m[row.slug] = { last_at: row.last_at, calls: row.calls }
          setMcpActive(m)
        })
        .catch(() => {})
    }
    refresh()
    const iv = setInterval(refresh, 30000)
    return () => { cancelled = true; clearInterval(iv) }
  }, [])

  async function setVisibility(slug: string, vis: string) {
    await adminApi.put(`/api/apps/${slug}`, { visibility: vis }).catch(() => {})
    setApps(prev => prev.map(a => a.slug === slug ? { ...a, visibility: vis } : a))
  }

  async function deleteApp(slug: string, name: string) {
    if (!confirm(`Delete "${name}"?`)) return
    if (!confirm(`This is irreversible. Really delete "${name}"?`)) return
    await adminApi.del(`/api/apps/${slug}?confirm=true`).catch(() => {})
    loadAll()
  }

  async function restartApp(slug: string, env: string) {
    await adminApi.post(`/api/apps/${slug}/restart/${env}`).catch(() => {})
  }

  async function checkUpdates(slug: string) {
    type UpdatesRes = {
      latest_sha?: string
      latest_message?: string
      production?: { deployed_sha?: string | null; update_available?: boolean }
      sandbox?: { deployed_sha?: string | null; update_available?: boolean }
      error?: { message?: string }
    }
    const r = await adminApi.get<UpdatesRes>(`/api/apps/${slug}/updates`).catch(() => null)
    let text: string
    if (!r) text = 'Error'
    else if (r.error) text = r.error.message || 'Error'
    else if (r.production?.update_available || r.sandbox?.update_available) {
      const envs = [
        r.production?.update_available ? 'prod' : null,
        r.sandbox?.update_available ? 'sand' : null,
      ].filter(Boolean).join(' + ')
      text = `↑ ${envs} → ${r.latest_sha ?? 'new'}`
    } else {
      text = '✓ up to date'
    }
    setCheckUpdateText(prev => ({ ...prev, [slug]: text }))
    setTimeout(() => setCheckUpdateText(prev => ({ ...prev, [slug]: '' })), 5000)
  }

  async function registerGithubHook(slug: string) {
    const r = await adminApi.post<{ message?: string; error?: string }>(`/api/apps/${slug}/webhook/register-github`).catch(() => null)
    alert(r?.message ?? r?.error ?? 'Done')
  }

  async function saveRam(slug: string, raw: string) {
    const ram = raw.trim() ? Number(raw) : null
    if (raw.trim() && (isNaN(ram!) || ram! < 0)) return
    await adminApi.put(`/api/apps/${slug}`, { max_ram_mb: ram }).catch(() => {})
    setApps(prev => prev.map(a => a.slug === slug
      ? { ...a, resource_limits: { ...(a.resource_limits ?? {}), max_ram_mb: ram ?? undefined } }
      : a))
  }

  async function saveCpu(slug: string, raw: string) {
    const cpu = raw.trim() ? Number(raw) : null
    if (raw.trim() && (isNaN(cpu!) || cpu! < 0)) return
    await adminApi.put(`/api/apps/${slug}`, { max_cpu_percent: cpu }).catch(() => {})
    setApps(prev => prev.map(a => a.slug === slug
      ? { ...a, resource_limits: { ...(a.resource_limits ?? {}), max_cpu_percent: cpu ?? undefined } }
      : a))
  }

  async function saveImages(slug: string, raw: string) {
    if (!raw.trim()) return
    const n = parseInt(raw, 10)
    if (isNaN(n) || n < 0 || n > 50) return
    await adminApi.put(`/api/apps/${slug}`, { image_retention: n }).catch(() => {})
    setApps(prev => prev.map(a => a.slug === slug ? { ...a, image_retention: n } : a))
  }

  async function saveCategory(slug: string, cat: string) {
    const value = cat.trim()
    await adminApi.put(`/api/apps/${slug}`, { category: value }).catch(() => {})
    setApps(prev => prev.map(a => a.slug === slug ? { ...a, category: value || undefined } : a))
  }

  async function saveName(slug: string, name: string) {
    const value = name.trim()
    if (!value) return
    await adminApi.put(`/api/apps/${slug}`, { name: value }).catch(() => {})
    setApps(prev => prev.map(a => a.slug === slug ? { ...a, name: value } : a))
  }

  async function saveDescription(slug: string, desc: string) {
    await adminApi.put(`/api/apps/${slug}`, { description: desc }).catch(() => {})
    setApps(prev => prev.map(a => a.slug === slug ? { ...a, description: desc } : a))
  }

  async function setFrameAncestors(app: App) {
    const help = "Allowed embedders (CSP frame-ancestors syntax).\n\n" +
      "Examples:\n" +
      "  'self'                              (default — only same origin)\n" +
      "  'self' https://my.opswat.com        (also allow MyOPSWAT)\n" +
      "  'self' https://*.opswat.com         (any opswat.com subdomain)\n\n" +
      "Leave blank to reset to default.";
    const val = prompt(help, app.frame_ancestors ?? '')
    if (val === null) return
    try {
      const r = await adminApi.put<{ app?: App; error?: { message?: string } }>(`/api/apps/${app.slug}`, { frame_ancestors: val.trim() || null })
      if (r?.error) { alert('Failed: ' + (r.error.message || 'unknown')); return }
      const newVal = val.trim() || null
      setApps(prev => prev.map(a => a.slug === app.slug ? { ...a, frame_ancestors: newVal ?? undefined } : a))
    } catch (e) {
      alert('Failed: ' + (e as Error).message)
    }
  }

  async function showAppToken(slug: string) {
    const r = await adminApi.post<{ key?: string; deployment_key?: string }>(`/api/apps/${slug}/deployment-key`).catch(() => null)
    const key = r?.key ?? r?.deployment_key ?? ''
    setPromptModal({
      open: true,
      key,
      prompt: `Use this deployment key to authenticate API calls for app "${slug}".\n\nSet the header:\n  X-Deployment-Key: ${key}\n\nKeep it secret — it grants deploy access to this app.`,
    })
  }

  async function generateAgentKey() {
    const ts = Date.now()
    const name = `onboarding-${ts}`
    const email = `onboarding-${ts}@appcrane`
    const r = await adminApi.post<{ key?: string; api_key?: string; user?: { id: number } }>('/api/users', {
      name,
      email,
      role: 'admin',
      kind: 'agent',
    }).catch(() => null)
    const key = r?.key ?? r?.api_key ?? ''
    const origin = typeof window !== 'undefined' ? window.location.origin : 'https://your-appcrane-host'
    const host = typeof window !== 'undefined' ? window.location.host : 'your-appcrane-host'
    const brief = `You are AppCrane's app-onboarding agent. Your job: take this conversation
from "user wants something deployed" to "a working sandbox URL on
${host}", end-to-end, in one session.

YOU HAVE TWO TOOL FAMILIES on the same MCP connection:
  - appcrane_*  — AppCrane lifecycle ops (create_app, deploy, get_logs, env, …)
  - github_*    — GitHub passthrough (read/write files, open PRs, list
                  branches, create repos). The user's PAT was wired into
                  your MCP config via the X-Github-Token header, so github_*
                  calls authenticate automatically — you do NOT pass a token
                  argument to them.

Use github_* for ALL code-level GitHub work. Do NOT shell out to \`gh\` or
\`git\` CLI. Do NOT clone to local disk. Everything happens through MCP tools.

INPUTS YOU NEED FROM THE USER (ask in your first turn, all at once):
  1. Starting point — one of:
       (a) An idea, no code yet              → scaffold from scratch
       (b) Local code, no GitHub repo        → create repo, push existing code
       (c) Existing GitHub repo URL          → skip scaffolding, just register
  2. The PAT they configured in their \`claude mcp add\` command. You need it
     once to pass as \`github_token\` to appcrane_create_app (AppCrane stores
     it encrypted on the app record so it can clone for future deploys).
     You're not asking for a new PAT — just the same value they already used.
     Don't echo it back.
  3. Any env vars / secrets (usually none).
  4. Display name (you'll propose; user confirms).

KEY APPCRANE TOOLS:
  appcrane_create_app(name, slug, github_url, github_token, branch?, …)
  appcrane_set_env(slug, env, key, value)
  appcrane_deploy(slug, env)                       — env="sandbox"
  appcrane_get_logs(slug, env, lines?, search?)

KEY GITHUB TOOLS (call tools/list to see exact names on your connection —
they may be prefixed \`github_\` or \`mcp__github__\` depending on server
version):
  create_repository                                — paths (a), (b)
  create_or_update_file / push_files               — scaffold or edit
  get_file_contents                                — read existing repo
  create_pull_request                              — for path (c) fixes
  list_branches, list_commits, …

ORDER, BY PATH:

  Path (a) — fresh idea:
    1. Pick slug (lowercase-hyphen, ≤20 chars). Pick stack (default: Vite +
       React + TS SPA; Express + Vite SPA single Node process if backend is
       needed). Propose; wait for ✅.
    2. github_create_repository (private: true).
    3. Push scaffolded files via github_push_files: package.json,
       deployhub.json (version 0.1.0, build, start, be.health "/api/health",
       port hint), source files, AND an /api/health route that returns
       JSON: {status: "ok", version: "<value from package.json>"}.
       AppCrane's deploy validator REJECTS apps whose health endpoint
       does not return both \`status\` and \`version\` fields — this is
       enforced server-side; skipping it means the deploy fails.
    4. appcrane_create_app({ name, slug, github_url, github_token, branch: "main" })
    5. appcrane_set_env (only if user has secrets)
    6. appcrane_deploy(slug, "sandbox")
    7. appcrane_get_logs — confirm health green. If red, read logs, fix via
       github_create_or_update_file, redeploy.

  Path (b) — local code, no repo:
    As (a), but step 3 = read user's local code, audit for missing pieces
    (deployhub.json, /api/health endpoint returning {status, version},
    start script), add via github_push_files. Don't modify files the
    user wrote without asking.

  Path (c) — repo already on GitHub:
    1. github_get_file_contents to verify deployhub.json exists AND the
       app exposes /api/health returning {status, version}. If missing,
       github_create_pull_request adding them; ask user to merge.
       Without a valid health endpoint the deploy will be rejected.
    2. appcrane_create_app
    3-5 as above (set_env, deploy, get_logs).

CONSTRAINTS — common pitfalls that fail deploys:
  - Sandbox only. Never deploy to production.
  - Vite: \`base: process.env.APP_BASE_PATH || './'\`. Never '/'. AppCrane does
    NOT inject APP_BASE_PATH at build time.
  - If you write a custom Dockerfile:
      • EXPOSE must match the port in deployhub.json (default 3000).
      • Do NOT declare VOLUME /data — AppCrane mounts it at runtime.
      • Do NOT set ENV DATA_DIR — AppCrane injects it.
      • Must end with USER <non-root>.
  - App must read PORT from process.env (\`process.env.PORT || 3000\`).
  - On failure, surface the error and ask before retrying. No silent loops.
  - End with the sandbox URL + one line of "what's deployed".`
    const prompt = `Onboard a new application end-to-end via an AppCrane onboarding agent.

=== STEP 1 — Generate a GitHub PAT ===

At https://github.com/settings/tokens. Classic: scope \`repo\`. Or
fine-grained: Contents R/W, Metadata R, Administration W (for the orgs/repos
you want to onboard apps for). The PAT lives only in your local
~/.claude.json — never stored on the AppCrane server, only passed through as
a header at request time.

=== STEP 2 — Wire AppCrane MCP into your local Claude Code ===

Replace <YOUR_GITHUB_PAT> with the PAT from Step 1, then run once in any
terminal (the X-API-Key value is already inlined):

  claude mcp add --transport http appcrane ${origin}/api/mcp \\
    --header "X-API-Key: ${key}" \\
    --header "X-Github-Token: <YOUR_GITHUB_PAT>"

The X-Github-Token header is what enables AppCrane's GitHub passthrough — the
agent gets \`github_*\` tools (read files, push files, open PRs, create repos)
on the same MCP connection. No separate GitHub MCP server install needed.

=== STEP 3 — Open a fresh Claude Code session and paste the brief below ===

In any terminal: \`claude\`. Paste everything between BEGIN and END as your
first message:

>>>>> BEGIN BRIEF >>>>>

${brief}

<<<<< END BRIEF <<<<<`
    setPromptModal({
      open: true,
      title: 'New Application Onboarding',
      key,
      prompt,
    })
  }

  function toggleEvars(slug: string, env: string) {
    const ekey = `${slug}:${env}`
    if (openEvars[slug] === env) {
      setOpenEvars(prev => ({ ...prev, [slug]: null }))
      return
    }
    setOpenEvars(prev => ({ ...prev, [slug]: env }))
    adminApi
      .get<Record<string, string> | EnvVar[]>(`/api/apps/${slug}/env/${env}?reveal=true`)
      .then(r => {
        let vars: EnvVar[]
        if (Array.isArray(r)) {
          vars = r
        } else {
          vars = Object.entries(r as Record<string, string>).map(([key, value]) => ({ key, value }))
        }
        setEvarData(prev => ({ ...prev, [ekey]: vars }))
      })
      .catch(() => {})
  }

  function updateEnvVar(slug: string, env: string, idx: number, field: 'key' | 'value', val: string) {
    const ekey = `${slug}:${env}`
    setEvarData(prev => {
      const arr = [...(prev[ekey] ?? [])]
      arr[idx] = { ...arr[idx], [field]: val }
      return { ...prev, [ekey]: arr }
    })
  }

  async function saveEnvVar(slug: string, env: string, idx: number) {
    const ekey = `${slug}:${env}`
    const row = evarData[ekey]?.[idx]
    if (!row) return
    await adminApi.put(`/api/apps/${slug}/env/${env}`, { [row.key]: row.value }).catch(() => {})
  }

  async function deleteEnvVar(slug: string, env: string, idx: number) {
    const ekey = `${slug}:${env}`
    const row = evarData[ekey]?.[idx]
    if (!row) return
    await adminApi.del(`/api/apps/${slug}/env/${env}/${row.key}`).catch(() => {})
    setEvarData(prev => {
      const arr = [...(prev[ekey] ?? [])]
      arr.splice(idx, 1)
      return { ...prev, [ekey]: arr }
    })
  }

  async function addEnvVar(slug: string, env: string) {
    const ekey = `${slug}:${env}`
    setEvarData(prev => ({
      ...prev,
      [ekey]: [...(prev[ekey] ?? []), { key: '', value: '' }],
    }))
  }

  function openAppFrame(app: App, env: 'production' | 'sandbox') {
    const prodUrl = `/${app.slug}`
    const sandUrl = `/${app.slug}-sandbox`
    setFrame({
      open:        true,
      url:         env === 'production' ? prodUrl : sandUrl,
      title:       `${app.name} (${env === 'production' ? 'prod' : 'sandbox'})`,
      slug:        app.slug,
      appName:     app.name,
      env,
      prodUrl,
      sandUrl,
      prodVersion: app.production?.deploy?.version || '',
      sandVersion: app.sandbox?.deploy?.version    || '',
      hasIcon:     iconUrls[app.slug] != null,
      hasGithub:   !!app.github_url,
    })
  }

  async function uploadIcon(slug: string, file: File) {
    const fd = new FormData()
    fd.append('icon', file)
    await fetch(`/api/apps/${slug}/icon`, {
      method: 'POST',
      headers: adminApi.authHeaders(),
      body: fd,
    })
    setIconUrls(prev => ({ ...prev, [slug]: URL.createObjectURL(file) }))
  }

  /**
   * Health-state badge class + tooltip. Distinguishes three cases that
   * pre-v2.2.11 all looked the same (gray dot, "—" version):
   *
   *   never deployed       → gray dot, "Not deployed yet"
   *   deployed, no health  → yellow dot, "Health endpoint not responding —
   *                           the app is running but /api/health didn't
   *                           return JSON with {status, version}. Check
   *                           deploy logs."
   *   deployed, healthy    → green dot
   *   deployed, down       → red dot
   */
  function healthState(app: App, env: 'production' | 'sandbox') {
    const h = app[env]?.health?.status
    const ver = versions[app.slug]?.[env === 'production' ? 'prod' : 'sand']
    if (h === 'healthy') return { className: 'dot dot-green', title: 'Healthy' }
    if (h === 'down')    return { className: 'dot dot-red',   title: 'Down — last health check failed' }
    if (!ver) return { className: 'dot dot-gray', title: 'Not deployed yet' }
    return {
      className: 'dot dot-yellow',
      title: 'Health endpoint not responding — app is running but /api/health did not return JSON with {status, version}. Check deploy logs.',
    }
  }

  function visBadgeClass(vis?: string) {
    if (vis === 'public') return 'vis-badge vis-public'
    if (vis === 'private') return 'vis-badge vis-private'
    return 'vis-badge vis-hidden'
  }

  // Distinct, sorted list of every category currently in use — feeds the
  // Tag dropdowns in the table (filter row + per-row editor).
  const allTags = Array.from(
    new Set(apps.map(a => (a.category || '').trim()).filter(Boolean)),
  ).sort((a, b) => a.localeCompare(b))

  const visOf = (a: App) => a.visibility || 'hidden'
  const ramOf = (a: App) => a.resource_limits?.max_ram_mb ?? -1
  const cpuOf = (a: App) => a.resource_limits?.max_cpu_percent ?? -1
  const imgOf = (a: App) => a.image_retention ?? -1

  function toggleSort(key: SortKey) {
    setSort(s => s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' })
  }
  function sortArrow(key: SortKey) {
    if (sort.key !== key) return ''
    return sort.dir === 'asc' ? ' ↑' : ' ↓'
  }

  const filtered = apps.filter(a => {
    if (filter.vis  && visOf(a) !== filter.vis) return false
    if (filter.tag  && (a.category || '') !== filter.tag) return false
    if (filter.name && !(a.name || '').toLowerCase().includes(filter.name.toLowerCase())) return false
    if (filter.ramMin && ramOf(a) < Number(filter.ramMin)) return false
    if (filter.cpuMin && cpuOf(a) < Number(filter.cpuMin)) return false
    return true
  })
  const sorted = [...filtered].sort((x, y) => {
    let cmp = 0
    switch (sort.key) {
      case 'name':       cmp = (x.name || '').toLowerCase().localeCompare((y.name || '').toLowerCase()); break
      case 'visibility': cmp = visOf(x).localeCompare(visOf(y)); break
      case 'category':   cmp = (x.category || '').localeCompare(y.category || ''); break
      case 'ram':        cmp = ramOf(x) - ramOf(y); break
      case 'cpu':        cmp = cpuOf(x) - cpuOf(y); break
      case 'images':     cmp = imgOf(x) - imgOf(y); break
    }
    return sort.dir === 'asc' ? cmp : -cmp
  })

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>Applications</h2>
        <button className="btn btn-accent" onClick={generateAgentKey}>New Application Onboarding</button>
        <input
          type="text"
          autoFocus
          autoComplete="off"
          placeholder="Search applications by name…"
          value={filter.name}
          onChange={e => setFilter(f => ({ ...f, name: e.target.value }))}
          style={{
            marginLeft: 'auto',
            minWidth: 280,
            padding: '8px 12px',
            border: '1px solid var(--border)',
            borderRadius: 7,
            background: 'var(--surface2)',
            color: 'var(--text)',
            fontSize: '.9rem',
            outline: 'none',
          }}
        />
      </div>

      <div className="apps-table-wrap">
        <table className="apps-table">
          <thead>
            <tr>
              <th></th>
              <th></th>
              <th className="th-sort" onClick={() => toggleSort('name')}>Name{sortArrow('name')}</th>
              <th>Description</th>
              <th className="th-sort" onClick={() => toggleSort('visibility')}>Visibility{sortArrow('visibility')}</th>
              <th className="th-sort" onClick={() => toggleSort('category')}>Tag{sortArrow('category')}</th>
              <th className="th-sort" onClick={() => toggleSort('ram')}>RAM (MB){sortArrow('ram')}</th>
              <th className="th-sort" onClick={() => toggleSort('cpu')}>CPU (%){sortArrow('cpu')}</th>
              <th className="th-sort" onClick={() => toggleSort('images')}>Images{sortArrow('images')}</th>
              <th>Sandbox</th>
              <th>Production</th>
            </tr>
            <tr className="apps-filter-row">
              <th></th>
              <th></th>
              <th>
                <input
                  className="apps-filter-input"
                  type="text" placeholder="filter name…"
                  value={filter.name} onChange={e => setFilter(f => ({ ...f, name: e.target.value }))}
                />
              </th>
              <th></th>
              <th>
                <select
                  className="apps-filter-input"
                  value={filter.vis} onChange={e => setFilter(f => ({ ...f, vis: e.target.value }))}
                >
                  <option value="">all</option>
                  <option value="hidden">hidden</option>
                  <option value="private">private</option>
                  <option value="public">public</option>
                </select>
              </th>
              <th>
                <select
                  className="apps-filter-input"
                  value={filter.tag} onChange={e => setFilter(f => ({ ...f, tag: e.target.value }))}
                >
                  <option value="">all</option>
                  {allTags.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </th>
              <th>
                <input
                  className="apps-filter-input"
                  type="number" min={0} placeholder="≥"
                  value={filter.ramMin} onChange={e => setFilter(f => ({ ...f, ramMin: e.target.value }))}
                />
              </th>
              <th>
                <input
                  className="apps-filter-input"
                  type="number" min={0} placeholder="≥"
                  value={filter.cpuMin} onChange={e => setFilter(f => ({ ...f, cpuMin: e.target.value }))}
                />
              </th>
              <th></th>
              <th></th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(app => {
              const activeEnv = openEvars[app.slug]
              const ramVal = app.resource_limits?.max_ram_mb ?? ''
              const cpuVal = app.resource_limits?.max_cpu_percent ?? ''
              const imgVal = app.image_retention ?? ''
              const tagDraftVal = tagDraft[app.slug]
              const isExpanded = !!expanded[app.slug]
              return (
                <>
                  <tr key={app.slug}>
                    <td style={{ width: 22 }}>
                      <button
                        type="button"
                        className="apps-row-toggle"
                        onClick={() => setExpanded(p => ({ ...p, [app.slug]: !p[app.slug] }))}
                        title={isExpanded ? 'Hide environments' : 'Show sandbox / production'}
                      >{isExpanded ? '▾' : '▸'}</button>
                    </td>
                    <td>
                      <div
                        className="app-icon-wrap"
                        onClick={() => iconInputRefs.current[app.slug]?.click()}
                        title="Click to upload icon"
                        style={{ width: 28, height: 28 }}
                      >
                        {iconUrls[app.slug]
                          ? <img src={iconUrls[app.slug]} className="app-icon-img" alt="" />
                          : <span className="app-icon-ph">{app.name.charAt(0).toUpperCase()}</span>
                        }
                        <input
                          type="file" accept="image/*"
                          style={{ display: 'none' }}
                          ref={el => { iconInputRefs.current[app.slug] = el }}
                          onChange={e => {
                            const f = e.target.files?.[0]
                            if (f) uploadIcon(app.slug, f)
                          }}
                        />
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <input
                          className="editable" defaultValue={app.name}
                          onBlur={e => { if (e.target.value !== app.name) saveName(app.slug, e.target.value) }}
                          style={{ minWidth: 130, flex: 1 }}
                        />
                        {mcpActive[app.slug] && (
                          <span
                            title={`MCP active — ${mcpActive[app.slug].calls} call(s) in last 5min, latest ${new Date(mcpActive[app.slug].last_at).toLocaleTimeString()}`}
                            style={{
                              fontSize: '.65rem', fontWeight: 600, letterSpacing: '.3px',
                              padding: '2px 6px', borderRadius: 3,
                              color: 'var(--accent)', background: 'rgba(59,130,246,.12)',
                              border: '1px solid rgba(59,130,246,.3)',
                              whiteSpace: 'nowrap',
                            }}
                          >MCP ●</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <input
                        className="editable" defaultValue={app.description ?? ''}
                        placeholder="—"
                        onBlur={e => { if (e.target.value !== (app.description ?? '')) saveDescription(app.slug, e.target.value) }}
                        style={{ minWidth: 180 }}
                      />
                    </td>
                    <td>
                      <select
                        value={app.visibility ?? 'hidden'}
                        onChange={e => setVisibility(app.slug, e.target.value)}
                        className={visBadgeClass(app.visibility)}
                        style={{ fontSize: '.75rem' }}
                      >
                        <option value="hidden">hidden</option>
                        <option value="private">private</option>
                        <option value="public">public</option>
                      </select>
                    </td>
                    <td>
                      {tagDraftVal !== undefined ? (
                        <input
                          className="editable" autoFocus defaultValue={tagDraftVal}
                          placeholder="new tag…"
                          onBlur={e => {
                            saveCategory(app.slug, e.target.value)
                            setTagDraft(d => { const n = { ...d }; delete n[app.slug]; return n })
                          }}
                          onKeyDown={e => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }}
                          style={{ minWidth: 100 }}
                        />
                      ) : (
                        <select
                          value={app.category ?? ''}
                          onChange={e => {
                            const v = e.target.value
                            if (v === '__new__') setTagDraft(d => ({ ...d, [app.slug]: '' }))
                            else saveCategory(app.slug, v)
                          }}
                          style={{ fontSize: '.78rem' }}
                        >
                          <option value="">—</option>
                          {allTags.map(t => <option key={t} value={t}>{t}</option>)}
                          <option value="__new__">+ New tag…</option>
                        </select>
                      )}
                    </td>
                    <td>
                      <input
                        className="editable" type="number" min={0} defaultValue={ramVal}
                        onBlur={e => { if (String(e.target.value) !== String(ramVal)) saveRam(app.slug, e.target.value) }}
                        style={{ width: 70 }}
                      />
                    </td>
                    <td>
                      <input
                        className="editable" type="number" min={0} defaultValue={cpuVal}
                        onBlur={e => { if (String(e.target.value) !== String(cpuVal)) saveCpu(app.slug, e.target.value) }}
                        style={{ width: 60 }}
                      />
                    </td>
                    <td>
                      <input
                        className="editable" type="number" min={0} max={50} defaultValue={imgVal}
                        onBlur={e => { if (String(e.target.value) !== String(imgVal)) saveImages(app.slug, e.target.value) }}
                        style={{ width: 60 }}
                      />
                    </td>
                    {(['sandbox', 'production'] as const).map(env => {
                      const ver = versions[app.slug]?.[env === 'production' ? 'prod' : 'sand']
                      const isDown = app[env]?.health?.status === 'down'
                      return (
                        <td key={env}>
                          <span className="apps-status-env" title={env === 'production' ? 'Production' : 'Sandbox'}>
                            {(() => { const s = healthState(app, env); return <span className={s.className} title={s.title} /> })()}
                            <span className="apps-status-ver">{ver ?? '—'}</span>
                            {isDown ? (
                              <span className="env-link env-link-disabled" title={`${env} is down — open disabled`} aria-disabled="true">↗</span>
                            ) : (
                              <a
                                className="env-link"
                                href="#"
                                onClick={e => { e.preventDefault(); openAppFrame(app, env) }}
                                title={`Open ${env}`}
                              >↗</a>
                            )}
                          </span>
                        </td>
                      )
                    })}
                  </tr>
                  <tr key={`${app.slug}-actions`} className="apps-row-actions">
                    <td colSpan={11} style={{ borderTop: 'none', paddingTop: 0, paddingBottom: 8 }}>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', paddingLeft: 8, alignItems: 'center' }}>
                        {app.owner ? (
                          <span
                            className="badge"
                            title={`Owner: ${app.owner.name}${app.owner.email ? ` (${app.owner.email})` : ''}`}
                            style={{ background: 'var(--surface2)', color: 'var(--dim)', fontSize: '.7rem', fontWeight: 500 }}
                          >
                            👤 {app.owner.name}
                          </span>
                        ) : (
                          <span
                            className="badge"
                            title="No owner assigned. Set one from /users by promoting an assigned user to owner."
                            style={{ background: 'rgba(245,158,11,.15)', color: 'var(--yellow, #f59e0b)', fontSize: '.7rem', fontWeight: 600 }}
                          >
                            ⚠ No owner
                          </span>
                        )}
                        <a className="btn btn-xs" href={`/app?slug=${app.slug}`}>manage</a>
                        <button className="btn btn-xs" onClick={() => showAppToken(app.slug)}>onboard</button>
                        <button
                          className="btn btn-xs"
                          onClick={() => setFrameAncestors(app)}
                          title={app.frame_ancestors ? `Embedders: ${app.frame_ancestors}` : 'Allowed embedders (default: same origin only)'}
                        >🖼{app.frame_ancestors ? ' ✓' : ''}</button>
                        {(app.source_type === 'github' || app.github_url) && (
                          <>
                            {app.github_url && (
                              <a className="btn btn-xs" href={app.github_url} target="_blank" rel="noreferrer" title={app.github_url}>gh ↗</a>
                            )}
                            <button
                              className="btn btn-xs"
                              onClick={() => checkUpdates(app.slug)}
                              title="Check GitHub for new commits since last deploy"
                            >{checkUpdateText[app.slug] || '↑'}</button>
                            <button
                              className="btn btn-xs"
                              onClick={() => registerGithubHook(app.slug)}
                              title="Register GitHub webhook for auto-deploy"
                            >hook</button>
                          </>
                        )}
                        <button className="btn btn-xs btn-red" onClick={() => deleteApp(app.slug, app.name)}>✕</button>
                      </div>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr key={`${app.slug}-envs`} className="apps-row-drill">
                      <td colSpan={11}>
                        <div className="apps-drill-envs">
                          {(['sandbox', 'production'] as const).map(env => {
                            const ver = versions[app.slug]?.[env === 'production' ? 'prod' : 'sand']
                            const isProd = env === 'production'
                            const isDown = app[env]?.health?.status === 'down'
                            return (
                              <div key={env} className={`apps-drill-env apps-drill-env-${env}`}>
                                <div className="apps-drill-env-hdr">
                                  {isProd ? 'Production' : 'Sandbox'}
                                </div>
                                <div className="apps-drill-env-body">
                                  {(() => { const s = healthState(app, env); return <span className={s.className} title={s.title} /> })()}
                                  <span style={{ fontFamily: 'monospace', fontSize: '.74rem', color: 'var(--dim)' }}>{ver ?? '—'}</span>
                                  {isDown ? (
                                    <span className="env-link env-link-disabled" title={`${env} is down — open disabled`} aria-disabled="true">↗ open</span>
                                  ) : (
                                    <a className="env-link" href="#" onClick={e => { e.preventDefault(); openAppFrame(app, env) }}>↗ open</a>
                                  )}
                                  <button className="btn btn-xs" onClick={() => toggleEvars(app.slug, env)}>env vars</button>
                                  <button className="btn btn-xs" onClick={() => restartApp(app.slug, env)}>↺ restart</button>
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      </td>
                    </tr>
                  )}
                  {isExpanded && activeEnv && (
                    <tr key={`${app.slug}-evars`}>
                      <td colSpan={11} className="evars-panel">
                        <div style={{ fontWeight: 600, fontSize: '.78rem', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.5px', color: 'var(--dim)' }}>
                          {activeEnv === 'production' ? 'Production' : 'Sandbox'} Env Vars · {app.name}
                        </div>
                        {(evarData[`${app.slug}:${activeEnv}`] ?? []).map((row, idx) => (
                          <div key={idx} style={{ display: 'flex', gap: 6, marginBottom: 6, alignItems: 'center' }}>
                            <input
                              style={{ flex: 1, padding: '4px 8px', fontSize: '.8rem' }}
                              value={row.key}
                              onChange={e => updateEnvVar(app.slug, activeEnv, idx, 'key', e.target.value)}
                              onBlur={() => saveEnvVar(app.slug, activeEnv, idx)}
                              placeholder="KEY"
                            />
                            <input
                              style={{ flex: 2, padding: '4px 8px', fontSize: '.8rem', fontFamily: 'monospace' }}
                              value={row.value}
                              onChange={e => updateEnvVar(app.slug, activeEnv, idx, 'value', e.target.value)}
                              onBlur={() => saveEnvVar(app.slug, activeEnv, idx)}
                              placeholder="value"
                            />
                            <button className="btn btn-xs btn-red" onClick={() => deleteEnvVar(app.slug, activeEnv, idx)}>✕</button>
                          </div>
                        ))}
                        <button className="btn btn-xs" style={{ marginTop: 4 }} onClick={() => addEnvVar(app.slug, activeEnv)}>+ Add var</button>
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
            {sorted.length === 0 && (
              <tr><td colSpan={11} style={{ textAlign: 'center', color: 'var(--dim)', padding: 24 }}>No apps match the filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {frame.open && (
        <FrameOverlay
          frame={frame}
          framePanel={framePanel}
          setFrame={setFrame}
          setFramePanel={setFramePanel}
        />
      )}

      {promptModal.open && (
        <div className="prompt-overlay" onClick={() => setPromptModal({ open: false })}>
          <div className="prompt-modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: 16 }}>{promptModal.title ?? 'API Key'}</div>
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 7, padding: '10px 14px', fontFamily: 'monospace', fontSize: '.85rem', wordBreak: 'break-all', marginBottom: 12, cursor: 'text', userSelect: 'all' }}>
              {promptModal.key}
            </div>
            <button
              className="btn btn-xs"
              style={{ marginBottom: 16 }}
              onClick={() => navigator.clipboard.writeText(promptModal.key ?? '')}
            >
              Copy key
            </button>
            {promptModal.prompt && (
              <>
                <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 7, padding: '10px 14px', fontSize: '.82rem', color: 'var(--dim)', maxHeight: 200, overflowY: 'auto', whiteSpace: 'pre-wrap', marginBottom: 12 }}>
                  {promptModal.prompt}
                </div>
                <button
                  className="btn btn-xs"
                  style={{ marginBottom: 16 }}
                  onClick={() => navigator.clipboard.writeText(promptModal.prompt ?? '')}
                >
                  Copy instructions
                </button>
              </>
            )}
            <div style={{ fontSize: '.78rem', color: 'var(--red)', marginBottom: 16 }}>
              The API key will not be shown again.
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setPromptModal({ open: false })}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

interface FrameOverlayProps {
  frame: FrameState
  framePanel: 'ask' | 'request' | 'bug' | null
  setFrame: React.Dispatch<React.SetStateAction<FrameState>>
  setFramePanel: React.Dispatch<React.SetStateAction<'ask' | 'request' | 'bug' | null>>
}

function FrameOverlay({ frame, framePanel, setFrame, setFramePanel }: FrameOverlayProps) {
  const topbarRef = useRef<HTMLElement>(null)
  const iframeRef = useRef<HTMLIFrameElement | null>(null)
  const [folded, setFolded] = useState(false)
  // v2.3.2: point-and-click Request flow — picker activates on button
  // click, then the captured ctx drives a floating modal instead of a
  // side drawer. The drawer-based Request panel is kept for portal embed
  // compatibility (CranePanels.tsx) but no longer mounted from here.
  const peek = usePeek(iframeRef)
  const [requestCtx, setRequestCtx] = useState<PeekCtx | null>(null)
  useEffect(() => {
    if (peek.ctx) {
      setRequestCtx(peek.ctx)
      peek.clear()
    }
  }, [peek.ctx]) // eslint-disable-line react-hooks/exhaustive-deps

  // v2.3.4 What's New — when this frame opens for an app, ask the server
  // if there are deployments the user hasn't acknowledged yet. Shows a
  // dialog when the live version differs from the user's last_seen. The
  // server silently records first-time visits (no dialog) so users don't
  // get a wall of historic changes for an app that's been live for months.
  const [whatsNew, setWhatsNew] = useState<{ currentVersion: string | null; changes: WhatsNewChange[] } | null>(null)
  useEffect(() => {
    if (!frame.slug) return
    let cancelled = false
    adminApi
      .get<{ current_version: string | null; changes: WhatsNewChange[]; first_time: boolean }>(
        `/api/apps/${encodeURIComponent(frame.slug)}/whats-new`,
      )
      .then(r => {
        if (cancelled || !r) return
        if (!r.first_time && r.changes && r.changes.length > 0) {
          setWhatsNew({ currentVersion: r.current_version, changes: r.changes })
        }
      })
      .catch(() => { /* silent — this is a nice-to-have, not a blocker */ })
    return () => { cancelled = true }
  }, [frame.slug])
  // Per-panel last-used width, persisted across open/close so closing
  // and reopening Request keeps the user's chosen width.
  const [widths, setWidths] = useState<Record<'ask' | 'request' | 'bug', number>>({
    ask: 380, request: 420, bug: 460,
  })
  const dragRef = useRef<{ startX: number; startW: number; key: 'ask' | 'request' | 'bug' } | null>(null)
  const onResizerDown = (e: React.MouseEvent) => {
    if (!framePanel) return
    e.preventDefault()
    dragRef.current = { startX: e.clientX, startW: widths[framePanel], key: framePanel }
    const onMove = (ev: MouseEvent) => {
      const d = dragRef.current
      if (!d) return
      const delta = d.startX - ev.clientX
      const next = Math.max(280, Math.min(900, d.startW + delta))
      setWidths(w => ({ ...w, [d.key]: next }))
    }
    const onUp = () => {
      dragRef.current = null
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  // The Custom Element fires CustomEvents (not React synthetic events) so
  // we wire a per-mount listener block. Re-binds when callbacks change.
  useEffect(() => {
    const el = topbarRef.current
    if (!el) return

    const onBack    = () => setFrame({ open: false, url: '', title: '' })
    const onRefresh = () => {
      const cur = frame.url
      setFrame(f => ({ ...f, url: '' }))
      setTimeout(() => setFrame(f => ({ ...f, url: cur })), 0)
    }
    const onEnv = (e: Event) => {
      const env = (e as CustomEvent<{ env: 'production' | 'sandbox' }>).detail.env
      setFrame(f => ({
        ...f,
        env,
        url:   env === 'sandbox' ? f.sandUrl! : f.prodUrl!,
        title: `${f.appName} (${env === 'sandbox' ? 'sandbox' : 'prod'})`,
      }))
    }
    const onFold = (e: Event) => {
      const next = (e as CustomEvent<{ folded: boolean }>).detail.folded
      setFolded(next)
    }

    el.addEventListener('crane-back',        onBack)
    el.addEventListener('crane-refresh',     onRefresh)
    el.addEventListener('crane-env-change',  onEnv)
    el.addEventListener('crane-fold-toggle', onFold)
    return () => {
      el.removeEventListener('crane-back',        onBack)
      el.removeEventListener('crane-refresh',     onRefresh)
      el.removeEventListener('crane-env-change',  onEnv)
      el.removeEventListener('crane-fold-toggle', onFold)
    }
  }, [frame.url, frame.appName, setFrame])

  // Shrink the iframe to leave room for the active drawer instead of
  // letting the drawer overlap the app. Width is user-resizable via the
  // .frame-dock-resizer; persisted per panel in `widths` state.
  const dockWidth = framePanel ? widths[framePanel] : 0
  return (
    <div
      className="app-frame-overlay"
      style={{ ['--frame-dock-width' as string]: `${dockWidth}px` } as React.CSSProperties}
    >
      <crane-app-topbar
        ref={topbarRef}
        app-name={frame.appName ?? frame.title ?? ''}
        app-icon-url={frame.hasIcon && frame.slug ? `/api/apps/${frame.slug}/icon` : ''}
        app-slug={frame.slug ?? ''}
        prod-version={frame.prodVersion ?? ''}
        sand-version={frame.sandVersion ?? ''}
        prod-url={frame.prodUrl ?? ''}
        sand-url={frame.sandUrl ?? ''}
        env={frame.env ?? 'production'}
        current-url={frame.url}
        {...(folded ? { folded: '' } : {})}
      >
        <span slot="actions" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <PresenceAvatars slug={frame.slug ?? null} />
          {frame.hasGithub && (
            <>
              <button
                type="button"
                className={'crane-topbar-btn' + (peek.active || requestCtx ? ' active' : '')}
                onClick={() => {
                  // v2.3.2 flow: click → immediately enter pick mode → on
                  // capture, the useEffect above opens the floating modal
                  // anchored to the picked element. No drawer.
                  if (requestCtx) { setRequestCtx(null); return }
                  if (peek.active) { peek.stop(); return }
                  peek.start()
                }}
                title={peek.active
                  ? 'Click an element in the app, then describe the change. Esc to cancel.'
                  : 'Point at an element to request an enhancement'}
              ><Icon.Lightbulb size={14} /> {peek.active ? 'Pick…' : 'Request'}</button>
              <button
                type="button"
                className={'crane-topbar-btn' + (framePanel === 'bug' ? ' active' : '')}
                onClick={() => setFramePanel(p => p === 'bug' ? null : 'bug')}
                title="Report a bug"
              ><Icon.Bug size={14} /> Bug</button>
            </>
          )}
        </span>
      </crane-app-topbar>

      {frame.url && <iframe ref={iframeRef} className="app-frame-iframe" src={frame.url} title={frame.title} />}
      {framePanel && (
        <div
          className="frame-dock-resizer"
          style={{ right: dockWidth }}
          onMouseDown={onResizerDown}
          title="Drag to resize panel"
        />
      )}
      {requestCtx && (
        <RequestModal
          slug={frame.slug ?? null}
          appName={frame.appName ?? frame.title ?? ''}
          peekCtx={requestCtx}
          onClose={() => setRequestCtx(null)}
        />
      )}
      {whatsNew && frame.slug && (
        <WhatsNewModal
          slug={frame.slug}
          appName={frame.appName ?? frame.title ?? frame.slug}
          currentVersion={whatsNew.currentVersion}
          changes={whatsNew.changes}
          onClose={() => setWhatsNew(null)}
        />
      )}
      <BugPanel
        slug={frame.slug ?? null}
        appName={frame.appName ?? frame.title ?? ''}
        open={framePanel === 'bug'}
        onClose={() => setFramePanel(null)}
        width={widths.bug}
      />
    </div>
  )
}
