import { useState, useEffect, useRef } from 'react'
import { adminApi } from '../adminApi'
import { BuilderBadge } from '../components/runtime-topbar/BuilderBadge'
import { PresenceAvatars } from '../components/runtime-topbar/PresenceAvatars'
import { JobsButton } from '../components/runtime-topbar/JobsButton'
import { AskPanel } from '../components/runtime-topbar/AskPanel'
import { RequestPanel } from '../components/runtime-topbar/RequestPanel'
import { BugPanel } from '../components/runtime-topbar/BugPanel'
import { defineCraneAppTopbar } from '../topbar-element/entry'
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
  has_claude_credentials?: boolean
  has_github_token?: boolean
  resource_limits?: { max_ram_mb?: number; max_cpu_percent?: number }
  image_retention?: number
  frame_ancestors?: string | null
  production?: { deploy?: { status?: string; version?: string }; health?: { status: string } }
  sandbox?: { deploy?: { status?: string; version?: string }; health?: { status: string } }
}

interface EnvVar {
  key: string
  value: string
}

interface AnalysisEnvVar {
  key: string
  required: boolean
  example?: string
  description?: string
}

interface Analysis {
  name: string
  slug: string
  description?: string
  framework?: string
  language?: string
  env_vars?: AnalysisEnvVar[]
  notes?: string
  github_url?: string
  branch?: string
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
}

type WizardStep = 'input' | 'analyzing' | 'review'
type SortKey = 'name' | 'visibility' | 'category' | 'ram' | 'cpu' | 'images'

export function Applications() {
  const [apps, setApps] = useState<App[]>([])
  const [versions, setVersions] = useState<Record<string, { prod?: string; sand?: string }>>({})
  const [openEvars, setOpenEvars] = useState<Record<string, string | null>>({})
  const [evarData, setEvarData] = useState<Record<string, EnvVar[]>>({})
  const [frame, setFrame] = useState<FrameState>({ open: false, url: '', title: '' })
  const [framePanel, setFramePanel] = useState<'ask' | 'request' | 'bug' | null>(null)
  const [promptModal, setPromptModal] = useState<PromptModal>({ open: false })
  const [wizardOpen, setWizardOpen] = useState(false)
  const [wizardStep, setWizardStep] = useState<WizardStep>('input')
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [wizardEnvValues, setWizardEnvValues] = useState<Record<string, string>>({})
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

  const ghUrlRef = useRef<HTMLInputElement>(null)
  const branchRef = useRef<HTMLInputElement>(null)
  const patRef = useRef<HTMLInputElement>(null)
  const azNameRef = useRef<HTMLInputElement>(null)
  const azSlugRef = useRef<HTMLInputElement>(null)
  const azDescRef = useRef<HTMLInputElement>(null)

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
    const name = `agent-${ts}`
    const email = `agent-${ts}@appcrane`
    const r = await adminApi.post<{ key?: string; api_key?: string; user?: { id: number } }>('/api/users', {
      name,
      email,
      role: 'user',
      kind: 'agent',
    }).catch(() => null)
    const key = r?.key ?? r?.api_key ?? ''
    setPromptModal({
      open: true,
      key,
      prompt: `Agent user created: ${name}\nEmail: ${email}\n\nAdd this API key to your agent's environment:\n  APPCRANE_API_KEY=${key}\n\nThis key grants user-level access. The API key will not be shown again.`,
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

  async function analyzeRepo() {
    const github_url = ghUrlRef.current?.value.trim()
    if (!github_url) return
    const branch = branchRef.current?.value.trim() || 'main'
    const github_token = patRef.current?.value.trim() || undefined
    setWizardStep('analyzing')
    const r = await adminApi
      .post<{ analysis: Analysis }>('/api/apps/analyze', { github_url, branch, github_token })
      .catch(() => null)
    if (!r?.analysis) {
      setWizardStep('input')
      alert('Analysis failed')
      return
    }
    setAnalysis(r.analysis)
    const vals: Record<string, string> = {}
    for (const ev of r.analysis.env_vars ?? []) {
      vals[ev.key] = ev.example ?? ''
    }
    setWizardEnvValues(vals)
    setWizardStep('review')
  }

  async function createApp() {
    if (!analysis) return
    const name = azNameRef.current?.value.trim() || analysis.name
    const slug = azSlugRef.current?.value.trim() || analysis.slug
    const description = azDescRef.current?.value.trim() || analysis.description
    await adminApi.post('/api/apps', {
      name,
      slug,
      description,
      github_url: analysis.github_url,
      branch: analysis.branch,
      source_type: 'github',
    }).catch(() => {})
    for (const env of ['production', 'sandbox']) {
      const body: Record<string, string> = {}
      for (const [k, v] of Object.entries(wizardEnvValues)) {
        if (v) body[k] = v
      }
      if (Object.keys(body).length) {
        await adminApi.put(`/api/apps/${slug}/env/${env}`, body).catch(() => {})
      }
    }
    setWizardOpen(false)
    setWizardStep('input')
    setAnalysis(null)
    loadAll()
  }

  function healthDot(app: App, env: 'production' | 'sandbox') {
    const h = app[env]?.health?.status
    if (!h || h === 'unknown') return 'dot dot-gray'
    if (h === 'healthy') return 'dot dot-green'
    return 'dot dot-red'
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
        <button className="btn btn-accent" onClick={() => { setWizardOpen(true); setWizardStep('input'); setAnalysis(null) }}>
          + Add from GitHub
        </button>
        <button className="btn" onClick={generateAgentKey}>+ New App Agent</button>
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
              <th>Status</th>
              <th>Actions</th>
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
                      <input
                        className="editable" defaultValue={app.name}
                        onBlur={e => { if (e.target.value !== app.name) saveName(app.slug, e.target.value) }}
                        style={{ minWidth: 130 }}
                      />
                      {app.has_claude_credentials && (
                        <span className="claude-badge" style={{ marginLeft: 6 }} title="App has its own Claude OAuth credentials">🔑</span>
                      )}
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
                    <td>
                      {/* Compact dual health summary; expand the row for the
                          full sandbox / production controls. */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span title="Sandbox" style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                          <span className={healthDot(app, 'sandbox')} />
                          <span style={{ fontSize: '.66rem', color: 'var(--dim)' }}>S</span>
                        </span>
                        <span title="Production" style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                          <span className={healthDot(app, 'production')} />
                          <span style={{ fontSize: '.66rem', color: 'var(--dim)' }}>P</span>
                        </span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
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
                            return (
                              <div key={env} className={`apps-drill-env apps-drill-env-${env}`}>
                                <div className="apps-drill-env-hdr">
                                  {isProd ? 'Production' : 'Sandbox'}
                                </div>
                                <div className="apps-drill-env-body">
                                  <span className={healthDot(app, env)} />
                                  <span style={{ fontFamily: 'monospace', fontSize: '.74rem', color: 'var(--dim)' }}>{ver ?? '…'}</span>
                                  <a className="env-link" href="#" onClick={e => { e.preventDefault(); openAppFrame(app, env) }}>↗ open</a>
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

      <div className={`az-overlay${wizardOpen ? ' open' : ''}`}>
        <div className="az-modal">
          {wizardStep === 'input' && (
            <>
              <div className="az-title" style={{ fontWeight: 700, fontSize: '1.05rem' }}>Add from GitHub</div>
              <div className="az-field">
                <label className="az-label">GitHub URL</label>
                <input ref={ghUrlRef} className="az-input" placeholder="https://github.com/owner/repo" />
              </div>
              <div className="az-field">
                <label className="az-label">Branch</label>
                <input ref={branchRef} className="az-input" placeholder="main" defaultValue="main" />
              </div>
              <div className="az-field">
                <label className="az-label">Personal Access Token (optional)</label>
                <input ref={patRef} className="az-input" type="password" placeholder="ghp_..." />
              </div>
              <div className="az-actions">
                <button className="btn" onClick={() => setWizardOpen(false)}>Cancel</button>
                <button className="btn btn-accent" onClick={analyzeRepo}>Analyze with AI →</button>
              </div>
            </>
          )}

          {wizardStep === 'analyzing' && (
            <div style={{ textAlign: 'center', padding: '20px 0' }}>
              <div style={{ marginBottom: 14 }}>
                <span className="az-spinner" />
                <span style={{ color: 'var(--dim)' }}>Cloning and analyzing repository…</span>
              </div>
            </div>
          )}

          {wizardStep === 'review' && analysis && (
            <>
              <div className="az-title" style={{ fontWeight: 700, fontSize: '1.05rem' }}>Review & Create</div>
              {(analysis.framework || analysis.language) && (
                <div style={{ display: 'flex', gap: 6 }}>
                  {analysis.framework && <span className="az-badge" style={{ background: 'var(--accent)', color: '#fff', padding: '2px 10px', borderRadius: 5, fontSize: '.8rem', fontWeight: 600 }}>{analysis.framework}</span>}
                  {analysis.language && <span style={{ background: 'var(--surface2)', border: '1px solid var(--border)', padding: '2px 10px', borderRadius: 5, fontSize: '.8rem', color: 'var(--dim)' }}>{analysis.language}</span>}
                </div>
              )}
              <div className="az-field">
                <label className="az-label">Name</label>
                <input ref={azNameRef} className="az-input" defaultValue={analysis.name} />
              </div>
              <div className="az-field">
                <label className="az-label">Slug</label>
                <input ref={azSlugRef} className="az-input" defaultValue={analysis.slug} />
              </div>
              <div className="az-field">
                <label className="az-label">Description</label>
                <input ref={azDescRef} className="az-input" defaultValue={analysis.description ?? ''} />
              </div>
              {(analysis.env_vars ?? []).length > 0 && (
                <div className="az-section">
                  <div style={{ fontWeight: 600, fontSize: '.82rem', marginBottom: 8, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '.5px' }}>Environment Variables</div>
                  {(analysis.env_vars ?? []).map(ev => (
                    <div key={ev.key} style={{ marginBottom: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: '.82rem', fontWeight: 600 }}>{ev.key}</span>
                        <span className={ev.required ? 'az-req' : 'az-opt'} style={{
                          fontSize: '.68rem', padding: '1px 6px', borderRadius: 4, fontWeight: 600,
                          background: ev.required ? '#ef444422' : '#22c55e22',
                          color: ev.required ? 'var(--red)' : 'var(--green)',
                        }}>
                          {ev.required ? 'required' : 'optional'}
                        </span>
                      </div>
                      {ev.description && <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 4 }}>{ev.description}</div>}
                      <input
                        className="az-input"
                        placeholder={ev.example ?? ''}
                        value={wizardEnvValues[ev.key] ?? ''}
                        onChange={e => setWizardEnvValues(prev => ({ ...prev, [ev.key]: e.target.value }))}
                      />
                    </div>
                  ))}
                </div>
              )}
              {analysis.notes && (
                <div className="az-notes">{analysis.notes}</div>
              )}
              <div className="az-actions">
                <button className="btn" onClick={() => { setWizardStep('input'); setAnalysis(null) }}>Back</button>
                <button className="btn" onClick={() => setWizardOpen(false)}>Cancel</button>
                <button className="btn btn-accent" onClick={createApp}>Create App</button>
              </div>
            </>
          )}
        </div>
      </div>

      {promptModal.open && (
        <div className="prompt-overlay" onClick={() => setPromptModal({ open: false })}>
          <div className="prompt-modal" onClick={e => e.stopPropagation()}>
            <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: 16 }}>API Key</div>
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
  const [folded, setFolded] = useState(false)
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
          <BuilderBadge slug={frame.slug ?? null} />
          {frame.hasGithub && (
            <>
              <button
                type="button"
                className={'crane-topbar-btn' + (framePanel === 'ask' ? ' active' : '')}
                onClick={() => setFramePanel(p => p === 'ask' ? null : 'ask')}
                title="Ask Claude about this app's source code"
              >🤖 Learn</button>
              <button
                type="button"
                className={'crane-topbar-btn' + (framePanel === 'request' ? ' active' : '')}
                onClick={() => setFramePanel(p => p === 'request' ? null : 'request')}
                title="File an enhancement request"
              >💡 Request</button>
              <button
                type="button"
                className={'crane-topbar-btn' + (framePanel === 'bug' ? ' active' : '')}
                onClick={() => setFramePanel(p => p === 'bug' ? null : 'bug')}
                title="Report a bug — same Plan / Code / Build pipeline as a request"
              >🐛 Bug</button>
            </>
          )}
          <JobsButton slug={frame.slug ?? null} />
        </span>
      </crane-app-topbar>

      {frame.url && <iframe className="app-frame-iframe" src={frame.url} title={frame.title} />}
      {framePanel && (
        <div
          className="frame-dock-resizer"
          style={{ right: dockWidth }}
          onMouseDown={onResizerDown}
          title="Drag to resize panel"
        />
      )}
      <AskPanel
        slug={frame.slug ?? null}
        appName={frame.appName ?? frame.title ?? ''}
        open={framePanel === 'ask'}
        onClose={() => setFramePanel(null)}
        width={widths.ask}
      />
      <RequestPanel
        slug={frame.slug ?? null}
        appName={frame.appName ?? frame.title ?? ''}
        open={framePanel === 'request'}
        onClose={() => setFramePanel(null)}
        width={widths.request}
      />
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
