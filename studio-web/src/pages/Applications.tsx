import { useState, useEffect, useRef } from 'react'
import { adminApi } from '../adminApi'
import { PresenceAvatars } from '../components/runtime-topbar/PresenceAvatars'
import { JobsButton } from '../components/runtime-topbar/JobsButton'
import { RequestModal } from '../components/runtime-topbar/RequestModal'
import { WhatsNewModal, type WhatsNewChange } from '../components/WhatsNewModal'
import { usePeek, type PeekCtx } from '../hooks/usePeek'
import { LauncherView } from './LauncherView'
import { useMe, isAdmin, canCreateApps } from '../hooks/useMe'
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
  auth_bypass_paths?: string[] | null
  domain?: string | null
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
  // v2.7.15: independently-copyable sections (e.g. "Managed Code" vs
  // "Unmanaged (GitHub)") so the user copies just the path they want.
  sections?: { label: string; text: string }[]
}

type SortKey = 'name' | 'visibility' | 'category' | 'ram' | 'cpu' | 'images'

export function Applications() {
  const me = useMe()
  // v2.5.0 role-aware view mode. End users default to launcher (tile
  // grid, no manage chrome). Admins / platform_admins default to manage
  // (the existing table) but can flip to launcher via the toggle. Stored
  // in localStorage so the choice persists across reloads.
  //
  // v2.5.17 fix: useState initializer ran before /api/auth/me resolved,
  // so isAdmin(null) was always false and the default fell to 'launcher'
  // for every user including platform_admin. Now: start `null` until me
  // loads, then resolve to the role-appropriate default. Saved
  // localStorage value still wins. Toggle button stays interactive.
  const adminLike = isAdmin(me)
  // v2.7.0: "+ Add Application" shows for anyone with the create-apps
  // permission (global admins, or a tier a platform admin granted) — in
  // both the Launcher and Manage views, not just admins in Manage.
  const mayCreateApp = canCreateApps(me)
  const [viewMode, setViewMode] = useState<'launcher' | 'manage' | null>(() => {
    const saved = typeof window !== 'undefined' ? localStorage.getItem('cc_apps_view') : null
    if (saved === 'launcher' || saved === 'manage') return saved
    return null
  })
  useEffect(() => {
    if (viewMode !== null || me === null) return
    setViewMode(adminLike ? 'manage' : 'launcher')
  }, [me, adminLike, viewMode])
  useEffect(() => { if (viewMode) { try { localStorage.setItem('cc_apps_view', viewMode) } catch (_) {} } }, [viewMode])

  const [apps, setApps] = useState<App[]>([])
  const [versions, setVersions] = useState<Record<string, { prod?: string; sand?: string }>>({})
  const [openEvars, setOpenEvars] = useState<Record<string, string | null>>({})
  const [evarData, setEvarData] = useState<Record<string, EnvVar[]>>({})
  const [frame, setFrame] = useState<FrameState>({ open: false, url: '', title: '' })
  const [framePanel, setFramePanel] = useState<'ask' | 'request' | 'bug' | null>(null)
  const [promptModal, setPromptModal] = useState<PromptModal>({ open: false })
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null)
  function copyText(text: string, label: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedLabel(label)
      setTimeout(() => setCopiedLabel(l => (l === label ? null : l)), 1500)
    }).catch(() => {})
  }
  const [checkUpdateText, setCheckUpdateText] = useState<Record<string, string>>({})
  const [iconUrls, setIconUrls] = useState<Record<string, string>>({})

  // v2.5.21: per-app Users modal — replaces the old wide N×M App Roles
  // matrix that lived under /settings#users. Click "Users" on an app row
  // to open a focused modal that lists every user with a role select for
  // this specific app.
  const [usersModalApp, setUsersModalApp] = useState<App | null>(null)
  // v2.7.24: client-side filter for the per-app Users modal (name / email).
  // Resets to empty on every close so opening another app doesn't carry over.
  const [usersModalFilter, setUsersModalFilter] = useState('')
  type ModalUser = { id: number; name: string; email: string | null; role: string; app_role: 'none' | 'user' | 'admin' | 'owner' }
  const [usersModalData, setUsersModalData] = useState<ModalUser[] | null>(null)
  const [usersModalSaving, setUsersModalSaving] = useState<Record<number, 'saving' | 'saved' | 'error'>>({})
  useEffect(() => {
    if (!usersModalApp) { setUsersModalData(null); return }
    let cancelled = false
    Promise.all([
      adminApi.get<{ users: { id: number; name: string; email: string | null; role: string }[] }>('/api/users'),
      adminApi.get<{ users: { id: number; app_role: ModalUser['app_role'] }[] }>(`/api/apps/${usersModalApp.slug}/identity/users`),
    ])
      .then(([allUsers, appUsers]) => {
        if (cancelled) return
        const roleByUserId = new Map(appUsers.users.map(u => [u.id, u.app_role]))
        const merged: ModalUser[] = (allUsers.users || []).map(u => ({
          id: u.id, name: u.name, email: u.email, role: u.role,
          app_role: roleByUserId.get(u.id) ?? 'none',
        }))
        setUsersModalData(merged)
      })
      .catch(() => { if (!cancelled) setUsersModalData([]) })
    return () => { cancelled = true }
  }, [usersModalApp])

  async function changeUserAppRole(userId: number, newRole: ModalUser['app_role']) {
    if (!usersModalApp) return
    const prev = usersModalData?.find(u => u.id === userId)?.app_role ?? 'none'
    setUsersModalData(d => d ? d.map(u => u.id === userId ? { ...u, app_role: newRole } : u) : d)
    setUsersModalSaving(s => ({ ...s, [userId]: 'saving' }))
    try {
      await adminApi.put(`/api/apps/${usersModalApp.slug}/roles`, { user_id: userId, app_role: newRole })
      setUsersModalSaving(s => ({ ...s, [userId]: 'saved' }))
      setTimeout(() => setUsersModalSaving(s => {
        if (s[userId] !== 'saved') return s
        const c = { ...s }; delete c[userId]; return c
      }), 1800)
    } catch (e) {
      setUsersModalData(d => d ? d.map(u => u.id === userId ? { ...u, app_role: prev } : u) : d)
      setUsersModalSaving(s => ({ ...s, [userId]: 'error' }))
      alert('Save failed: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

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

  async function setCustomDomain(app: App) {
    const help = "Custom domain for this app (served at the root of that domain).\n\n" +
      "e.g. raise.glick.run\n\n" +
      "The app is served there with NO AppCrane SSO and NO topbar - it does its\n" +
      "own auth. Maps to PRODUCTION. Point the domain's DNS at this host; Caddy\n" +
      "auto-provisions HTTPS. The crane.glick.run/" + app.slug + " path stays for ops.\n\n" +
      "Leave blank to remove the custom domain."
    const val = prompt(help, app.domain ?? '')
    if (val === null) return
    const next = val.trim() || null
    try {
      const r = await adminApi.put<{ app?: App; error?: { message?: string } }>(`/api/apps/${app.slug}`, { domain: next })
      if (r?.error) { alert('Failed: ' + (r.error.message || 'unknown')); return }
      setApps(prev => prev.map(a => a.slug === app.slug ? { ...a, domain: next } : a))
    } catch (e) {
      alert('Failed: ' + (e as Error).message)
    }
  }

  async function setAuthBypassPaths(app: App) {
    const current = (Array.isArray(app.auth_bypass_paths) ? app.auth_bypass_paths : []).join(', ')
    const help = "Path prefixes that bypass SSO on this app (comma- or newline-separated).\n\n" +
      "Each prefix must:\n" +
      "  • start with '/' (e.g. /ws/local-runner)\n" +
      "  • not overlap /api, /admin, /login, /portal, /health, /__crashed\n" +
      "  • not contain '..', '//', or whitespace\n\n" +
      "⚠ Requests under these prefixes reach your app with NO X-AppCrane-* identity\n" +
      "headers. Your app must authenticate them itself (e.g. token in query string).\n" +
      "Caddy suppresses access logging for these paths so query-string tokens don't\n" +
      "sit in log storage.\n\n" +
      "Leave blank to clear all bypass paths."
    const val = prompt(help, current)
    if (val === null) return
    const list = val.split(/[,\n]/).map(s => s.trim()).filter(Boolean)
    try {
      const r = await adminApi.put<{ app?: App; error?: { message?: string } }>(`/api/apps/${app.slug}`, { auth_bypass_paths: list })
      if (r?.error) { alert('Failed: ' + (r.error.message || 'unknown')); return }
      setApps(prev => prev.map(a => a.slug === app.slug ? { ...a, auth_bypass_paths: list.length ? list : null } : a))
    } catch (e) {
      alert('Failed: ' + (e as Error).message)
    }
  }

  // v2.6.0: showAppToken removed — it minted a `user_<random>` deployment
  // key for an X-Deployment-Key REST flow that duplicates MCP. Agents
  // authenticate to AppCrane via MCP only; per-app access is governed
  // by app_user_roles, not by paste-keys.
  // (The corresponding POST /api/apps/:slug/deployment-key endpoint was
  // removed server-side in this same commit. Existing keys keep working
  // until v3.0.)

  async function generateAgentKey() {
    const ts = Date.now()
    let failReason = ''
    // v2.7.4: ALWAYS issue a personal MCP key for the logged-in user — admins
    // included. Previously admins got a throwaway role:admin onboarding-agent
    // identity, and since every create path makes the CALLING identity the
    // app owner, that agent (not the human who clicked) ended up owning the
    // app. The human's own personal key — scope-restricted to apps they own —
    // then couldn't see it. A personal dhk_mcp_* key is equally restricted to
    // /api/mcp (auth.js KEY_SCOPE_RESTRICTED) but ties creation/ownership to
    // the human, so they own what they onboard. No admin-only endpoint, works
    // for admins and create_app-granted users alike.
    const k = await adminApi.post<{ api_key?: string }>('/api/me/mcp-keys', {
      label: `onboarding-${ts}`,
    }).catch((e: unknown) => { failReason = e instanceof Error ? e.message : String(e); return null })
    const key = k?.api_key ?? ''
    if (!key) {
      alert('Failed to issue an MCP key for onboarding' + (failReason ? `: ${failReason}` : '. Check the server logs.'))
      return
    }
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
       (d) "I don't have / want a GitHub"    → AppCrane manages the code:
           call appcrane_create_managed_app — AppCrane provisions a private
           repo on its service account, stores the credential, and you push
           scaffolding through github_* tools as usual. The user never sees
           github.com. Requires platform_admin to have configured the
           service-account in Settings → GitHub. If \`appcrane_create_managed_app\`
           returns "service-account is disabled / no token", fall back to
           paths (a)-(c) and ask the user for a PAT.
  2. The PAT they configured in their \`claude mcp add\` command. You need it
     once to pass as \`github_token\` to appcrane_create_app (AppCrane stores
     it encrypted on the app record so it can clone for future deploys).
     Path (d) does not require a PAT — managed apps use the service-account
     credential server-side. Don't echo it back.
  3. Any env vars / secrets (usually none).
  4. Display name (you'll propose; user confirms).

KEY APPCRANE TOOLS:
  appcrane_create_app(name, slug, github_url, github_token, branch?, …)
  appcrane_create_managed_app(name, slug, branch?, description?)  — path (d)
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

  Path (d) — AppCrane-managed code (no user PAT needed):
    1. Pick slug + stack as in (a). Propose; wait for ✅.
    2. appcrane_create_managed_app({ name, slug, branch: "main", description })
       — AppCrane creates the private repo on its service account; the
       returned repo.html_url is the github_url and the repo is auto-init'd
       with a README on the default branch.
    3. Push scaffolding via github_push_files to the returned full_name —
       the SAME files as path (a) step 3 (package.json, deployhub.json,
       sources, /api/health route returning {status, version}).
    4. appcrane_set_env (only if user has secrets)
    5. appcrane_deploy(slug, "sandbox")
    6. appcrane_get_logs — confirm health green; iterate via
       github_create_or_update_file + redeploy if red.

    The end user never sees github.com. They get a sandbox URL.

APP TILE ICON (optional, recommended):
  Commit \`public/icon.png\` (256×256 PNG preferred; SVG / WEBP / JPEG / GIF also accepted)
  in the repo. AppCrane picks it up on every deploy and uses it as the tile icon
  on the Dashboard, the Launcher cards, the Manage table, and the frame topbar.
  When the user has no design ready, propose a minimal monochrome SVG with their
  app name's initials or a single thematic glyph — committing one is part of a
  clean onboarding, not an afterthought.

  For mid-flight icon swaps without a redeploy: call appcrane_set_app_icon
  with the slug, format ("png"/"svg"/etc.), and base64-encoded image bytes.

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
    // v2.5.23: the full onboarding playbook now lives server-side at
    // server/services/guides/onboarding.md and is fetched by agents via
    // the appcrane_get_guide('onboarding') MCP tool. This modal no longer
    // pastes a 4 KB brief into the user's chat — they just run the
    // setup command, open Claude Code, and ask. The agent pulls the
    // latest playbook itself. Single source of truth on the server.
    void brief // kept above for reference; the modal now hands off to MCP

    // Managed Code — AppCrane hosts the repo; no GitHub account or PAT needed.
    const managedPrompt = `MANAGED CODE - AppCrane hosts the repo for you (no GitHub account or token).
Requires a platform admin to have configured the service-account in Settings > GitHub.

STEP 1 - Wire AppCrane MCP into your local Claude Code (run once in any terminal):

  claude mcp add --transport http appcrane ${origin}/api/mcp \\
    --header "X-API-Key: ${key}"

STEP 2 - In any terminal run \`claude\`, then paste:

  Onboard a new managed AppCrane app for me. I don't have a GitHub account,
  so use path (d). Call appcrane_get_guide topic="onboarding" first to pull
  the latest playbook, then walk me through it. Pick a small Vite + React +
  TS stack, ask me a name + what it does, and ship it to sandbox.

The agent calls appcrane_create_managed_app - AppCrane's service account creates a
private repo (AMC_<your_slug>), holds the credential, and pushes scaffolding for you.
You end with a sandbox URL and never touch github.com.`

    // Unmanaged (GitHub) — bring your own repo + PAT.
    const githubPrompt = `UNMANAGED (GITHUB) - you bring your own GitHub repo + Personal Access Token.

STEP 1 - Generate a GitHub PAT at https://github.com/settings/tokens.
  Classic: scope \`repo\`. Fine-grained (recommended): Contents R/W, Metadata R,
  Administration W. The PAT stays only in your local ~/.claude.json - never
  stored on the AppCrane server, only passed as a header at request time.

STEP 2 - Wire AppCrane MCP into your local Claude Code. Replace <YOUR_GITHUB_PAT>,
then run once in any terminal:

  claude mcp add --transport http appcrane ${origin}/api/mcp \\
    --header "X-API-Key: ${key}" \\
    --header "X-Github-Token: <YOUR_GITHUB_PAT>"

The X-Github-Token header enables AppCrane's GitHub passthrough - the agent gets
github_* tools (read/push files, open PRs, create repos) on the same connection.

STEP 3 - In any terminal run \`claude\`, then paste:

  Onboard a new app on AppCrane. Start by calling appcrane_get_guide with
  topic="onboarding" to fetch the latest playbook. Then ask me the inputs the
  guide lists, and walk through paths (a)/(b)/(c) accordingly.`

    setPromptModal({
      open: true,
      title: 'Add Application',
      key,
      sections: [
        { label: 'Managed Code', text: managedPrompt },
        { label: 'Unmanaged (GitHub)', text: githubPrompt },
      ],
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

  // v2.7.2: the "+ Add Application" key/instructions modal, shared by both
  // views. It used to live only in the Manage-view return, so a non-admin in
  // the Launcher clicked the button, generateAgentKey issued a key and called
  // setPromptModal({ open: true }) — but nothing rendered it. "Nothing
  // happens." Define it once and render in both returns.
  const promptModalEl = promptModal.open && (
    <div className="prompt-overlay" onClick={() => setPromptModal({ open: false })}>
      <div className="prompt-modal" onClick={e => e.stopPropagation()}>
        <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: 16 }}>{promptModal.title ?? 'API Key'}</div>
        <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 7, padding: '10px 14px', fontFamily: 'monospace', fontSize: '.85rem', wordBreak: 'break-all', marginBottom: 12, cursor: 'text', userSelect: 'all' }}>
          {promptModal.key}
        </div>
        <button
          className="btn btn-xs"
          style={{ marginBottom: 16 }}
          onClick={() => copyText(promptModal.key ?? '', 'key')}
        >
          {copiedLabel === 'key' ? 'Copied ✓' : 'Copy key'}
        </button>
        {promptModal.sections && promptModal.sections.map(section => (
          <div key={section.label} style={{ marginBottom: 18, borderTop: '1px solid var(--border)', paddingTop: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontWeight: 700, fontSize: '.9rem' }}>{section.label}</div>
              <button
                className="btn btn-xs btn-accent"
                onClick={() => copyText(section.text, section.label)}
              >
                {copiedLabel === section.label ? 'Copied ✓' : `Copy ${section.label}`}
              </button>
            </div>
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 7, padding: '10px 14px', fontSize: '.8rem', color: 'var(--dim)', maxHeight: 240, overflowY: 'auto', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
              {section.text}
            </div>
          </div>
        ))}
        {promptModal.prompt && (
          <>
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 7, padding: '10px 14px', fontSize: '.82rem', color: 'var(--dim)', maxHeight: 200, overflowY: 'auto', whiteSpace: 'pre-wrap', marginBottom: 12 }}>
              {promptModal.prompt}
            </div>
            <button
              className="btn btn-xs"
              style={{ marginBottom: 16 }}
              onClick={() => copyText(promptModal.prompt ?? '', 'instructions')}
            >
              {copiedLabel === 'instructions' ? 'Copied ✓' : 'Copy instructions'}
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
  )

  // v2.5.0: end users get the tile launcher. Admins can flip to it via
  // the toggle; non-admins never see the manage table at all (the data
  // would be filtered server-side anyway, but the toggle is hidden).
  if (viewMode === 'launcher') {
    return (
      <>
        <LauncherView
          onOpen={(slug, name, hasIcon) => {
            const a = apps.find(x => x.slug === slug)
            const prodUrl = `/${slug}`
            const sandUrl = `/${slug}-sandbox`
            // v2.6.1: open production by default. If production isn't
            // healthy (down / unknown / never deployed) but sandbox is,
            // fall back to sandbox so end users still see something
            // working. If both are problematic, still open production —
            // the topbar lets them switch envs, and the tile click is
            // already gated to disable when both are down.
            const prodOk = a?.production?.health?.status === 'healthy'
            const sandOk = a?.sandbox?.health?.status === 'healthy'
            const useSand = !prodOk && sandOk
            setFrame({
              open: true,
              url: useSand ? sandUrl : prodUrl,
              title: `${name} (${useSand ? 'sandbox' : 'prod'})`,
              slug, appName: name, env: useSand ? 'sandbox' : 'production',
              prodUrl, sandUrl,
              prodVersion: a?.production?.deploy?.version || '',
              sandVersion: a?.sandbox?.deploy?.version || '',
              hasIcon,
              hasGithub: !!a?.github_url,
            })
          }}
          headerRight={(mayCreateApp || adminLike) && (
            <>
              {mayCreateApp && (
                <button className="btn btn-accent" onClick={generateAgentKey}>+ Add Application</button>
              )}
              {adminLike && (
                // v2.5.20: moved from a floating bottom-right pill into the
                // Launcher header. The bottom-right placement was easy to
                // miss — multiple platform_admins ended up "stuck" on
                // Launcher with no obvious way back to the manage table.
                <div className="applications-mode-toggle" style={{ marginLeft: 8 }}>
                  <button className="active">Launcher</button>
                  <button onClick={() => setViewMode('manage')}>Manage</button>
                </div>
              )}
            </>
          )}
        />
        {frame.open && (
          <FrameOverlay frame={frame} framePanel={framePanel} setFrame={setFrame} setFramePanel={setFramePanel} />
        )}
        {promptModalEl}
      </>
    )
  }

  return (
    <div className="container">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>Applications</h2>
        {mayCreateApp && (
          <button className="btn btn-accent" onClick={generateAgentKey}>+ Add Application</button>
        )}
        {adminLike && (
          <div className="applications-mode-toggle" style={{ marginLeft: 8 }}>
            <button onClick={() => setViewMode('launcher')}>Launcher</button>
            <button className="active">Manage</button>
          </div>
        )}
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
                      // v2.5.5: live-fetch reads the running app's /api/health
                      // body.version. Most user apps don't expose that field,
                      // so the cell was permanently '—'. Fall back to the
                      // last live deployment's version (captured at deploy
                      // time from the manifest) when the live read is missing.
                      const liveVer = versions[app.slug]?.[env === 'production' ? 'prod' : 'sand']
                      const deployVer = app[env]?.deploy?.version
                      const ver = (liveVer && liveVer !== '—') ? liveVer : (deployVer || null)
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
                        <button
                          className="btn btn-xs"
                          onClick={() => setUsersModalApp(app)}
                          title="Manage which users have access to this app and at what role"
                        >Users</button>
                        <button
                          className="btn btn-xs"
                          onClick={() => setFrameAncestors(app)}
                          title={app.frame_ancestors ? `Embedders: ${app.frame_ancestors}` : 'Allowed embedders (default: same origin only)'}
                        >🖼{app.frame_ancestors ? ' ✓' : ''}</button>
                        {(() => {
                          const abp = Array.isArray(app.auth_bypass_paths) ? app.auth_bypass_paths : []
                          return (
                            <button
                              className="btn btn-xs"
                              onClick={() => setAuthBypassPaths(app)}
                              title={abp.length
                                ? `Auth-bypass paths: ${abp.join(', ')}`
                                : 'Path prefixes that bypass SSO on this app (advanced — apps must self-authenticate)'}
                            >🔓{abp.length ? ' ✓' : ''}</button>
                          )
                        })()}
                        <button
                          className="btn btn-xs"
                          onClick={() => setCustomDomain(app)}
                          title={app.domain
                            ? `Custom domain: ${app.domain} (served at root, no SSO/topbar)`
                            : 'Custom domain — serve this app on its own domain, bypassing AppCrane auth'}
                        >🌐{app.domain ? ' ✓' : ''}</button>
                        {(app.source_type === 'github' || app.source_type === 'managed' || app.github_url) && (
                          <>
                            {app.github_url && (
                              <a className="btn btn-xs" href={app.github_url} target="_blank" rel="noreferrer" title={app.github_url}>gh ↗</a>
                            )}
                            <button
                              className="btn btn-xs"
                              onClick={() => checkUpdates(app.slug)}
                              title="Check GitHub for new commits since last deploy"
                            >{checkUpdateText[app.slug] || '↑ updates'}</button>
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
                            const liveVer = versions[app.slug]?.[env === 'production' ? 'prod' : 'sand']
                            const deployVer = app[env]?.deploy?.version
                            const ver = (liveVer && liveVer !== '—') ? liveVer : (deployVer || null)
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

      {promptModalEl}

      {/* v2.5.21: per-app Users modal — opened from "Users" button on
          each Manage row. Lists every user with a role select for THIS
          app. Replaces the wide N×M App Roles matrix that used to live
          on /settings#users. */}
      {usersModalApp && (
        <div
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 10500,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          onClick={() => { setUsersModalApp(null); setUsersModalFilter('') }}
        >
          <div
            style={{
              width: 'min(640px, 92vw)', maxHeight: '80vh',
              background: 'var(--surface, #1a1a1a)', color: 'var(--text)',
              border: '1px solid var(--border, #333)', borderRadius: 8,
              boxShadow: '0 16px 48px rgba(0,0,0,.5)',
              display: 'flex', flexDirection: 'column', overflow: 'hidden',
            }}
            onClick={e => e.stopPropagation()}
            role="dialog"
            aria-label={`Users for ${usersModalApp.name}`}
          >
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '12px 16px',
              borderBottom: '1px solid var(--border, #333)',
              background: 'var(--surface2, #232323)',
            }}>
              <span style={{ fontWeight: 600, fontSize: '.95rem' }}>
                Users · {usersModalApp.name}
              </span>
              <span style={{ fontSize: '.74rem', color: 'var(--dim)', fontFamily: 'monospace' }}>
                {usersModalApp.slug}
              </span>
              <button
                style={{
                  marginLeft: 'auto', background: 'none', border: 'none',
                  color: 'var(--dim)', fontSize: '1.4rem', lineHeight: 1, cursor: 'pointer',
                }}
                onClick={() => { setUsersModalApp(null); setUsersModalFilter('') }}
                aria-label="Close"
              >×</button>
            </div>

            {/* v2.7.24: search box. Lives outside the scroll region so it
                stays pinned while the list scrolls. autoFocus = the input is
                ready as soon as the modal opens. */}
            <div style={{ padding: '10px 16px 6px', borderBottom: '1px solid var(--border-faint, #2a2a2a)' }}>
              <input
                type="text"
                placeholder="Search by name or email…"
                value={usersModalFilter}
                onChange={e => setUsersModalFilter(e.target.value)}
                autoFocus
                style={{
                  width: '100%', boxSizing: 'border-box',
                  padding: '6px 10px', fontSize: '.85rem',
                  background: 'var(--surface2, #232323)',
                  border: '1px solid var(--border, #333)',
                  borderRadius: 6, color: 'var(--text)',
                  outline: 'none',
                }}
              />
            </div>

            <div style={{ overflowY: 'auto', padding: '8px 16px', flex: 1 }}>
              {usersModalData === null ? (
                <div style={{ color: 'var(--dim)', padding: 16 }}>Loading…</div>
              ) : usersModalData.length === 0 ? (
                <div style={{ color: 'var(--dim)', padding: 16 }}>No users registered.</div>
              ) : (() => {
                const q = usersModalFilter.trim().toLowerCase()
                const filtered = q
                  ? usersModalData.filter(u =>
                      (u.name || '').toLowerCase().includes(q) ||
                      (u.email || '').toLowerCase().includes(q))
                  : usersModalData
                if (filtered.length === 0) {
                  return <div style={{ color: 'var(--dim)', padding: 16 }}>No users match &quot;{usersModalFilter}&quot;.</div>
                }
                return (
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border, #333)' }}>
                      <th style={{ textAlign: 'left',  padding: '8px 4px', fontSize: '.78rem', color: 'var(--dim)', fontWeight: 500 }}>User</th>
                      <th style={{ textAlign: 'right', padding: '8px 4px', fontSize: '.78rem', color: 'var(--dim)', fontWeight: 500 }}>Role on this app</th>
                      <th style={{ width: 28 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(u => {
                      const status = usersModalSaving[u.id]
                      const isPlatformAdmin = u.role === 'platform_admin'
                      const value = isPlatformAdmin ? 'owner' : u.app_role
                      return (
                        <tr key={u.id} style={{ borderBottom: '1px solid var(--border-faint, #2a2a2a)' }}>
                          <td style={{ padding: '8px 4px', fontSize: '.88rem' }}>
                            <div style={{ fontWeight: 500, display: 'flex', alignItems: 'center', gap: 8 }}>
                              {u.name}
                              {isPlatformAdmin && (
                                <span style={{
                                  fontSize: '.66rem', padding: '1px 6px', borderRadius: 3,
                                  background: 'rgba(245, 158, 11, .2)', color: '#fbbf24',
                                  border: '1px solid rgba(245, 158, 11, .4)',
                                }}>platform_admin</span>
                              )}
                            </div>
                            {u.email && (
                              <div style={{ fontSize: '.74rem', color: 'var(--dim)' }}>{u.email}</div>
                            )}
                          </td>
                          <td style={{ padding: '8px 4px', textAlign: 'right' }}>
                            <select
                              value={value}
                              disabled={isPlatformAdmin || status === 'saving'}
                              title={isPlatformAdmin
                                ? 'Platform admin has owner-equivalent access to every app. Demote their global role first.'
                                : undefined}
                              onChange={e => changeUserAppRole(u.id, e.target.value as ModalUser['app_role'])}
                              style={{ minWidth: 110 }}
                            >
                              <option value="none">none</option>
                              <option value="user">user</option>
                              <option value="admin">admin</option>
                              <option value="owner">owner</option>
                            </select>
                          </td>
                          <td style={{ padding: '8px 0', textAlign: 'center', width: 28 }}>
                            {!isPlatformAdmin && status === 'saving' && <span style={{ color: 'var(--dim)' }}>…</span>}
                            {!isPlatformAdmin && status === 'saved'  && <span style={{ color: 'var(--green)' }}>✓</span>}
                            {!isPlatformAdmin && status === 'error'  && <span style={{ color: 'var(--red)' }}>✗</span>}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                )
              })()}
            </div>

            <div style={{
              padding: '10px 16px',
              borderTop: '1px solid var(--border, #333)',
              background: 'var(--surface2, #232323)',
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <span style={{ fontSize: '.74rem', color: 'var(--dim)' }}>
                Changes save automatically.
              </span>
              <button className="btn btn-accent" onClick={() => setUsersModalApp(null)}>Done</button>
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

  // v2.7.5: keep the topbar version pill live AND correct for the env being
  // viewed. The frame was opened with a static deploy-record snapshot
  // (app.<env>.deploy.version) captured once at open time — so it never
  // changed when toggling Production/Sandbox, and showed a stale/empty value
  // when the production deploy record lagged the live container. Fetch the
  // live version for the ACTIVE env and write it into the matching attribute;
  // re-runs on env switch so the pill always reflects what's actually running
  // in the env you're looking at.
  useEffect(() => {
    if (!frame.slug) return
    const env = frame.env ?? 'production'
    let cancelled = false
    adminApi
      .get<{ version?: string }>(`/api/apps/${encodeURIComponent(frame.slug)}/live-version/${env}`)
      .then(r => {
        if (cancelled || !r?.version) return
        const field = env === 'sandbox' ? 'sandVersion' : 'prodVersion'
        setFrame(f => (f.slug === frame.slug && f.open ? { ...f, [field]: r.version } : f))
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [frame.slug, frame.env, setFrame])
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
      // v2.6.10: cache-bust on refresh. Setting an iframe's src to the
      // same URL it already has can be served from the browser disk
      // cache — the user clicks Refresh, the iframe unmounts and
      // remounts at /myapp, but the HTML response is cached so the new
      // asset hashes (and therefore the new version) never load.
      // Appending a fresh `_ts=…` query param forces a real network
      // fetch on every refresh; the app's server ignores unknown query
      // params and the SPA bundle picks up its current content-hashed
      // assets via the freshly fetched HTML.
      const cur = frame.url
      if (!cur) return
      const stripped = cur.replace(/([?&])_ts=\d+&?/, '$1').replace(/[?&]$/, '')
      const sep = stripped.includes('?') ? '&' : '?'
      const next = `${stripped}${sep}_ts=${Date.now()}`
      setFrame(f => ({ ...f, url: '' }))
      setTimeout(() => setFrame(f => ({ ...f, url: next })), 0)
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
              {/* v2.7.25: 📋 Jobs button. The component existed since the
                  AppStudio request flow shipped, multiple panels' copy points
                  users at the "📋 Jobs panel" to track progress — but the
                  button was never actually slotted into the topbar. Reporter
                  bug #158 ("Jobs panel button does nothing") was real: it did
                  nothing because it wasn't there. Gated on frame.hasGithub
                  (same as Request/Bug) — Jobs only exist for github apps. */}
              <JobsButton slug={frame.slug ?? null} />
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
