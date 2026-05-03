import { useEffect, useState, useCallback, useRef } from 'react'
import { api } from './api'
import type { Agent, AppCraneApp } from './types'
import { ChatPanel } from './components/ChatPanel'
import { AppContextPanel } from './components/AppContextPanel'
import { adminApi } from './adminApi'

interface SkillSummary { slug: string; name: string; apps?: string[] }
interface RequestSummary { id: number; app_slug: string; message: string; status?: string; created_at?: string }
const TERMINAL_STATUSES = new Set(['done', 'merged', 'closed', 'failed', 'cancelled'])

function HealthDot({ status }: { status: string }) {
  const color = status === 'healthy' ? 'var(--working)' : status === 'down' ? 'var(--danger)' : 'var(--fg-2)'
  return <span style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: color, marginRight: 4, verticalAlign: 'middle' }} />
}

/**
 * Compact OAuth badge with inline expiry. Bg color flips:
 *   accent (default) → green, ok
 *   orange           → expires within 24h
 *   red              → already expired
 * Tooltip carries the full datetime + a re-upload hint when stale.
 */
function OAuthBadge({ expiresAt }: { expiresAt?: string | number | null }) {
  const ms = typeof expiresAt === 'number' ? expiresAt
           : expiresAt ? Date.parse(String(expiresAt)) : NaN
  const valid   = Number.isFinite(ms) && ms > 0
  const expired = valid && ms < Date.now()
  const soon    = valid && !expired && ms - Date.now() < 24 * 3600 * 1000
  const bg = expired ? 'var(--danger, #ef4444)'
           : soon    ? '#f97316'
           :           'var(--accent, #6366f1)'
  const human = valid ? new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : ''
  const fullTip = valid
    ? `OAuth — Claude credentials expire ${new Date(ms).toLocaleString()}` + (expired ? '. ⚠ EXPIRED — re-run `claude login` and re-upload.' : soon ? '. ⏰ Expires soon.' : '.')
    : 'OAuth — this app uses its own Claude credentials.json.'
  return (
    <span className="sbadge" style={{ background: bg, color: '#fff' }} title={fullTip}>
      🔑 {valid ? human : 'OAuth'}{expired ? ' ⚠' : soon ? ' ⏰' : ''}
    </span>
  )
}

export function App() {
  const [apps, setApps] = useState<AppCraneApp[]>([])
  const [selectedSlug, setSelectedSlug] = useState<string | null>(null)
  const [activeAgent, setActiveAgent] = useState<Agent | null>(null)
  const [loadingSession, setLoadingSession] = useState(false)
  const [startingSession, setStartingSession] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [contextOpen, setContextOpen] = useState(false)

  // skill name list per app slug — populated from /api/skills (one fetch).
  const [skillsByApp, setSkillsByApp] = useState<Record<string, string[]>>({})
  // open enhancement requests grouped per app slug — refreshed every 8s.
  const [pendingByApp, setPendingByApp] = useState<Record<string, RequestSummary[]>>({})
  // Which app + which popup is currently open: 'skills' | 'pending' | null.
  const [popup, setPopup] = useState<{ slug: string; kind: 'skills' | 'pending' } | null>(null)
  const popupRef = useRef<HTMLDivElement>(null)

  const loadApps = useCallback(() => {
    return api.listApps().then(setApps).catch((e) => setError(String(e)))
  }, [])

  const loadPending = useCallback(() => {
    // /api/enhancements is admin-only; fall back to /my for portal users.
    return adminApi.get<{ requests: RequestSummary[] }>('/api/enhancements')
      .catch(() => adminApi.get<{ requests: RequestSummary[] }>('/api/enhancements/my').catch(() => ({ requests: [] })))
      .then(({ requests }) => {
        const map: Record<string, RequestSummary[]> = {}
        for (const r of requests || []) {
          if (TERMINAL_STATUSES.has((r.status || '').toLowerCase())) continue
          ;(map[r.app_slug] ||= []).push(r)
        }
        setPendingByApp(map)
      })
  }, [])

  useEffect(() => {
    loadApps()
    loadPending()
    adminApi.get<{ skills: SkillSummary[] }>('/api/skills').then(({ skills }) => {
      const map: Record<string, string[]> = {}
      for (const s of skills || []) {
        for (const slug of s.apps || []) (map[slug] ||= []).push(s.name || s.slug)
      }
      setSkillsByApp(map)
    }).catch(() => {})
    const t = setInterval(() => { loadApps(); loadPending() }, 8000)
    return () => clearInterval(t)
  }, [loadApps, loadPending])

  // Close popup on outside click
  useEffect(() => {
    if (!popup) return
    const onClick = (e: MouseEvent) => {
      if (popupRef.current && !popupRef.current.contains(e.target as Node)) setPopup(null)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [popup])

  const selectedApp = apps.find((a) => a.slug === selectedSlug) ?? null

  const selectApp = async (app: AppCraneApp) => {
    setSelectedSlug(app.slug)
    setActiveAgent(null)
    if (app.currentSession) {
      setLoadingSession(true)
      try {
        const agent = await api.getAgent(app.currentSession.id)
        setActiveAgent(agent)
      } catch (e) {
        setError(String(e))
      } finally {
        setLoadingSession(false)
      }
    }
  }

  const startSession = async (app: AppCraneApp) => {
    setStartingSession(true)
    setError(null)
    try {
      const agent = await api.createSession(app.slug)
      setActiveAgent(agent)
      await loadApps()
    } catch (e) {
      setError(String(e))
    } finally {
      setStartingSession(false)
    }
  }

  const onSessionUpdate = useCallback(async (_updated: Agent) => {
    await loadApps()
    if (selectedSlug) {
      const refreshed = apps.find((a) => a.slug === selectedSlug)
      if (refreshed?.currentSession) {
        const agent = await api.getAgent(refreshed.currentSession.id)
        setActiveAgent(agent)
      }
    }
  }, [apps, selectedSlug, loadApps])

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>Applications</h2>
        </div>
        {error && (
          <div style={{ padding: '6px 10px', fontSize: 11, color: 'var(--danger)' }}>{error}</div>
        )}
        <div className="sidebar-list">
          {apps.map((app) => (
            <div
              key={app.slug}
              className={`session-item ${selectedSlug === app.slug ? 'selected' : ''}`}
              onClick={() => selectApp(app)}
            >
              <div className="sname">
                <HealthDot status={app.production.health.status} />
                {app.name}
                {app.has_claude_credentials && (
                  <OAuthBadge expiresAt={app.claude_credentials_expires_at} />
                )}
                {(skillsByApp[app.slug]?.length ?? 0) > 0 && (
                  <button
                    type="button"
                    className="sbadge"
                    style={{ cursor: 'pointer', background: 'var(--surface, #2a2a2a)', border: '1px solid var(--border, #333)' }}
                    title="Skills assigned to this app's builder"
                    onClick={(e) => {
                      e.stopPropagation()
                      setPopup(p => p?.slug === app.slug && p.kind === 'skills' ? null : { slug: app.slug, kind: 'skills' })
                    }}
                  >🧩 {skillsByApp[app.slug].length}</button>
                )}
                {(pendingByApp[app.slug]?.length ?? 0) > 0 && (
                  <button
                    type="button"
                    className="sbadge"
                    style={{ cursor: 'pointer', background: 'var(--surface, #2a2a2a)', border: '1px solid var(--border, #333)' }}
                    title="Pending requests for this app"
                    onClick={(e) => {
                      e.stopPropagation()
                      setPopup(p => p?.slug === app.slug && p.kind === 'pending' ? null : { slug: app.slug, kind: 'pending' })
                    }}
                  >📋 {pendingByApp[app.slug].length}</button>
                )}
                {app.currentSession && (
                  <span className={`sbadge ${app.currentSession.status}`}>
                    {app.currentSession.status}
                  </span>
                )}
              </div>
              {popup?.slug === app.slug && (
                <div
                  ref={popupRef}
                  className="builder-popup"
                  onClick={e => e.stopPropagation()}
                >
                  <div className="builder-popup-hdr">
                    {popup.kind === 'skills'
                      ? `🧩 Skills (${skillsByApp[app.slug]?.length ?? 0})`
                      : `📋 Pending requests (${pendingByApp[app.slug]?.length ?? 0})`}
                  </div>
                  {popup.kind === 'skills' && (
                    <ul className="builder-popup-list">
                      {(skillsByApp[app.slug] ?? []).map((name, i) => (
                        <li key={i}>{name}</li>
                      ))}
                      {(skillsByApp[app.slug] ?? []).length === 0 && <li className="builder-popup-empty">No skills assigned.</li>}
                    </ul>
                  )}
                  {popup.kind === 'pending' && (
                    <ul className="builder-popup-list">
                      {(pendingByApp[app.slug] ?? []).map(r => (
                        <li key={r.id}>
                          <a href={`/requests#${r.id}`} title={r.message} onClick={e => e.stopPropagation()}>
                            #{r.id} <span className="builder-popup-status">{r.status || 'queued'}</span>
                            <div className="builder-popup-msg">{r.message}</div>
                          </a>
                        </li>
                      ))}
                      {(pendingByApp[app.slug] ?? []).length === 0 && <li className="builder-popup-empty">No pending requests.</li>}
                    </ul>
                  )}
                </div>
              )}
              {app.description && (
                <div className="smeta" style={{ fontFamily: 'inherit', opacity: 0.75 }}>
                  {app.description}
                </div>
              )}
              {app.currentSession?.branchName && (
                <div className="smeta">{app.currentSession.branchName}</div>
              )}
              {!app.currentSession && (
                <div className="smeta" style={{ fontFamily: 'inherit' }}>No session</div>
              )}
            </div>
          ))}
          {apps.length === 0 && !error && (
            <div style={{ padding: '8px', fontSize: 11, color: 'var(--fg-2)' }}>
              No apps found
            </div>
          )}
        </div>
      </aside>

      <div style={{ position: 'relative', height: '100%', minWidth: 0 }}>
        {selectedApp && (
          <button
            type="button"
            className={`ctx-toggle ${contextOpen ? 'active' : ''}`}
            onClick={() => setContextOpen(o => !o)}
            title="Per-app context the AI agents (Builder / Improve / Ask) load on every run"
          >📚 Context</button>
        )}

        {selectedApp ? (
          loadingSession ? (
            <div className="empty"><div>Loading session…</div></div>
          ) : activeAgent ? (
            <ChatPanel
              key={activeAgent.id}
              agent={activeAgent}
              app={selectedApp}
              onSessionUpdate={onSessionUpdate}
            />
          ) : (
            <AppDetail
              app={selectedApp}
              starting={startingSession}
              onStart={() => startSession(selectedApp)}
            />
          )
        ) : (
          <div className="empty">
            <div>Select an application</div>
            <div style={{ fontSize: 11 }}>{apps.length} app(s) loaded</div>
          </div>
        )}

        <AppContextPanel
          slug={selectedApp?.slug ?? null}
          appName={selectedApp?.name ?? ''}
          open={contextOpen && !!selectedApp}
          onClose={() => setContextOpen(false)}
        />
      </div>
    </div>
  )
}

function AppDetail({
  app, starting, onStart,
}: { app: AppCraneApp; starting: boolean; onStart: () => void }) {
  return (
    <main className="chat">
      <header>
        <span className="name">{app.name}</span>
        {app.category && <span className="branch">{app.category}</span>}
        {app.has_claude_credentials && (
          <OAuthBadge expiresAt={app.claude_credentials_expires_at} />
        )}
        <span className={`status-pill ${app.production.health.status === 'healthy' ? 'idle' : app.production.health.status === 'down' ? 'error' : 'paused'}`}>
          prod: {app.production.health.status}
        </span>
      </header>
      <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
        {app.description && (
          <p style={{ margin: 0, color: 'var(--fg-2)', lineHeight: 1.6 }}>{app.description}</p>
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
          <Row label="Slug" value={app.slug} mono />
          {app.github_url && <Row label="GitHub" value={app.github_url} mono />}
          <Row label="Type" value={app.source_type} />
          {app.production.deploy && (
            <Row label="Prod version" value={`${app.production.deploy.version || '—'} (${app.production.deploy.status})`} mono />
          )}
        </div>
        {app.github_url ? (
          <button className="primary" disabled={starting} onClick={onStart} style={{ width: 'fit-content' }}>
            {starting ? 'Starting…' : '+ Start Studio Session'}
          </button>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--waiting)' }}>
            App needs a GitHub URL configured before Studio can be used.
          </div>
        )}
      </div>
    </main>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
      <span style={{ color: 'var(--fg-2)', minWidth: 100 }}>{label}</span>
      <span style={{ fontFamily: mono ? 'monospace' : 'inherit', wordBreak: 'break-all' }}>{value}</span>
    </div>
  )
}
