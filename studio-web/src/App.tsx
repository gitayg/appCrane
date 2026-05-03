import { useEffect, useState, useCallback } from 'react'
import { api } from './api'
import type { Agent, AppCraneApp } from './types'
import { ChatPanel } from './components/ChatPanel'
import { AppContextPanel } from './components/AppContextPanel'

function HealthDot({ status }: { status: string }) {
  const color = status === 'healthy' ? 'var(--working)' : status === 'down' ? 'var(--danger)' : 'var(--fg-2)'
  return <span style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: color, marginRight: 4, verticalAlign: 'middle' }} />
}

export function App() {
  const [apps, setApps] = useState<AppCraneApp[]>([])
  const [selectedSlug, setSelectedSlug] = useState<string | null>(null)
  const [activeAgent, setActiveAgent] = useState<Agent | null>(null)
  const [loadingSession, setLoadingSession] = useState(false)
  const [startingSession, setStartingSession] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [contextOpen, setContextOpen] = useState(false)

  const loadApps = useCallback(() => {
    return api.listApps().then(setApps).catch((e) => setError(String(e)))
  }, [])

  useEffect(() => {
    loadApps()
    const t = setInterval(loadApps, 8000)
    return () => clearInterval(t)
  }, [loadApps])

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
                  <span
                    className="sbadge"
                    style={{ background: 'var(--accent, #6366f1)', color: '#fff' }}
                    title="OAuth — this app uses its own Claude credentials.json. AI work bills against the operator's subscription, not the global ANTHROPIC_API_KEY."
                  >🔑 OAuth</span>
                )}
                {app.currentSession && (
                  <span className={`sbadge ${app.currentSession.status}`}>
                    {app.currentSession.status}
                  </span>
                )}
              </div>
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
          <span
            className="status-pill idle"
            style={{ background: 'var(--accent, #6366f1)', color: '#fff' }}
            title="OAuth — this app uses its own Claude credentials.json"
          >🔑 OAuth</span>
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
