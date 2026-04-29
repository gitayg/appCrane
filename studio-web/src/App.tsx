import { useEffect, useState } from 'react'
import { api } from './api'
import type { Agent } from './types'
import { ChatPanel } from './components/ChatPanel'

export function App() {
  const [sessions, setSessions] = useState<Agent[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [newSlug, setNewSlug] = useState('')
  const [creating, setCreating] = useState(false)

  const load = () => api.listAgents().then(setSessions).catch((e) => setError(String(e)))

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  const selected = sessions.find((s) => s.id === selectedId) ?? null

  const startSession = async () => {
    const slug = newSlug.trim()
    if (!slug) return
    setCreating(true)
    setError(null)
    try {
      const agent = await api.createAgent(slug)
      setSessions((prev) => [agent, ...prev])
      setSelectedId(agent.id)
      setNewSlug('')
    } catch (e) {
      setError(String(e))
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>Studio Sessions</h2>
        </div>
        {error && (
          <div style={{ padding: '6px 10px', fontSize: 11, color: 'var(--danger)' }}>{error}</div>
        )}
        <div className="sidebar-list">
          {sessions.map((s) => (
            <div
              key={s.id}
              className={`session-item ${selectedId === s.id ? 'selected' : ''}`}
              onClick={() => setSelectedId(s.id)}
            >
              <div className="sname">
                {s.name}
                <span className={`sbadge ${s.sessionStatus || 'idle'}`}>
                  {s.sessionStatus || 'idle'}
                </span>
              </div>
              {s.branchName && <div className="smeta">{s.branchName}</div>}
            </div>
          ))}
          {sessions.length === 0 && (
            <div style={{ padding: '8px', fontSize: 11, color: 'var(--fg-2)' }}>
              No active sessions
            </div>
          )}
        </div>
        <div className="new-session-form">
          <input
            value={newSlug}
            placeholder="App slug…"
            onChange={(e) => setNewSlug(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && startSession()}
          />
          <button
            className="primary"
            disabled={!newSlug.trim() || creating}
            onClick={startSession}
          >
            {creating ? 'Starting…' : '+ New Session'}
          </button>
        </div>
      </aside>

      {selected ? (
        <ChatPanel
          key={selected.id}
          agent={selected}
          onSessionUpdate={(updated) =>
            setSessions((prev) => prev.map((s) => (s.id === updated.id ? updated : s)))
          }
        />
      ) : (
        <div className="empty">
          <div>Select a session or start a new one</div>
          <div style={{ fontSize: 11 }}>{sessions.length} session(s) loaded</div>
        </div>
      )}
    </div>
  )
}
