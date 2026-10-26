import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { adminApi } from '../adminApi'
import { StatusPill } from '../components/tasks/StatusPill'
import { TaskDetailPanel } from '../components/tasks/TaskDetailPanel'
import { fmtWhen, userLabel, type TaskSummary } from '../components/tasks/taskTypes'

// "My tasks": every task an app assigned to me, or created on my behalf,
// across all apps. Backed by /api/tasks (party-only, server-side role rules).
// ?task=<id> opens one task; the notification e-mails link there.

type Box = 'all' | 'assigned' | 'requested'
const STATUS_FILTERS: [string, string][] = [
  ['active', 'Open + in progress'], ['', 'Any status'], ['open', 'Open'], ['in_progress', 'In progress'],
  ['done', 'Done'], ['declined', 'Declined'], ['closed', 'Done + declined'],
]

export function Tasks() {
  const [params, setParams] = useSearchParams()
  const openId = params.get('task')
  const [box, setBox] = useState<Box>('all')
  const [status, setStatus] = useState('active')
  const [app, setApp] = useState('')
  const [tasks, setTasks] = useState<TaskSummary[]>([])
  const [apps, setApps] = useState<{ slug: string; name: string }[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    const q = new URLSearchParams({ box })
    if (status) q.set('status', status)
    if (app) q.set('app', app)
    setError(null)
    adminApi.get<{ tasks: TaskSummary[] }>(`/api/tasks?${q.toString()}`)
      .then(r => setTasks(r.tasks || []))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load your tasks'))
      .finally(() => setLoading(false))
  }, [box, status, app])

  useEffect(() => { load() }, [load])

  // The app filter offers every app I have a task in, whatever the other filters say.
  useEffect(() => {
    adminApi.get<{ tasks: TaskSummary[] }>('/api/tasks?box=all&limit=200')
      .then(r => {
        const seen = new Map<string, string>()
        for (const t of r.tasks || []) if (t.app) seen.set(t.app.slug, t.app.name)
        setApps([...seen].map(([slug, name]) => ({ slug, name })).sort((a, b) => a.name.localeCompare(b.name)))
      })
      .catch(() => {})
  }, [])

  const open = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('task', id); else next.delete('task')
    setParams(next, { replace: !id })
  }

  return (
    <div className="container" style={{ maxWidth: 1200 }}>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', margin: '0 0 14px' }}>
        Tasks apps have assigned to you, and tasks they created on your behalf, across every app.
      </p>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 12, alignItems: 'center' }}>
        {(['all', 'assigned', 'requested'] as Box[]).map(b => (
          <button key={b} className={`btn btn-sm${box === b ? ' btn-accent' : ''}`} onClick={() => setBox(b)}>
            {b === 'all' ? 'All my tasks' : b === 'assigned' ? 'Assigned to me' : 'Requested by me'}
          </button>
        ))}
        <select className="az-input" value={status} onChange={e => setStatus(e.target.value)} aria-label="Status filter">
          {STATUS_FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select className="az-input" value={app} onChange={e => setApp(e.target.value)} aria-label="App filter">
          <option value="">All apps</option>
          {apps.map(a => <option key={a.slug} value={a.slug}>{a.name}</option>)}
        </select>
      </div>

      {openId && (
        <div style={{ marginBottom: 14 }}>
          <TaskDetailPanel taskId={openId} onClose={() => open(null)} onChanged={load} />
        </div>
      )}

      {error && <div className="req-table-wrap" style={{ padding: 16, color: '#fca5a5' }}>{error}</div>}
      {!error && (
        <div className="req-table-wrap">
          <table className="req-table">
            <colgroup>
              <col style={{ width: 110 }} />
              <col />
              <col style={{ width: 140 }} />
              <col style={{ width: 130 }} />
              <col style={{ width: 130 }} />
              <col style={{ width: 110 }} />
              <col style={{ width: 130 }} />
            </colgroup>
            <thead>
              <tr>
                <th>Created</th>
                <th>Subject</th>
                <th>App</th>
                <th>Requested by</th>
                <th>Assigned to</th>
                <th>Status</th>
                <th>Last activity</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map(t => (
                <tr key={t.id} onClick={() => open(t.id)} style={{ cursor: 'pointer', background: t.id === openId ? 'var(--surface2)' : undefined }}>
                  <td style={{ fontSize: '.78rem', color: 'var(--dim)', whiteSpace: 'nowrap' }}>{fmtWhen(t.created_at)}</td>
                  <td style={{ fontSize: '.84rem', wordBreak: 'break-word', fontWeight: t.unread ? 600 : 400 }}>
                    {t.unread && <span title="New activity" style={{ display: 'inline-block', width: 7, height: 7, borderRadius: 4, background: 'var(--accent)', marginRight: 6 }} />}
                    {t.subject}
                  </td>
                  <td style={{ fontSize: '.78rem' }}>{t.app?.name || '-'}</td>
                  <td style={{ fontSize: '.78rem' }}>{t.my_roles?.requester ? 'Me' : userLabel(t.requester)}</td>
                  <td style={{ fontSize: '.78rem' }}>{t.my_roles?.assignee ? 'Me' : userLabel(t.assignee)}</td>
                  <td><StatusPill status={t.status} /></td>
                  <td style={{ fontSize: '.78rem', color: 'var(--dim)', whiteSpace: 'nowrap' }}>{fmtWhen(t.last_activity_at, true)}</td>
                </tr>
              ))}
              {!loading && tasks.length === 0 && (
                <tr><td colSpan={7} style={{ padding: 18, textAlign: 'center', color: 'var(--dim)' }}>No tasks match these filters.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
