import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { StatusPill } from './StatusPill'
import { announceTasksChanged } from './useTaskCount'
import { STATUS_LABEL, fmtWhen, safeHref, userLabel, type TaskDetail, type TaskStatus } from './taskTypes'

// One task: its body, thread and history, a reply box, the status moves this
// person may make (from the server's allowed_statuses), and delete for the
// requester. Every string is user text and rendered as React text, never HTML.
export function TaskDetailPanel({ taskId, onClose, onChanged }: {
  taskId: string
  onClose: () => void
  onChanged: () => void
}) {
  const [task, setTask] = useState<TaskDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reply, setReply] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let alive = true
    setTask(null); setError(null)
    adminApi.get<{ task: TaskDetail }>(`/api/tasks/${encodeURIComponent(taskId)}`)
      .then(r => { if (alive) { setTask(r.task); announceTasksChanged() } })
      .catch(e => { if (alive) setError(e instanceof Error ? e.message : 'Failed to load the task') })
    return () => { alive = false }
  }, [taskId])

  async function reload() {
    const r = await adminApi.get<{ task: TaskDetail }>(`/api/tasks/${encodeURIComponent(taskId)}`)
    setTask(r.task)
  }

  async function act(fn: () => Promise<unknown>) {
    setBusy(true); setError(null)
    try {
      await fn()
      await reload()
      onChanged()
      announceTasksChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Action failed')
    } finally {
      setBusy(false)
    }
  }

  const sendReply = () => act(async () => {
    await adminApi.post(`/api/tasks/${encodeURIComponent(taskId)}/comments`, { body: reply })
    setReply('')
  })
  const setStatus = (status: TaskStatus) => act(() => adminApi.patch(`/api/tasks/${encodeURIComponent(taskId)}`, { status }))
  async function remove() {
    if (!confirm('Delete this task? It disappears for you, the assignee and the app.')) return
    setBusy(true)
    try {
      await adminApi.del(`/api/tasks/${encodeURIComponent(taskId)}`)
      onChanged(); announceTasksChanged(); onClose()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Delete failed')
      setBusy(false)
    }
  }

  if (error && !task) {
    return <div className="req-table-wrap" style={{ padding: 16, color: '#fca5a5' }}>{error} <button className="btn btn-sm" onClick={onClose}>Close</button></div>
  }
  if (!task) return <div className="req-table-wrap" style={{ padding: 16, color: 'var(--dim)' }}>Loading...</div>

  const appName = task.app?.name || 'the app'
  const href = safeHref(task.url)
  return (
    <div className="req-table-wrap" style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: '1.05rem', fontWeight: 600, wordBreak: 'break-word' }}>{task.subject}</div>
          <div style={{ color: 'var(--dim)', fontSize: '.8rem', marginTop: 4 }}>
            From <b>{appName}</b>, asked by {userLabel(task.requester)} for {userLabel(task.assignee)} on {fmtWhen(task.created_at, true)}
            {task.due_date && <> - due {task.due_date}</>}
            {task.external_ref && <> - ref {task.external_ref}</>}
          </div>
        </div>
        <StatusPill status={task.status} />
        <button className="btn btn-sm" onClick={onClose} aria-label="Close task">Close</button>
      </div>

      {task.body && <div style={{ marginTop: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '.88rem' }}>{task.body}</div>}
      {href && <div style={{ marginTop: 8 }}><a href={href} target="_blank" rel="noopener noreferrer">Open in {appName}</a></div>}

      <div style={{ marginTop: 16, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
        {task.allowed_statuses.length > 0 && <span style={{ fontSize: '.8rem', color: 'var(--dim)' }}>Move to:</span>}
        {task.allowed_statuses.map(s => (
          <button key={s} className="btn btn-sm" disabled={busy} onClick={() => setStatus(s)}>{STATUS_LABEL[s]}</button>
        ))}
        {task.can_delete && (
          <button className="btn btn-sm btn-red" style={{ marginLeft: 'auto' }} disabled={busy} onClick={remove}>Delete task</button>
        )}
      </div>

      <h4 style={{ margin: '18px 0 8px', fontSize: '.85rem' }}>Thread</h4>
      {task.comments.length === 0 && <div style={{ color: 'var(--dim)', fontSize: '.82rem' }}>No replies yet.</div>}
      {task.comments.map(c => (
        <div key={c.id} style={{ borderLeft: '2px solid var(--border)', padding: '4px 10px', margin: '0 0 10px' }}>
          <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>
            <b style={{ color: 'var(--text)' }}>{userLabel(c.author, appName)}</b>{c.via === 'app' && !c.author ? ' (app)' : ''} - {fmtWhen(c.created_at, true)}
          </div>
          <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '.86rem', marginTop: 2 }}>{c.body}</div>
        </div>
      ))}

      <div style={{ marginTop: 10 }}>
        <textarea
          className="az-input"
          style={{ width: '100%', minHeight: 70, boxSizing: 'border-box' }}
          maxLength={5000}
          placeholder="Write a reply"
          value={reply}
          onChange={e => setReply(e.target.value)}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 6 }}>
          <button className="btn btn-sm btn-accent" disabled={busy || !reply.trim()} onClick={sendReply}>Reply</button>
        </div>
      </div>
      {error && <div style={{ color: '#fca5a5', fontSize: '.82rem', marginTop: 6 }}>{error}</div>}

      <h4 style={{ margin: '14px 0 6px', fontSize: '.85rem' }}>History</h4>
      <ul style={{ margin: 0, paddingLeft: 18, fontSize: '.78rem', color: 'var(--dim)' }}>
        {task.history.map((h, i) => (
          <li key={i}>
            {fmtWhen(h.created_at, true)}: {h.kind === 'created'
              ? `created by ${appName} for ${userLabel(h.actor, appName)}`
              : `${userLabel(h.actor, appName)} moved it from ${h.from_status ? STATUS_LABEL[h.from_status] : '-'} to ${h.to_status ? STATUS_LABEL[h.to_status] : '-'}`}
          </li>
        ))}
      </ul>
    </div>
  )
}
