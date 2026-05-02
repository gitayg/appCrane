import { useState, useEffect, useRef, useCallback } from 'react'
import { adminApi } from '../adminApi'
import { App as StudioApp } from '../App'
import { SkillsTab } from '../components/SkillsTab'

interface Enhancement {
  id: number
  message: string
  status?: string
  app_slug?: string
  user_name?: string
  created_at?: string
  latest_job_id?: number
  latest_job_phase?: string
  latest_job_status?: string
  latest_job_error?: string
  cost_tokens?: number
  cost_usd_cents?: number
  fix_version?: string
  branch_name?: string
  pr_url?: string
  ai_plan?: any
}

interface Job {
  id: number
  phase: string
  status: string
  error?: string
  created_at?: string
  started_at?: string
  finished_at?: string
  duration_ms?: number
  cost_tokens?: number
  cost_usd_cents?: number
  text?: string
  log?: string[]
  branch?: string
}

interface TraceData {
  active: boolean
  trace: Job[]
  ai_log?: string
}

interface AppOption {
  slug: string
  name: string
}

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

const STATUS_LABELS: Record<string, string> = {
  new: 'New',
  selected: 'Selected for Implementation',
  planning: 'Planning…',
  no_changes_needed: 'No changes needed',
  pending_user_review_plan: 'Plan ready',
  plan_approved: 'Approved',
  coding: 'Coding…',
  sandbox_ready: 'Sandbox ready',
  merged: 'Shipped',
  done: 'Done',
  auto_failed: 'Failed',
  in_progress: 'In Progress',
}

const ALL_STATUSES = Object.keys(STATUS_LABELS)

function fmtDate(str?: string): string {
  if (!str) return '—'
  const d = new Date(str)
  return d.toLocaleString(undefined, {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

function fmtMs(ms?: number): string {
  if (ms == null) return ''
  if (ms < 1000) return '<1s'
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  const m = Math.floor(ms / 60000)
  const s = Math.floor((ms % 60000) / 1000)
  return `${m}m ${s}s`
}

function fmtJobTime(str?: string): string {
  if (!str) return ''
  const d = new Date(str)
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function msGap(a?: string, b?: string): number {
  if (!a || !b) return 0
  return Math.abs(new Date(b).getTime() - new Date(a).getTime())
}

function StatusBadge({ status }: { status?: string }) {
  const label = status ? (STATUS_LABELS[status] ?? status) : '—'
  return (
    <span className={`enh-status badge-status s-${status ?? 'new'}`}>{label}</span>
  )
}

function JobTag({ id }: { id: number }) {
  return <span className="job-tag">JOB-{String(id).padStart(4, '0')}</span>
}

function statusIcon(status: string) {
  if (status === 'done' || status === 'success') return <span style={{ color: 'var(--green)' }}>✓</span>
  if (status === 'failed' || status === 'error') return <span style={{ color: 'var(--red)' }}>✗</span>
  if (status === 'running') return <span style={{ color: 'var(--accent)' }}>▶</span>
  return <span style={{ color: 'var(--dim)' }}>·</span>
}

function CostBadge({ tokens, cents }: { tokens?: number; cents?: number }) {
  if (!tokens && !cents) return null
  return (
    <span style={{ fontSize: '.72rem', color: 'var(--dim)', background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 4, padding: '1px 6px', whiteSpace: 'nowrap' }}>
      {tokens ? `${tokens.toLocaleString()}t` : ''}{tokens && cents ? ' ' : ''}{cents ? `$${(cents / 100).toFixed(3)}` : ''}
    </span>
  )
}

type SortKey = 'id' | 'app_slug' | 'user_name' | 'created_at' | 'message' | 'status'
type SortDir = 'asc' | 'desc'

function getHash(): string {
  const h = window.location.hash.replace('#', '')
  // Old hashes (#library, #studio) collapse into the merged Builders view
  if (h === 'library' || h === 'studio' || h === 'builders') return 'builders'
  if (h === 'skills') return 'skills'
  return 'requests'
}

export function AppStudio() {
  const [tab, setTab] = useState<string>(getHash)
  const [allEnhancements, setAllEnhancements] = useState<Enhancement[]>([])
  const [apps, setApps] = useState<AppOption[]>([])
  const [filterApp, setFilterApp] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterText, setFilterText] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('id')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [selected, setSelected] = useState<Enhancement | null>(null)
  const [chatOpen, setChatOpen] = useState(false)
  const [chatApp, setChatApp] = useState('')
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatSending, setChatSending] = useState(false)
  const chatBottomRef = useRef<HTMLDivElement>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [trace, setTrace] = useState<TraceData | null>(null)
  const [openJobs, setOpenJobs] = useState<Set<number>>(new Set())

  useEffect(() => {
    function onHash() { setTab(getHash()) }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const loadData = useCallback(() => {
    return Promise.all([
      adminApi.get<{ requests: Enhancement[] }>('/api/enhancements').catch(() => ({ requests: [] })),
      adminApi.get<{ apps: AppOption[] }>('/api/apps').catch(() => ({ apps: [] })),
    ]).then(([eRes, aRes]) => {
      const sorted = [...(eRes.requests ?? [])].sort((a, b) => b.id - a.id)
      setAllEnhancements(sorted)
      setApps(aRes.apps ?? [])
    })
  }, [])

  useEffect(() => { loadData() }, [loadData])

  const stopPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }, [])

  const fetchTrace = useCallback((id: number) => {
    adminApi.get<TraceData>(`/api/appstudio/${id}/trace`)
      .then(t => {
        setTrace(t)
        const defaultOpen = new Set<number>()
        for (const j of t.trace) {
          if (j.status === 'running' || j.status === 'failed' || j.status === 'error' || j.status === 'queued') {
            defaultOpen.add(j.id)
          }
        }
        setOpenJobs(prev => {
          const merged = new Set(prev)
          defaultOpen.forEach(id => merged.add(id))
          return merged
        })
        if (!t.active) stopPoll()
      })
      .catch(() => {})
  }, [stopPoll])

  const openDetail = useCallback((enh: Enhancement) => {
    stopPoll()
    setSelected(enh)
    setTrace(null)
    setOpenJobs(new Set())
    fetchTrace(enh.id)
    pollRef.current = setInterval(() => fetchTrace(enh.id), 1500)
  }, [fetchTrace, stopPoll])

  useEffect(() => {
    if (trace && !trace.active) stopPoll()
  }, [trace, stopPoll])

  useEffect(() => () => stopPoll(), [stopPoll])

  const backToList = useCallback(() => {
    stopPoll()
    setSelected(null)
    setTrace(null)
    loadData()
  }, [stopPoll, loadData])

  function handleSort(key: SortKey) {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  function thArrow(key: SortKey) {
    if (sortKey !== key) return ''
    return sortDir === 'asc' ? ' ▲' : ' ▼'
  }

  const filtered = allEnhancements.filter(e => {
    if (filterApp && e.app_slug !== filterApp) return false
    if (filterStatus && e.status !== filterStatus) return false
    if (filterText) {
      const q = filterText.toLowerCase()
      if (!e.message?.toLowerCase().includes(q) && !e.user_name?.toLowerCase().includes(q)) return false
    }
    return true
  })

  const sortedFiltered = [...filtered].sort((a, b) => {
    let av: any = a[sortKey as keyof Enhancement]
    let bv: any = b[sortKey as keyof Enhancement]
    if (av == null) av = ''
    if (bv == null) bv = ''
    if (typeof av === 'number' && typeof bv === 'number') {
      return sortDir === 'asc' ? av - bv : bv - av
    }
    return sortDir === 'asc'
      ? String(av).localeCompare(String(bv))
      : String(bv).localeCompare(String(av))
  })

  async function setStatus(id: number, status: string) {
    await adminApi.post(`/api/enhancements/${id}/status`, { status }).catch(() => {})
    setAllEnhancements(prev => prev.map(e => e.id === id ? { ...e, status } : e))
  }

  async function deleteEnhancement(id: number) {
    if (!confirm('Delete this request?')) return
    const res = await adminApi.post<{ error?: { message?: string } }>(`/api/enhancements/${id}/delete`).catch(() => null)
    if (res && res.error) { alert('Delete failed: ' + (res.error.message || 'unknown')); return }
    setAllEnhancements(prev => prev.filter(e => e.id !== id))
  }

  async function sendAction(id: number, path: string, body?: unknown) {
    await adminApi.post(`/api/appstudio/${id}/${path}`, body).catch(() => {})
    loadData()
    if (selected?.id === id) {
      stopPoll()
      fetchTrace(id)
      pollRef.current = setInterval(() => fetchTrace(id), 1500)
    }
  }

  async function deleteJob(jobId: number) {
    if (!confirm('Delete this job?')) return
    await adminApi.del(`/api/appstudio/jobs/${jobId}`).catch(() => {})
    if (selected) fetchTrace(selected.id)
  }

  async function retryJob(jobId: number) {
    try {
      await adminApi.post(`/api/appstudio/jobs/${jobId}/retry`)
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Retry failed')
      return
    }
    if (selected) fetchTrace(selected.id)
  }

  function openChat() {
    setChatMessages([{ role: 'assistant', content: "What would you like to add or improve? Describe it briefly and I'll help you refine it." }])
    setChatInput('')
    setChatApp(apps[0]?.slug ?? '')
    setChatOpen(true)
  }

  async function sendChat() {
    const text = chatInput.trim()
    if (!text || chatSending) return
    const msgs: ChatMessage[] = [...chatMessages, { role: 'user', content: text }]
    setChatMessages(msgs)
    setChatInput('')
    setChatSending(true)
    const r = await adminApi.post<{ reply?: string; message?: string }>('/api/appstudio/chat', {
      app_slug: chatApp,
      messages: msgs,
    }).catch(() => null)
    const reply = r?.reply ?? r?.message ?? ''
    if (reply) setChatMessages(prev => [...prev, { role: 'assistant', content: reply }])
    setChatSending(false)
  }

  async function submitRequest() {
    const lastAi = [...chatMessages].reverse().find(m => m.role === 'assistant')
    if (!lastAi) return
    await adminApi.post('/api/enhancements', { message: lastAi.content, app_slug: chatApp }).catch(() => {})
    setChatOpen(false)
    loadData()
  }

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatMessages])

  function toggleJob(id: number) {
    setOpenJobs(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="container" style={{ maxWidth: 1400 }}>
      {tab === 'requests' && (
        selected ? (
          <DetailView
            enh={selected}
            trace={trace}
            openJobs={openJobs}
            onToggleJob={toggleJob}
            onBack={backToList}
            onAction={sendAction}
            onDeleteJob={deleteJob}
            onRetryJob={retryJob}
          />
        ) : (
          <RequestsTab
            enhancements={sortedFiltered}
            apps={apps}
            filterApp={filterApp}
            filterStatus={filterStatus}
            filterText={filterText}
            sortKey={sortKey}
            sortDir={sortDir}
            onFilterApp={setFilterApp}
            onFilterStatus={setFilterStatus}
            onFilterText={setFilterText}
            onSort={handleSort}
            thArrow={thArrow}
            onSelect={openDetail}
            onSetStatus={setStatus}
            onDelete={deleteEnhancement}
            onNewRequest={openChat}
            total={sortedFiltered.length}
          />
        )
      )}

      {tab === 'builders' && (
        <div style={{ height: 'calc(100vh - 120px)', overflow: 'hidden' }}>
          <StudioApp />
        </div>
      )}

      {tab === 'skills' && <SkillsTab />}

      {chatOpen && (
        <div className="chat-overlay">
          <div className="chat-modal">
            <div className="chat-header">
              <span style={{ fontWeight: 700 }}>New Request</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <select
                  value={chatApp}
                  onChange={e => setChatApp(e.target.value)}
                  style={{ fontSize: '.8rem', padding: '3px 6px' }}
                >
                  {apps.map(a => <option key={a.slug} value={a.slug}>{a.name}</option>)}
                </select>
                <button className="btn btn-xs" onClick={() => setChatOpen(false)}>✕</button>
              </div>
            </div>
            <div className="chat-messages">
              {chatMessages.map((m, i) => (
                <div key={i} className={`chat-bubble ${m.role === 'user' ? 'user' : 'ai'}`}>
                  {m.content}
                </div>
              ))}
              {chatSending && <div className="chat-bubble ai" style={{ color: 'var(--dim)' }}>…</div>}
              <div ref={chatBottomRef} />
            </div>
            <div className="chat-input-row">
              <textarea
                className="chat-input"
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat() }
                }}
                placeholder="Describe your request…"
                rows={2}
              />
              <button className="btn btn-accent btn-sm" onClick={sendChat} disabled={chatSending}>Send</button>
            </div>
            <div className="chat-footer">
              <button className="btn btn-accent btn-sm" onClick={submitRequest}>Submit as Request</button>
              <button className="btn btn-sm" onClick={() => setChatOpen(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

interface RequestsTabProps {
  enhancements: Enhancement[]
  apps: AppOption[]
  filterApp: string
  filterStatus: string
  filterText: string
  sortKey: SortKey
  sortDir: SortDir
  onFilterApp: (v: string) => void
  onFilterStatus: (v: string) => void
  onFilterText: (v: string) => void
  onSort: (k: SortKey) => void
  thArrow: (k: SortKey) => string
  onSelect: (e: Enhancement) => void
  onSetStatus: (id: number, status: string) => void
  onDelete: (id: number) => void
  onNewRequest: () => void
  total: number
}

function RequestsTab({
  enhancements, apps, filterApp, filterStatus, filterText,
  onFilterApp, onFilterStatus, onFilterText,
  onSort, thArrow, onSelect, onSetStatus, onDelete, onNewRequest, total,
}: RequestsTabProps) {
  return (
    <>
      <div className="filter-row">
        <select value={filterApp} onChange={e => onFilterApp(e.target.value)} style={{ fontSize: '.82rem' }}>
          <option value="">All apps</option>
          {apps.map(a => <option key={a.slug} value={a.slug}>{a.name}</option>)}
        </select>
        <select value={filterStatus} onChange={e => onFilterStatus(e.target.value)} style={{ fontSize: '.82rem' }}>
          <option value="">All statuses</option>
          {ALL_STATUSES.map(s => <option key={s} value={s}>{STATUS_LABELS[s]}</option>)}
        </select>
        <input
          type="text"
          value={filterText}
          onChange={e => onFilterText(e.target.value)}
          placeholder="Search…"
          style={{ flex: 1, fontSize: '.82rem' }}
        />
        <span style={{ marginLeft: 'auto', color: 'var(--dim)', fontSize: '.82rem', whiteSpace: 'nowrap' }}>{total} requests</span>
        <button className="btn btn-accent btn-sm" onClick={onNewRequest}>+ New Request</button>
      </div>
      <div className="req-table-wrap">
        <table className="req-table">
          <colgroup>
            <col style={{ width: 70 }} />
            <col style={{ width: 130 }} />
            <col style={{ width: 120 }} />
            <col style={{ width: 160 }} />
            <col style={{ width: 420 }} />
            <col style={{ width: 130 }} />
            <col style={{ width: 120 }} />
            <col style={{ width: 100 }} />
            <col style={{ width: 140 }} />
            <col style={{ width: 44 }} />
          </colgroup>
          <thead>
            <tr>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('id')}>#{ thArrow('id')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('app_slug')}>App{thArrow('app_slug')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('user_name')}>User{thArrow('user_name')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('created_at')}>Date{thArrow('created_at')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('message')}>Message{thArrow('message')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('status')}>Status{thArrow('status')}</th>
              <th>Latest Job</th>
              <th>Cost</th>
              <th>Version / PR</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {enhancements.map(e => (
              <tr
                key={e.id}
                className="clickable"
                onClick={() => onSelect(e)}
              >
                <td style={{ fontFamily: 'monospace', fontSize: '.78rem', color: 'var(--dim)' }}>
                  #{String(e.id).padStart(4, '0')}
                </td>
                <td>
                  {e.app_slug
                    ? <span className="app-pill" style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 7px', fontSize: '.75rem', color: 'var(--dim)' }}>{e.app_slug}</span>
                    : '—'}
                </td>
                <td style={{ fontSize: '.82rem', color: 'var(--dim)' }}>{e.user_name ?? '—'}</td>
                <td style={{ fontSize: '.78rem', color: 'var(--dim)' }}>{fmtDate(e.created_at)}</td>
                <td style={{ fontSize: '.82rem', wordBreak: 'break-word' }}>{e.message}</td>
                <td>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start' }}>
                    <StatusBadge status={e.status} />
                    {e.status === 'new' && (
                      <button
                        className="btn btn-xs btn-accent"
                        onClick={ev => { ev.stopPropagation(); onSetStatus(e.id, 'selected') }}
                      >
                        Start
                      </button>
                    )}
                  </div>
                </td>
                <td>
                  {e.latest_job_id ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <JobTag id={e.latest_job_id} />
                      {e.latest_job_phase && <span style={{ fontSize: '.72rem', color: 'var(--dim)' }}>{e.latest_job_phase}</span>}
                      {e.latest_job_status && (
                        <span style={{
                          fontSize: '.72rem',
                          color: e.latest_job_status === 'done' || e.latest_job_status === 'success' ? 'var(--green)'
                            : e.latest_job_status === 'failed' || e.latest_job_status === 'error' ? 'var(--red)'
                            : e.latest_job_status === 'running' ? 'var(--accent)'
                            : 'var(--dim)',
                        }}>
                          {e.latest_job_status}
                        </span>
                      )}
                    </div>
                  ) : '—'}
                </td>
                <td style={{ fontSize: '.78rem', color: 'var(--dim)' }}>
                  {(e.cost_tokens || e.cost_usd_cents) ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      {e.cost_tokens ? <span>{e.cost_tokens.toLocaleString()}t</span> : null}
                      {e.cost_usd_cents ? <span>${(e.cost_usd_cents / 100).toFixed(3)}</span> : null}
                    </div>
                  ) : '—'}
                </td>
                <td style={{ fontSize: '.78rem' }}>
                  {e.fix_version && (e.status === 'merged' || e.status === 'done') ? (
                    <span style={{ color: 'var(--green)', fontFamily: 'monospace', fontWeight: 700 }}>{e.fix_version}</span>
                  ) : e.pr_url ? (
                    <a href={e.pr_url} target="_blank" rel="noreferrer" onClick={ev => ev.stopPropagation()} style={{ color: 'var(--accent)', fontSize: '.75rem' }}>PR ↗</a>
                  ) : e.branch_name ? (
                    <span style={{ color: 'var(--dim)', fontFamily: 'monospace', fontSize: '.72rem' }}>{e.branch_name}</span>
                  ) : '—'}
                </td>
                <td>
                  <button
                    className="btn btn-xs btn-red"
                    style={{ padding: '2px 7px' }}
                    onClick={ev => { ev.stopPropagation(); onDelete(e.id) }}
                    title="Delete"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
            {enhancements.length === 0 && (
              <tr>
                <td colSpan={10} style={{ color: 'var(--dim)', textAlign: 'center', padding: 24 }}>No requests found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}

interface DetailViewProps {
  enh: Enhancement
  trace: TraceData | null
  openJobs: Set<number>
  onToggleJob: (id: number) => void
  onBack: () => void
  onAction: (id: number, path: string, body?: unknown) => void
  onDeleteJob: (jobId: number) => void
  onRetryJob: (jobId: number) => void
}

function DetailView({ enh, trace, openJobs, onToggleJob, onBack, onAction, onDeleteJob, onRetryJob }: DetailViewProps) {
  const plan = enh.ai_plan

  async function handlePlanFeedback(id: number) {
    const comment = prompt('Describe your requested changes:')
    if (!comment) return
    onAction(id, 'plan-feedback', { comment })
  }

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <button className="btn btn-sm" onClick={onBack}>← Back to list</button>
      </div>
      <div className="detail-panel">
        <div style={{ fontWeight: 700, fontSize: '1.05rem', marginBottom: 10, wordBreak: 'break-word' }}>
          {enh.message.slice(0, 100)}{enh.message.length > 100 ? '…' : ''}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', marginBottom: 14 }}>
          {enh.app_slug && (
            <span style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 8px', fontSize: '.78rem', color: 'var(--dim)' }}>{enh.app_slug}</span>
          )}
          {enh.user_name && <span style={{ color: 'var(--dim)', fontSize: '.82rem' }}>{enh.user_name}</span>}
          <span style={{ color: 'var(--dim)', fontSize: '.78rem' }}>{fmtDate(enh.created_at)}</span>
          <StatusBadge status={enh.status} />
          {(enh.cost_tokens || enh.cost_usd_cents) && (
            <CostBadge tokens={enh.cost_tokens} cents={enh.cost_usd_cents} />
          )}
        </div>

        <div style={{ fontSize: '.88rem', lineHeight: 1.6, color: 'var(--text)', marginBottom: 16, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
          {enh.message}
        </div>

        {plan && (
          <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 7, padding: '12px 16px', marginBottom: 16, fontSize: '.85rem' }}>
            <div style={{ fontWeight: 700, marginBottom: 8, color: 'var(--dim)', fontSize: '.72rem', textTransform: 'uppercase', letterSpacing: '.5px' }}>AI Plan</div>
            {plan.summary && <p style={{ marginBottom: 8, lineHeight: 1.5 }}>{plan.summary}</p>}
            {plan.files_to_change?.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <div style={{ fontWeight: 600, fontSize: '.78rem', marginBottom: 4, color: 'var(--dim)' }}>Files to change</div>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {plan.files_to_change.map((f: string, i: number) => <li key={i} style={{ fontFamily: 'monospace', fontSize: '.78rem', color: 'var(--dim)' }}>{f}</li>)}
                </ul>
              </div>
            )}
            {plan.test_files?.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <div style={{ fontWeight: 600, fontSize: '.78rem', marginBottom: 4, color: 'var(--dim)' }}>Test files</div>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {plan.test_files.map((f: string, i: number) => <li key={i} style={{ fontFamily: 'monospace', fontSize: '.78rem', color: 'var(--dim)' }}>{f}</li>)}
                </ul>
              </div>
            )}
            {plan.risks && <div style={{ marginBottom: 8 }}><span style={{ fontWeight: 600, color: 'var(--dim)', fontSize: '.78rem' }}>Risks: </span>{plan.risks}</div>}
            {plan.test_plan && <div><span style={{ fontWeight: 600, color: 'var(--dim)', fontSize: '.78rem' }}>Test plan: </span>{plan.test_plan}</div>}
          </div>
        )}

        {enh.pr_url && (
          <div style={{ marginBottom: 16 }}>
            <a href={enh.pr_url} target="_blank" rel="noreferrer" className="btn btn-sm">View PR ↗</a>
          </div>
        )}

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {(enh.status === 'new' || enh.status === 'selected') && (
            <button className="btn btn-accent btn-sm" onClick={() => onAction(enh.id, 'plan')}>Plan with AI</button>
          )}
          {enh.status === 'pending_user_review_plan' && (
            <>
              <button className="btn btn-accent btn-sm" onClick={() => onAction(enh.id, 'approve-plan')}>Approve plan + code it</button>
              <button className="btn btn-sm" onClick={() => handlePlanFeedback(enh.id)}>Request changes</button>
            </>
          )}
          {enh.status === 'sandbox_ready' && (
            <button className="btn btn-accent btn-sm" onClick={() => onAction(enh.id, 'approve-sandbox')}>Ship it</button>
          )}
          {enh.status !== 'done' && enh.status !== 'merged' && enh.status !== 'auto_failed' && (
            <button
              className="btn btn-danger btn-sm"
              onClick={() => { if (confirm('Reject this request?')) onAction(enh.id, 'reject') }}
            >
              Reject
            </button>
          )}
        </div>
      </div>

      <div className="trace-panel">
        <div className="trace-heading">
          {trace?.active ? (
            <>
              <span className="trace-pulse" />
              Live trace — job running
            </>
          ) : (
            `Trace — ${trace?.trace?.length ?? 0} jobs`
          )}
        </div>
        {(trace?.trace ?? []).map(job => {
          const isOpen = openJobs.has(job.id)
          const isRunning = job.status === 'running'
          const isFailed = job.status === 'failed' || job.status === 'error'
          const waitMs = job.started_at ? msGap(job.created_at, job.started_at) : null
          const durMs = job.duration_ms ?? (job.started_at && job.finished_at ? msGap(job.started_at, job.finished_at) : null)
          const bodyLines: string[] = []
          if (job.text) bodyLines.push(job.text)
          if (job.log?.length) bodyLines.push(...job.log)
          if (job.branch) bodyLines.push(`branch: ${job.branch}`)
          if (job.error) bodyLines.push(`ERROR: ${job.error}`)
          return (
            <div key={job.id} className="trace-block">
              <div className="trace-block-hdr" onClick={() => onToggleJob(job.id)}>
                <JobTag id={job.id} />
                <span className="trace-phase">{job.phase}</span>
                {statusIcon(job.status)}
                <span style={{ fontSize: '.75rem', fontWeight: 600, color: isFailed ? 'var(--red)' : isRunning ? 'var(--accent)' : 'var(--dim)' }}>
                  {job.status}
                </span>
                {durMs != null && <span className="trace-timing">{fmtMs(durMs)}</span>}
                <CostBadge tokens={job.cost_tokens} cents={job.cost_usd_cents} />
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
                  {isFailed && (
                    <button
                      className="btn btn-xs btn-accent"
                      onClick={e => { e.stopPropagation(); onRetryJob(job.id) }}
                      title="Retry this job"
                    >
                      ↺
                    </button>
                  )}
                  {!isRunning && (
                    <button
                      className="btn btn-xs btn-red"
                      onClick={e => { e.stopPropagation(); onDeleteJob(job.id) }}
                      title="Delete job"
                    >
                      ✕
                    </button>
                  )}
                </div>
              </div>
              {(job.created_at || job.started_at || job.finished_at) && (
                <div style={{ padding: '4px 14px', fontSize: '.72rem', color: 'var(--dim)', display: 'flex', gap: 12, flexWrap: 'wrap', background: 'var(--surface)', borderTop: '1px solid var(--border)' }}>
                  {job.created_at && <span>queued {fmtJobTime(job.created_at)}</span>}
                  {job.started_at && (
                    <span>
                      → started {fmtJobTime(job.started_at)}
                      {waitMs != null && waitMs > 0 && <span style={{ color: 'var(--yellow)', marginLeft: 4 }}>(+{fmtMs(waitMs)} wait)</span>}
                    </span>
                  )}
                  {job.finished_at && (
                    <span>
                      → done {fmtJobTime(job.finished_at)}
                      {durMs != null && <span style={{ color: isFailed ? 'var(--red)' : 'var(--green)', marginLeft: 4 }}>{fmtMs(durMs)}</span>}
                    </span>
                  )}
                </div>
              )}
              {isOpen && bodyLines.length > 0 && (
                <pre className="trace-body">{bodyLines.join('\n')}</pre>
              )}
            </div>
          )
        })}
        {(!trace || trace.trace.length === 0) && (
          <div style={{ padding: '16px 14px', color: 'var(--dim)', fontSize: '.82rem' }}>No jobs yet</div>
        )}
      </div>
    </div>
  )
}

