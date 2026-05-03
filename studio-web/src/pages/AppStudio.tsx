import { useState, useEffect, useRef, useCallback } from 'react'
import { adminApi } from '../adminApi'
import { App as StudioApp } from '../App'

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
  ai_plan?: any
  pr_url?: string | null
  branch_name?: string | null
  fix_version?: string | null
  comments?: Comment[]
  open_comment_count?: number
}

export interface Comment {
  id: number
  type: 'bug' | 'note' | 'review'
  body: string
  status: 'open' | 'resolved'
  author_user_id: number | null
  author_name: string | null
  created_at: string
  resolved_at: string | null
  resolved_by: number | null
}

interface AppOption {
  slug: string
  name: string
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
  if (h === 'skills')   return 'skills'
  if (h === 'branding') return 'branding'
  return 'requests'
}

interface AppStudioProps {
  /** When set, locks the tab and ignores hash changes. Used by the
   *  /requests and /builders routes after the AppStudio nav level was
   *  collapsed in v1.27.38. */
  tab?: string
}

export function AppStudio({ tab: forcedTab }: AppStudioProps = {}) {
  const [tab, setTab] = useState<string>(forcedTab ?? getHash())
  const [allEnhancements, setAllEnhancements] = useState<Enhancement[]>([])
  const [apps, setApps] = useState<AppOption[]>([])
  const [filterApp, setFilterApp] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterText, setFilterText] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('id')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [selected, setSelected] = useState<Enhancement | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [trace, setTrace] = useState<TraceData | null>(null)

  useEffect(() => {
    if (forcedTab) { setTab(forcedTab); return }
    function onHash() { setTab(getHash()) }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [forcedTab])

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
        if (!t.active) stopPoll()
      })
      .catch(() => {})
  }, [stopPoll])

  const openDetail = useCallback((enh: Enhancement) => {
    stopPoll()
    setSelected(enh)
    setTrace(null)
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

  return (
    <div className="container" style={{ maxWidth: 1400 }}>
      {tab === 'requests' && (
        selected ? (
          <DetailView
            enh={selected}
            trace={trace}
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
            total={sortedFiltered.length}
          />
        )
      )}

      {tab === 'builders' && (
        <div style={{ height: 'calc(100vh - 120px)', overflow: 'hidden' }}>
          <StudioApp />
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
  total: number
}

function RequestsTab({
  enhancements, apps, filterApp, filterStatus, filterText,
  onFilterApp, onFilterStatus, onFilterText,
  onSort, thArrow, onSelect, onSetStatus, onDelete, total,
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
  onBack: () => void
  onAction: (id: number, path: string, body?: unknown) => void
  onDeleteJob: (jobId: number) => void
  onRetryJob: (jobId: number) => void
}

function DetailView({ enh, trace, onBack, onAction, onDeleteJob, onRetryJob }: DetailViewProps) {
  function onRedo() {
    const resetBranch = confirm(
      `Redo "${enh.message.slice(0, 60)}${enh.message.length > 60 ? '…' : ''}"?\n\n` +
      `Wipes the current plan + comments and queues a fresh plan job.\n\n` +
      `Click OK to keep the existing branch (the next coder run continues on top).\n` +
      `Click Cancel to abort. To also reset the branch to a fresh one, use the "Redo + reset branch" option from a follow-up.`,
    )
    if (!resetBranch) return
    onAction(enh.id, 'redo')
  }
  function onRedoReset() {
    if (!confirm(`Redo + RESET BRANCH for "${enh.message.slice(0, 60)}${enh.message.length > 60 ? '…' : ''}"?\n\nClears the linked branch_name so the next coder run starts on a fresh branch. Existing remote branch (and any open PR) is left alone.`)) return
    onAction(enh.id, 'redo', { reset_branch: true })
  }
  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className="btn btn-sm" onClick={onBack}>← Back to list</button>
        <button
          className="btn btn-sm"
          onClick={onRedo}
          title="Re-run from scratch — wipes plan + comments, queues fresh plan job. Keeps the existing branch."
        >🔁 Redo</button>
        <button
          className="btn btn-sm"
          onClick={onRedoReset}
          title="Redo AND clear branch_name so coder starts on a fresh branch (existing remote branch / PR untouched)."
        >🔁 Redo + reset branch</button>
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

        {/* Inline hint for merge conflicts on the open_pr phase — points
            the user at the right action instead of leaving them staring
            at "Pull Request has merge conflicts" with no next step. */}
        {(() => {
          const openPrJobs = (trace?.trace || []).filter(j => j.phase === 'open_pr')
          const failedConflict = openPrJobs.find(j => j.status === 'failed' && /merge conflict/i.test(j.error || ''))
          if (!failedConflict) return null
          return (
            <div style={{
              background: 'rgba(239, 68, 68, .1)', border: '1px solid rgba(239, 68, 68, .3)',
              borderRadius: 6, padding: '10px 14px', marginBottom: 14, fontSize: '.85rem', lineHeight: 1.5,
            }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>⚠️ Merge conflict</div>
              <div style={{ color: 'var(--dim)' }}>
                <code>main</code> moved while this branch was being coded — GitHub can't auto-merge.
                Click <strong>🔁 Redo + reset branch</strong> above to re-plan + re-code against the
                current <code>main</code> on a fresh branch (sidesteps the conflict). Or rebase the
                existing PR locally and click <strong>Ship it</strong> on the Build tab to retry.
              </div>
            </div>
          )
        })()}

        <PhaseTabs
          enh={enh}
          trace={trace}
          onAction={onAction}
          onRetryJob={onRetryJob}
          onDeleteJob={onDeleteJob}
        />
      </div>

    </div>
  )
}

// ── Phase tabs ─────────────────────────────────────────────────────
//
// Tabs follow the enhancement lifecycle: Request → Plan → (Revise plan) →
// Code → Build → Open PR. Each tab corresponds to a phase the worker
// emits in enhancement_jobs.phase, except 'request' which is the initial
// submission itself. 'revise_plan' is hidden when no revise jobs exist.
//
// Each tab carries a state badge driven by the latest job for that
// phase. The next-up tab (first 'idle' one after the current activity)
// gets an accent ring so the operator always sees what's coming.
//
// Default tab on open is status-driven: jump to whichever tab needs
// operator action (pending review → Plan, sandbox ready → Build, etc).

type Phase = 'request' | 'plan' | 'code' | 'build' | 'open_pr' | 'feedback'

// Feedback is at the end — it's not a lifecycle phase, it's a thread
// the operator can interact with at any point. Keeping it last so it
// reads as "review / comment after seeing the work" but accessible
// from the start.
const PHASE_ORDER: Phase[] = ['request', 'plan', 'code', 'build', 'open_pr', 'feedback']
const PHASE_LABELS: Record<Phase, string> = {
  request:  'Request',
  plan:     'Plan',
  code:     'Code',
  build:    'Build',
  open_pr:  'Open PR',
  feedback: 'Feedback',
}

interface PhaseTabsProps {
  enh: Enhancement
  trace: TraceData | null
  onAction: (id: number, path: string, body?: unknown) => void
  onRetryJob: (jobId: number) => void
  onDeleteJob: (jobId: number) => void
}

type TabState = 'idle' | 'queued' | 'running' | 'done' | 'failed'

function jobsForPhase(trace: TraceData | null, phase: string): Job[] {
  if (!trace?.trace) return []
  return trace.trace.filter(j => j.phase === phase)
}

function tabState(jobs: Job[]): TabState {
  if (!jobs.length) return 'idle'
  const latest = jobs[jobs.length - 1]
  if (latest.status === 'running') return 'running'
  if (latest.status === 'queued')  return 'queued'
  if (latest.status === 'failed' || latest.status === 'error') return 'failed'
  return 'done'
}

function defaultTabFor(enh: Enhancement, trace: TraceData | null): Phase {
  // Status-driven: jump straight to the tab that needs operator action.
  switch (enh.status) {
    case 'pending_user_review_plan': return 'plan'
    case 'sandbox_ready':            return 'build'
    case 'merged': case 'done':      return 'open_pr'
  }
  // Otherwise: latest active phase, falling back to Request.
  const jobs = trace?.trace ?? []
  for (let i = jobs.length - 1; i >= 0; i--) {
    const p = jobs[i].phase as Phase
    if (PHASE_ORDER.includes(p)) return p
  }
  return 'request'
}

function PhaseTabs({ enh, trace, onAction, onRetryJob, onDeleteJob }: PhaseTabsProps) {
  // The Plan tab merges 'plan' + 'revise_plan' jobs (revisions are still
  // planning) so the operator sees the full iteration history in one place.
  const planJobs = [...jobsForPhase(trace, 'plan'), ...jobsForPhase(trace, 'revise_plan')]
    .sort((a, b) => a.id - b.id)
  // Feedback's "state" tracks open-comment count: idle when nothing's
  // open, queued when there are open items waiting on the agent. We
  // never mark it done/failed — it's not a phase the worker drives.
  const openComments = trace?.open_comment_count ?? 0
  const states: Record<Phase, TabState> = {
    // Request is "done" the moment the row exists.
    request:  'done',
    plan:     tabState(planJobs),
    code:     tabState(jobsForPhase(trace, 'code')),
    build:    tabState(jobsForPhase(trace, 'build')),
    open_pr:  tabState(jobsForPhase(trace, 'open_pr')),
    feedback: openComments > 0 ? 'queued' : 'idle',
  }
  const visibleTabs = PHASE_ORDER

  // First idle tab = the next up. Used to draw the accent ring.
  const nextUp = visibleTabs.find(p => states[p] === 'idle') ?? null

  const [active, setActive] = useState<Phase>(() => defaultTabFor(enh, trace))
  // Re-sync default when the enhancement changes (e.g. parent flipped to a
  // different request). Don't fight the user once they've clicked a tab.
  const enhId = enh.id
  const sawEnhId = useRef<number>(enhId)
  useEffect(() => {
    if (sawEnhId.current !== enhId) {
      sawEnhId.current = enhId
      setActive(defaultTabFor(enh, trace))
    }
  }, [enhId, enh, trace])

  return (
    <div className="phase-tabs">
      <div className="phase-tab-strip" role="tablist">
        {visibleTabs.map(p => {
          const s = states[p]
          const isActive = p === active
          const isNext = p === nextUp && s === 'idle'
          return (
            <button
              key={p}
              type="button"
              role="tab"
              aria-selected={isActive}
              className={`phase-tab phase-tab-${s}${isActive ? ' active' : ''}${isNext ? ' next-up' : ''}`}
              onClick={() => setActive(p)}
            >
              <span className="phase-tab-label">
                {PHASE_LABELS[p]}
                {p === 'feedback' && openComments > 0 && (
                  <span className="phase-tab-count">({openComments} open)</span>
                )}
              </span>
              <span className={`phase-tab-dot phase-tab-dot-${s}`} aria-hidden="true" />
            </button>
          )
        })}
      </div>
      <div className="phase-tab-content" role="tabpanel">
        {active === 'request' && <RequestPane enh={enh} onAction={onAction} />}
        {active === 'plan'    && <PlanPane    enh={enh} trace={trace} jobs={planJobs}
                                               onAction={onAction}
                                               onRetryJob={onRetryJob} onDeleteJob={onDeleteJob} />}
        {active === 'code'    && <PhaseLogPane phase="code"
                                               jobs={jobsForPhase(trace, 'code')}
                                               onRetryJob={onRetryJob} onDeleteJob={onDeleteJob}
                                               emptyHint="Coding hasn't started yet — approve the plan to kick it off." />}
        {active === 'build'   && <BuildPane   enh={enh} jobs={jobsForPhase(trace, 'build')}
                                               onAction={onAction} onRetryJob={onRetryJob} onDeleteJob={onDeleteJob} />}
        {active === 'open_pr' && <OpenPrPane  enh={enh} trace={trace} jobs={jobsForPhase(trace, 'open_pr')}
                                               onRetryJob={onRetryJob} onDeleteJob={onDeleteJob} />}
        {active === 'feedback' && <FeedbackPane enh={enh} trace={trace} onAction={onAction} />}
      </div>
    </div>
  )
}

// ── Tab pane components ──────────────────────────────────────────

function RequestPane({ enh, onAction }: { enh: Enhancement; onAction: PhaseTabsProps['onAction'] }) {
  const canPlan = enh.status === 'new' || enh.status === 'selected'
  const canReject = enh.status !== 'done' && enh.status !== 'merged' && enh.status !== 'auto_failed'
  return (
    <>
      <div className="pane-text">{enh.message}</div>
      <div className="pane-actions">
        {canPlan && (
          <button className="btn btn-accent btn-sm" onClick={() => onAction(enh.id, 'plan')}>Plan with AI</button>
        )}
        {canReject && (
          <button
            className="btn btn-danger btn-sm"
            onClick={() => { if (confirm('Reject this request?')) onAction(enh.id, 'reject') }}
          >Reject</button>
        )}
      </div>
    </>
  )
}

// States where a plan is rendered but approval is no longer relevant —
// either already approved or the workflow moved past it.
const PLAN_APPROVE_HIDDEN_STATES = new Set([
  'plan_approved', 'coding', 'sandbox_ready', 'pr_opened', 'pr_merged',
  'merged', 'shipped', 'closed', 'failed', 'auto_failed',
])

function PlanPane({ enh, trace, jobs, onAction, onRetryJob, onDeleteJob }: {
  enh: Enhancement; trace: TraceData | null; jobs: Job[];
  onAction: PhaseTabsProps['onAction']; onRetryJob: (id: number) => void; onDeleteJob: (id: number) => void;
}) {
  // Trace endpoint includes the parsed plan so we don't need a second
  // fetch. Fall back to enh.ai_plan in case the trace hasn't loaded yet.
  const plan = trace?.ai_plan ?? enh.ai_plan
  const reviseCount = jobs.filter(j => j.phase === 'revise_plan').length
  return (
    <>
      {plan ? (
        <div className="pane-card">
          <div className="pane-section-hdr" style={{ marginBottom: 8, fontSize: '.7rem', textTransform: 'uppercase', letterSpacing: '.5px' }}>
            Current plan{reviseCount > 0 ? ` — revised ${reviseCount}× from feedback below` : ''}
          </div>
          {plan.summary && <p style={{ marginBottom: 10, lineHeight: 1.55 }}>{plan.summary}</p>}
          {plan.files_to_change?.length > 0 && (
            <div className="pane-section">
              <div className="pane-section-hdr">Files to change</div>
              <ul className="pane-list">
                {plan.files_to_change.map((f: any, i: number) => (
                  <li key={i}>{typeof f === 'string' ? f : `${f.path ?? ''} (${f.action ?? '?'})${f.rationale ? ` — ${f.rationale}` : ''}`}</li>
                ))}
              </ul>
            </div>
          )}
          {plan.test_files?.length > 0 && (
            <div className="pane-section">
              <div className="pane-section-hdr">Test files</div>
              <ul className="pane-list">
                {plan.test_files.map((f: any, i: number) => (
                  <li key={i}>{typeof f === 'string' ? f : `${f.path ?? ''} (${f.action ?? '?'})${f.what ? ` — ${f.what}` : ''}`}</li>
                ))}
              </ul>
            </div>
          )}
          {plan.risks && (
            <div className="pane-section"><span className="pane-section-hdr">Risks: </span>{plan.risks}</div>
          )}
          {plan.test_plan && (
            <div className="pane-section"><span className="pane-section-hdr">Test plan: </span>{plan.test_plan}</div>
          )}
        </div>
      ) : (
        <div className="pane-empty">No plan yet — click <em>Plan with AI</em> on the Request tab.</div>
      )}

      {jobs.length > 0 && (
        <div>
          <div className="pane-section-hdr" style={{ marginBottom: 6 }}>
            Iteration history ({jobs.length} {jobs.length === 1 ? 'run' : 'runs'})
          </div>
          <ExpandedJobsTrace jobs={jobs} onRetryJob={onRetryJob} onDeleteJob={onDeleteJob} />
        </div>
      )}

      {/* Approve gate: show whenever a plan exists AND the workflow
          hasn't moved past the plan phase. Previously gated only on
          'pending_user_review_plan' which hid the button when the
          status was 'planning' (a re-plan is in flight) or 'selected'
          (a non-admin user built it but admin still needs to approve). */}
      {plan && !PLAN_APPROVE_HIDDEN_STATES.has(enh.status || '') && (
        <div className="pane-actions">
          <button className="btn btn-accent btn-sm" onClick={() => onAction(enh.id, 'approve-plan')}>Approve plan + code it</button>
          <button
            className="btn btn-sm"
            onClick={() => {
              const comment = prompt('Describe your requested changes:')
              if (comment) onAction(enh.id, 'plan-feedback', { comment })
            }}
          >Request changes</button>
        </div>
      )}
      {plan && PLAN_APPROVE_HIDDEN_STATES.has(enh.status || '') && (
        <div className="pane-empty" style={{ marginTop: 12, fontSize: '.78rem' }}>
          Plan already past approval — current status: <strong>{enh.status}</strong>.
          Watch the Code / Build / Open PR tabs for progress.
        </div>
      )}
    </>
  )
}

function PhaseLogPane({ jobs, onRetryJob, onDeleteJob, emptyHint }: {
  phase: Phase; jobs: Job[];
  onRetryJob: (id: number) => void; onDeleteJob: (id: number) => void;
  emptyHint: string;
}) {
  if (!jobs.length) return <div className="pane-empty">{emptyHint}</div>
  return <ExpandedJobsTrace jobs={jobs} onRetryJob={onRetryJob} onDeleteJob={onDeleteJob} />
}

function BuildPane({ enh, jobs, onAction, onRetryJob, onDeleteJob }: {
  enh: Enhancement; jobs: Job[];
  onAction: PhaseTabsProps['onAction']; onRetryJob: (id: number) => void; onDeleteJob: (id: number) => void;
}) {
  return (
    <>
      {jobs.length === 0
        ? <div className="pane-empty">Build hasn't started — happens automatically after Code completes.</div>
        : <ExpandedJobsTrace jobs={jobs} onRetryJob={onRetryJob} onDeleteJob={onDeleteJob} />
      }
      {enh.status === 'sandbox_ready' && (
        <div className="pane-actions">
          <button className="btn btn-accent btn-sm" onClick={() => onAction(enh.id, 'approve-sandbox')}>Ship it</button>
        </div>
      )}
    </>
  )
}

function OpenPrPane({ enh, trace, jobs, onRetryJob, onDeleteJob }: {
  enh: Enhancement; trace: TraceData | null; jobs: Job[];
  onRetryJob: (id: number) => void; onDeleteJob: (id: number) => void;
}) {
  // Trace returns these too — prefer it (fresher than the row from the list).
  const prUrl       = trace?.pr_url       ?? enh.pr_url
  const branchName  = trace?.branch_name  ?? enh.branch_name
  const fixVersion  = trace?.fix_version  ?? enh.fix_version
  return (
    <>
      {prUrl && (
        <div className="pane-actions" style={{ marginBottom: 12 }}>
          <a href={prUrl} target="_blank" rel="noreferrer" className="btn btn-sm">View PR ↗</a>
          {fixVersion && <span style={{ marginLeft: 8, color: 'var(--dim)', fontSize: '.82rem' }}>fix version: <code>{fixVersion}</code></span>}
          {branchName && <span style={{ marginLeft: 8, color: 'var(--dim)', fontSize: '.82rem' }}>branch: <code>{branchName}</code></span>}
        </div>
      )}
      {jobs.length === 0
        ? <div className="pane-empty">No PR opened yet — runs after Build succeeds (auto-mode) or after manual approval.</div>
        : <ExpandedJobsTrace jobs={jobs} onRetryJob={onRetryJob} onDeleteJob={onDeleteJob} />
      }
    </>
  )
}

// Always-expanded variant of JobsTrace — no click-to-expand, log/text
// always visible. Used in the Plan tab so the operator can read the
// plan + every revision iteration without clicking through.
function ExpandedJobsTrace({ jobs, onRetryJob, onDeleteJob }: {
  jobs: Job[];
  onRetryJob: (id: number) => void; onDeleteJob: (id: number) => void;
}) {
  return (
    <>
      {jobs.map(job => {
        const isRunning = job.status === 'running'
        const isFailed = job.status === 'failed' || job.status === 'error'
        const waitMs = job.started_at ? msGap(job.created_at, job.started_at) : null
        const durMs = job.duration_ms ?? (job.started_at && job.finished_at ? msGap(job.started_at, job.finished_at) : null)
        const bodyLines: string[] = []
        if (job.text) bodyLines.push(job.text)
        if (job.log?.length) bodyLines.push(...job.log)
        if (job.branch) bodyLines.push(`branch: ${job.branch}`)
        if (job.error) bodyLines.push(`ERROR: ${job.error}`)
        const isRevise = job.phase === 'revise_plan'
        return (
          <div key={job.id} className="trace-block" style={{ marginBottom: 10 }}>
            <div className="trace-block-hdr" style={{ cursor: 'default' }}>
              <JobTag id={job.id} />
              <span className="trace-phase">{isRevise ? 'revise' : job.phase}</span>
              {statusIcon(job.status)}
              <span style={{ fontSize: '.75rem', fontWeight: 600, color: isFailed ? 'var(--red)' : isRunning ? 'var(--accent)' : 'var(--dim)' }}>
                {job.status}
              </span>
              {durMs != null && <span className="trace-timing">{fmtMs(durMs)}</span>}
              <CostBadge tokens={job.cost_tokens} cents={job.cost_usd_cents} />
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
                {isFailed && (
                  <button className="btn btn-xs btn-accent" onClick={() => onRetryJob(job.id)} title="Retry this job">↺</button>
                )}
                {!isRunning && (
                  <button className="btn btn-xs btn-red" onClick={() => onDeleteJob(job.id)} title="Delete job">✕</button>
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
            {bodyLines.length > 0 && (
              <pre className="trace-body">{bodyLines.join('\n')}</pre>
            )}
          </div>
        )
      })}
    </>
  )
}

// ── Feedback pane: bugs / notes / reviews thread ───────────────

const COMMENT_TYPE_META: Record<Comment['type'], { icon: string; label: string }> = {
  bug:    { icon: '🐛', label: 'Bug' },
  note:   { icon: '📝', label: 'Note' },
  review: { icon: '👀', label: 'Review' },
}

function FeedbackPane({ enh, trace, onAction }: {
  enh: Enhancement; trace: TraceData | null;
  onAction: PhaseTabsProps['onAction'];
}) {
  // Comments come from the trace endpoint (which polls every 1.5s) so the
  // list stays fresh without an extra fetch loop here. The mutating
  // actions below hit the API; the next trace poll picks up the change.
  const comments: Comment[] = trace?.comments ?? []
  const [type, setType]   = useState<Comment['type']>('bug')
  const [body, setBody]   = useState('')
  const [busy, setBusy]   = useState(false)
  const [error, setError] = useState<string | null>(null)

  const isTerminal = enh.status === 'done' || enh.status === 'merged' || enh.status === 'auto_failed'
  const openComments = comments.filter(c => c.status === 'open')

  async function submit() {
    const trimmed = body.trim()
    if (!trimmed || busy) return
    setBusy(true); setError(null)
    try {
      await adminApi.post(`/api/enhancements/${enh.id}/comments`, { type, body: trimmed })
      setBody('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function toggleStatus(c: Comment) {
    const next = c.status === 'open' ? 'resolved' : 'open'
    try {
      await fetch(`/api/enhancements/${enh.id}/comments/${c.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...adminApi.authHeaders() },
        body: JSON.stringify({ status: next }),
      })
    } catch (_) {}
  }

  async function remove(c: Comment) {
    if (!confirm('Delete this comment?')) return
    try {
      await adminApi.del(`/api/enhancements/${enh.id}/comments/${c.id}`)
    } catch (_) {}
  }

  return (
    <>
      {/* Banner: re-trigger pipeline when terminal status + open feedback */}
      {isTerminal && openComments.length > 0 && (
        <div className="pane-card" style={{ background: 'rgba(245,158,11,.12)', borderColor: '#f59e0b' }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>This request is {enh.status}, but {openComments.length} feedback item{openComments.length === 1 ? '' : 's'} {openComments.length === 1 ? 'is' : 'are'} still open.</div>
          <div style={{ fontSize: '.82rem', color: 'var(--dim)', marginBottom: 8 }}>
            Re-run the pipeline to address them. The planner will see the open items and incorporate them into a new plan.
          </div>
          <button
            className="btn btn-accent btn-sm"
            onClick={() => onAction(enh.id, 'plan')}
          >Re-plan with open feedback</button>
        </div>
      )}

      {/* Add form */}
      <div className="pane-card">
        <div className="pane-section-hdr" style={{ marginBottom: 8 }}>Add feedback</div>
        <div style={{ display: 'flex', gap: 12, marginBottom: 8, flexWrap: 'wrap' }}>
          {(['bug', 'note', 'review'] as Comment['type'][]).map(t => (
            <label key={t} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: '.82rem', cursor: 'pointer' }}>
              <input type="radio" checked={type === t} onChange={() => setType(t)} />
              {COMMENT_TYPE_META[t].icon} {COMMENT_TYPE_META[t].label}
            </label>
          ))}
        </div>
        <textarea
          value={body}
          onChange={e => setBody(e.target.value)}
          placeholder={
            type === 'bug'    ? 'What broke? What did you expect vs see?'
          : type === 'review' ? 'Your assessment — what works, what to change'
          :                     'Anything the agent should know on the next run'
          }
          rows={3}
          disabled={busy}
          style={{ width: '100%', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: 8, color: 'var(--text)', fontFamily: 'inherit', fontSize: '.85rem', resize: 'vertical' }}
        />
        {error && <div style={{ color: 'var(--red)', fontSize: '.78rem', marginTop: 6 }}>{error}</div>}
        <div className="pane-actions" style={{ marginTop: 8 }}>
          <button className="btn btn-accent btn-sm" onClick={submit} disabled={busy || !body.trim()}>
            {busy ? 'Adding…' : `Add ${COMMENT_TYPE_META[type].label.toLowerCase()}`}
          </button>
        </div>
      </div>

      {/* Thread */}
      {comments.length === 0
        ? <div className="pane-empty">No feedback yet.</div>
        : <div>
            <div className="pane-section-hdr" style={{ marginBottom: 8 }}>
              Thread ({comments.length}, {openComments.length} open)
            </div>
            {comments.map(c => (
              <div
                key={c.id}
                style={{
                  border: '1px solid var(--border)', borderRadius: 7, padding: '10px 12px',
                  marginBottom: 8, background: c.status === 'resolved' ? 'var(--surface)' : 'var(--surface2)',
                  opacity: c.status === 'resolved' ? 0.7 : 1,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, fontSize: '.78rem', marginBottom: 6, flexWrap: 'wrap' }}>
                  <span>{COMMENT_TYPE_META[c.type].icon} <strong>{COMMENT_TYPE_META[c.type].label}</strong></span>
                  {c.author_name && <span style={{ color: 'var(--dim)' }}>{c.author_name}</span>}
                  <span style={{ color: 'var(--dim)' }}>{fmtDate(c.created_at)}</span>
                  {c.status === 'resolved' && (
                    <span style={{ color: 'var(--green)', fontWeight: 600 }}>✓ resolved</span>
                  )}
                  <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
                    <button className="btn btn-xs" onClick={() => toggleStatus(c)}>
                      {c.status === 'open' ? 'Resolve' : 'Reopen'}
                    </button>
                    <button className="btn btn-xs btn-red" onClick={() => remove(c)}>✕</button>
                  </div>
                </div>
                <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '.85rem', lineHeight: 1.55 }}>{c.body}</div>
              </div>
            ))}
          </div>
      }
    </>
  )
}


