import { useState, useEffect, useCallback } from 'react'
import { adminApi } from '../adminApi'

type Bucket = 'triage' | 'in_progress' | 'shipped' | 'validated'

interface Enhancement {
  id: number
  message: string
  status?: string
  bucket?: Bucket
  validated_at?: string | null
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

const BUCKET_LABELS: Record<Bucket, string> = {
  triage:      'Triage',
  in_progress: 'In Progress',
  shipped:     'Shipped',
  validated:   'Validated',
}

const BUCKET_COLORS: Record<Bucket, { bg: string; fg: string; border: string }> = {
  triage:      { bg: '#3b82f618', fg: '#3b82f6', border: '#3b82f644' },
  in_progress: { bg: '#f59e0b18', fg: '#f59e0b', border: '#f59e0b44' },
  shipped:     { bg: '#22c55e18', fg: '#22c55e', border: '#22c55e44' },
  validated:   { bg: '#a78bfa18', fg: '#a78bfa', border: '#a78bfa44' },
}

const BUCKETS: Bucket[] = ['triage', 'in_progress', 'shipped', 'validated']

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

function BucketAction({ bucket, onChange }: { bucket?: Bucket; onChange: (b: Bucket) => void }) {
  const next: Partial<Record<Bucket, { label: string; to: Bucket }>> = {
    triage:      { label: 'Start',      to: 'in_progress' },
    in_progress: { label: 'Mark shipped', to: 'shipped' },
    shipped:     { label: 'Validate',   to: 'validated' },
  }
  const action = next[bucket || 'triage']
  if (!action) {
    return <span style={{ fontSize: '.72rem', color: 'var(--dim)' }}>—</span>
  }
  return (
    <button
      className="btn btn-xs btn-accent"
      style={{ fontSize: '.72rem', padding: '3px 9px', whiteSpace: 'nowrap' }}
      onClick={() => onChange(action.to)}
    >
      {action.label}
    </button>
  )
}

function BucketBadge({ bucket }: { bucket?: Bucket }) {
  const b: Bucket = bucket || 'triage'
  const c = BUCKET_COLORS[b]
  return (
    <span style={{
      display: 'inline-block', padding: '3px 10px', borderRadius: 4,
      fontSize: '.72rem', fontWeight: 600, letterSpacing: '.3px',
      background: c.bg, color: c.fg, border: `1px solid ${c.border}`,
      whiteSpace: 'nowrap',
    }}>
      {BUCKET_LABELS[b]}
    </span>
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

type SortKey = 'id' | 'app_slug' | 'user_name' | 'created_at' | 'message' | 'status' | 'bucket'
type SortDir = 'asc' | 'desc'

function getHash(): string {
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
  const [filterText, setFilterText] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('id')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [filterBuckets, setFilterBuckets] = useState<Set<Bucket>>(new Set())

  useEffect(() => {
    if (forcedTab) { setTab(forcedTab); return }
    function onHash() { setTab(getHash()) }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [forcedTab])

  // "Show closed" toggle — when off (default), the server already
  // omits status='done' rows; when on, request both lists and merge.
  const [showClosed] = useState(false)
  const loadData = useCallback(() => {
    const url = showClosed ? '/api/enhancements?include_done=1' : '/api/enhancements'
    return Promise.all([
      adminApi.get<{ requests: Enhancement[] }>(url).catch(() => ({ requests: [] })),
      adminApi.get<{ apps: AppOption[] }>('/api/apps').catch(() => ({ apps: [] })),
    ]).then(([eRes, aRes]) => {
      const sorted = [...(eRes.requests ?? [])].sort((a, b) => b.id - a.id)
      setAllEnhancements(sorted)
      setApps(aRes.apps ?? [])
    })
  }, [showClosed])

  useEffect(() => { loadData() }, [loadData])

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
    if (filterBuckets.size > 0 && (!e.bucket || !filterBuckets.has(e.bucket))) return false
    if (filterText) {
      const q = filterText.toLowerCase()
      if (!e.message?.toLowerCase().includes(q) && !e.user_name?.toLowerCase().includes(q)) return false
    }
    return true
  })

  function toggleBucketFilter(b: Bucket) {
    setFilterBuckets(prev => {
      const next = new Set(prev)
      if (next.has(b)) next.delete(b)
      else next.add(b)
      return next
    })
  }

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

  async function setBucket(id: number, bucket: Bucket) {
    await adminApi.put(`/api/enhancements/${id}/bucket`, { bucket }).catch(() => {})
    setAllEnhancements(prev => prev.map(e => e.id === id ? { ...e, bucket } : e))
  }

  async function deleteEnhancement(id: number) {
    if (!confirm('Delete this request?')) return
    const res = await adminApi.post<{ error?: { message?: string } }>(`/api/enhancements/${id}/delete`).catch(() => null)
    if (res && res.error) { alert('Delete failed: ' + (res.error.message || 'unknown')); return }
    setAllEnhancements(prev => prev.filter(e => e.id !== id))
  }

  return (
    <div className="container" style={{ maxWidth: 1400 }}>
      {tab === 'requests' && (
        <RequestsTab
          enhancements={sortedFiltered}
          apps={apps}
          filterApp={filterApp}
          filterBuckets={filterBuckets}
          filterText={filterText}
          sortKey={sortKey}
          sortDir={sortDir}
          onFilterApp={setFilterApp}
          onToggleBucket={toggleBucketFilter}
          onFilterText={setFilterText}
          onSort={handleSort}
          thArrow={thArrow}
          onSetBucket={setBucket}
          onDelete={deleteEnhancement}
          total={sortedFiltered.length}
        />
      )}
    </div>
  )
}

interface RequestsTabProps {
  enhancements: Enhancement[]
  apps: AppOption[]
  filterApp: string
  filterBuckets: Set<Bucket>
  filterText: string
  sortKey: SortKey
  sortDir: SortDir
  onFilterApp: (v: string) => void
  onToggleBucket: (b: Bucket) => void
  onFilterText: (v: string) => void
  onSort: (k: SortKey) => void
  thArrow: (k: SortKey) => string
  onSetBucket: (id: number, bucket: Bucket) => void
  onDelete: (id: number) => void
  total: number
}

function RequestsTab({
  enhancements, apps, filterApp, filterBuckets, filterText,
  onFilterApp, onToggleBucket, onFilterText,
  onSort, thArrow, onSetBucket, onDelete, total,
}: RequestsTabProps) {
  return (
    <>
      <div className="filter-row" style={{ flexWrap: 'wrap', alignItems: 'center', gap: 10 }}>
        <select value={filterApp} onChange={e => onFilterApp(e.target.value)} style={{ fontSize: '.82rem' }}>
          <option value="">All apps</option>
          {apps.map(a => <option key={a.slug} value={a.slug}>{a.name}</option>)}
        </select>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {BUCKETS.map(b => {
            const active = filterBuckets.has(b)
            const c = BUCKET_COLORS[b]
            return (
              <button
                key={b}
                onClick={() => onToggleBucket(b)}
                title={active ? `Hide ${BUCKET_LABELS[b]}` : `Show only ${BUCKET_LABELS[b]} (combinable)`}
                style={{
                  fontSize: '.72rem', fontWeight: 600, letterSpacing: '.3px',
                  padding: '4px 11px', borderRadius: 4, cursor: 'pointer',
                  fontFamily: 'inherit',
                  background: active ? c.bg : 'transparent',
                  color: active ? c.fg : 'var(--dim)',
                  border: `1px solid ${active ? c.border : 'var(--border)'}`,
                  transition: 'all .12s ease',
                }}>
                {BUCKET_LABELS[b]}
              </button>
            )
          })}
        </div>
        <input
          type="text"
          value={filterText}
          onChange={e => onFilterText(e.target.value)}
          placeholder="Search…"
          style={{ flex: 1, fontSize: '.82rem', minWidth: 140 }}
        />
        <span style={{ marginLeft: 'auto', color: 'var(--dim)', fontSize: '.82rem', whiteSpace: 'nowrap' }}>{total} requests</span>
      </div>
      <div className="req-table-wrap">
        <table className="req-table">
          <colgroup>
            <col style={{ width: 70 }} />
            <col style={{ width: 130 }} />
            <col style={{ width: 120 }} />
            <col style={{ width: 140 }} />
            <col />
            <col style={{ width: 110 }} />
            <col style={{ width: 130 }} />
            <col style={{ width: 44 }} />
          </colgroup>
          <thead>
            <tr>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('id')}>#{ thArrow('id')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('app_slug')}>App{thArrow('app_slug')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('user_name')}>User{thArrow('user_name')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('created_at')}>Date{thArrow('created_at')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('message')}>Message{thArrow('message')}</th>
              <th style={{ cursor: 'pointer' }} onClick={() => onSort('bucket')}>Status{thArrow('bucket')}</th>
              <th>Version / PR</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {enhancements.map(e => (
              <tr key={e.id}>
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
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <BucketBadge bucket={e.bucket} />
                    <BucketAction bucket={e.bucket} onChange={b => onSetBucket(e.id, b)} />
                  </div>
                </td>
                <td style={{ fontSize: '.78rem' }}>
                  {e.fix_version ? (
                    <span style={{ color: 'var(--green)', fontFamily: 'monospace', fontWeight: 700 }}>{e.fix_version}</span>
                  ) : e.pr_url ? (
                    <a href={e.pr_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontSize: '.75rem' }}>PR ↗</a>
                  ) : e.branch_name ? (
                    <span style={{ color: 'var(--dim)', fontFamily: 'monospace', fontSize: '.72rem' }}>{e.branch_name}</span>
                  ) : '—'}
                </td>
                <td>
                  <button
                    className="btn btn-xs btn-red"
                    style={{ padding: '2px 7px' }}
                    onClick={() => onDelete(e.id)}
                    title="Delete"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
            {enhancements.length === 0 && (
              <tr>
                <td colSpan={8} style={{ color: 'var(--dim)', textAlign: 'center', padding: 24 }}>No requests found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}

