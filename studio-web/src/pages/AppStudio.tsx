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
    // /api/enhancements is admin-only; fall back to /owned (requests
    // filed against apps the caller owns or admins) so an app owner
    // sees their triage list without needing global admin. Without
    // this, sairaj sees badge count "11" in the sidebar but "No
    // requests found" on the page (bug surfaced 2026-06-11). /owned
    // returns the same rich shape as the admin endpoint so this page
    // renders identically.
    const url = showClosed ? '/api/enhancements?include_done=1' : '/api/enhancements'
    const ownedUrl = showClosed ? '/api/enhancements/owned?include_done=1' : '/api/enhancements/owned'
    return Promise.all([
      adminApi.get<{ requests: Enhancement[] }>(url)
        .catch(() => adminApi.get<{ requests: Enhancement[] }>(ownedUrl).catch(() => ({ requests: [] }))),
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
    // Don't optimistic-remove until the server confirms — the previous
    // version did `.catch(() => null)` which swallowed every error and
    // then dropped the row from local state regardless. The row would
    // disappear from the UI and reappear on refresh because the server
    // never actually deleted it.
    try {
      await adminApi.post(`/api/enhancements/${id}/delete`)
      setAllEnhancements(prev => prev.filter(e => e.id !== id))
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      alert(`Delete failed: ${msg}`)
    }
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
            <col style={{ width: 190 }} />
            <col style={{ width: 155 }} />
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
                    ? <span className="app-pill" style={{ background: e.app_slug === '_platform' ? 'rgba(59,130,246,.15)' : 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 7px', fontSize: '.75rem', color: e.app_slug === '_platform' ? 'var(--accent)' : 'var(--dim)' }}>{e.app_slug === '_platform' ? 'AppCrane Platform' : e.app_slug}</span>
                    : '—'}
                </td>
                <td style={{ fontSize: '.82rem', color: 'var(--dim)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={e.user_name ?? undefined}>{e.user_name ?? '—'}</td>
                <td style={{ fontSize: '.78rem', color: 'var(--dim)', whiteSpace: 'nowrap' }}>{fmtDate(e.created_at)}</td>
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

