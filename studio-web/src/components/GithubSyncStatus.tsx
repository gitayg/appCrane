import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'

interface SyncStatus {
  state: 'same' | 'ahead' | 'behind' | 'diverged' | 'unknown'
  ahead: number | null
  behind: number | null
  branch: string
  crane_sha: string | null
  github_sha: string | null
  github_repo: string | null
  checked_at: string
  reason_code: string | null
  reason: string | null
}

const commits = (n: number) => `${n} commit${n === 1 ? '' : 's'}`

function describe(s: SyncStatus): { text: string; color: string } {
  switch (s.state) {
    case 'same':
      return { text: `GitHub and AppCrane have the same '${s.branch}'.`, color: 'var(--green, #22c55e)' }
    case 'ahead':
      return { text: `AppCrane has ${commits(s.ahead ?? 0)} GitHub doesn't.`, color: 'var(--yellow, #eab308)' }
    case 'behind':
      return { text: `GitHub has ${commits(s.behind ?? 0)} AppCrane doesn't.`, color: 'var(--yellow, #eab308)' }
    case 'diverged':
      return { text: `The copies have split: AppCrane has ${commits(s.ahead ?? 0)} GitHub doesn't, and GitHub has ${commits(s.behind ?? 0)} AppCrane doesn't.`, color: 'var(--red, #ef4444)' }
    default:
      return { text: `Not checked: ${s.reason || 'unknown reason'}`, color: 'var(--dim)' }
  }
}

/** Applications → expanded row of a Crane-hosted app with a GitHub URL: GitHub's branch vs AppCrane's. */
export function GithubSyncStatus({ slug }: { slug: string }) {
  const [s, setS] = useState<SyncStatus | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback((refresh: boolean) => {
    setBusy(true)
    setErr('')
    adminApi.get<SyncStatus>(`/api/apps/${encodeURIComponent(slug)}/github-sync${refresh ? '?refresh=1' : ''}`)
      .then(setS)
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setBusy(false))
  }, [slug])

  useEffect(() => { load(false) }, [load])

  const d = s ? describe(s) : null
  return (
    <div style={{ marginTop: 6, fontSize: '.78rem', display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
      <span style={{ color: 'var(--dim)' }}>GitHub{s?.github_repo ? ` (${s.github_repo})` : ''}</span>
      {err ? (
        <span style={{ color: 'var(--dim)' }}>Could not load the comparison: {err}</span>
      ) : !s ? (
        <span style={{ color: 'var(--dim)' }}>Checking…</span>
      ) : (
        <>
          <span style={{ color: d!.color }} title={s.state === 'unknown' ? (s.reason_code ?? undefined) : `AppCrane ${s.crane_sha?.slice(0, 7) ?? '—'} · GitHub ${s.github_sha?.slice(0, 7) ?? '—'}`}>
            {d!.text}
          </span>
          <span style={{ color: 'var(--dim)' }}>Checked {serverDate(s.checked_at).toLocaleString()}</span>
        </>
      )}
      <button className="btn btn-xs" disabled={busy} onClick={() => load(true)}>{busy ? 'Checking…' : 'Refresh'}</button>
    </div>
  )
}
