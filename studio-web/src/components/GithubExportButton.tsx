import { useState } from 'react'
import { adminApi, ApiError } from '../adminApi'

interface ExportResult {
  ok: boolean
  state: 'pushed' | 'up_to_date' | 'refused' | 'failed'
  reason_code: string | null
  reason: string | null
  branch: string
  github_repo: string | null
  local_sha: string | null
  github_sha_after: string | null
  verified: boolean
}

/** Applications → expanded row of a Crane-hosted app with a GitHub URL: push AppCrane's copy to GitHub. */
export function GithubExportButton({ slug }: { slug: string }) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; text: string; title?: string } | null>(null)

  const run = () => {
    if (!window.confirm('Push AppCrane\'s copy of this app\'s branch and tags to GitHub? AppCrane never force-pushes: if GitHub has commits AppCrane lacks, nothing is pushed.')) return
    setBusy(true)
    setResult(null)
    adminApi.post<ExportResult>(`/api/apps/${encodeURIComponent(slug)}/github-export`, {})
      .then((r) => setResult({
        ok: true,
        text: r.state === 'up_to_date'
          ? `GitHub already matches: '${r.branch}' at ${r.github_sha_after?.slice(0, 7)} (verified).`
          : `Pushed '${r.branch}' to GitHub; verified at ${r.github_sha_after?.slice(0, 7)}.`,
        title: r.github_sha_after ?? undefined,
      }))
      .catch((e: unknown) => {
        const reason = e instanceof ApiError ? (e.details.reason as string | undefined) || e.message : e instanceof Error ? e.message : String(e)
        const refused = e instanceof ApiError && e.details.state === 'refused'
        setResult({ ok: false, text: `${refused ? 'Not pushed' : 'Export failed'}: ${reason}`, title: e instanceof ApiError ? e.code : undefined })
      })
      .finally(() => setBusy(false))
  }

  return (
    <div style={{ marginTop: 6, fontSize: '.78rem', display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
      <button className="btn btn-xs" disabled={busy} onClick={run}>{busy ? 'Pushing…' : 'Push to GitHub'}</button>
      {result && (
        <span style={{ color: result.ok ? 'var(--green, #22c55e)' : 'var(--red, #ef4444)' }} title={result.title}>{result.text}</span>
      )}
    </div>
  )
}
