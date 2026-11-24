import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'
import TrashEntryDetail, { type TrashDetail } from '../components/TrashEntryDetail'

interface Finding {
  id: number
  kind: string
  severity: 'info' | 'warning' | 'error'
  app_id: number | null
  slug: string | null
  env: string | null
  subject: string | null
  detail: Record<string, unknown>
  fix: string | null
  fix_label: string | null
  status: string
  first_seen_at: string
  last_seen_at: string
  fix_result: string | null
}

interface Run { id: number; trigger_by: string; started_at: string; finished_at: string | null; docker_ok: number | null; counts: Record<string, number> | null; error: string | null }
interface Paused { app_id: number; slug: string; env: string; reason: string; paused_at: string }
interface Trash { id: number; kind: string; slug: string | null; original_path: string; trash_path: string; reason: string; moved_at: string; expires_at: string; detail: TrashDetail | null }
interface State { last_run: Run | null; findings: Finding[]; paused_probes: Paused[]; trash: Trash[] }

const KIND_LABEL: Record<string, string> = {
  live_without_container: 'Live deployment, no container',
  probe_without_container: 'Health probe with nothing to probe',
  probe_paused: 'Health probe paused',
  live_release_missing: 'Live release missing on disk',
  failed_streak: 'Last deploys all failed',
  stale_live_rows: 'Several releases marked live',
  dangling_current: 'current link points nowhere',
  github_url_mismatch: 'github_url differs from the attached repository',
  github_url_differs_from_release: 'github_url differs from the running release',
  container_without_app: 'Container with no app',
  orphan_app_dir: 'App directory with no app',
  rename_leftover_dir: 'Directory left by a rename',
  orphan_repo: 'Repository with no app',
  rename_leftover_repo: 'Repository left by a rename',
  orphan_backups_dir: 'Backups directory with no app',
  orphan_coder_dir: 'Coder workspace with no app',
  orphan_attestations_dir: 'Attestations with no app',
  orphan_npm_cache_dir: 'Studio npm cache with no app',
  orphan_rows: 'Rows for an app that is gone',
  upload_conversion_skipped: 'Upload conversion skipped',
  trash_expired: 'Trash past its retention',
}

const COLOR: Record<string, string> = { error: 'var(--red)', warning: 'var(--amber, #b7791f)', info: 'var(--dim)' }
const when = (ts: string | null | undefined) => (ts ? serverDate(ts).toLocaleString() : 'never')
const errText = (e: unknown) => (e instanceof Error ? e.message : String(e))

function Detail({ d }: { d: Record<string, unknown> }) {
  const entries = Object.entries(d).filter(([, v]) => v !== null && v !== undefined && v !== '')
  return (
    <div style={{ fontSize: '.8rem', color: 'var(--dim)' }}>
      {entries.map(([k, v]) => (
        <div key={k}><b>{k}</b>: {typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>
      ))}
    </div>
  )
}

/** Platform admin: deployment records against what Docker and the disk hold, with one-click fixes. */
export function Reconcile() {
  const [state, setState] = useState<State | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState<string>('')
  const [status, setStatus] = useState('active')

  const load = useCallback(() => {
    adminApi.get<State>(`/api/state-reconcile?status=${encodeURIComponent(status)}`)
      .then(s => { setState(s); setError('') })
      .catch(e => setError(errText(e)))
  }, [status])
  useEffect(() => { load() }, [load])

  async function act(key: string, path: string, confirmText?: string) {
    if (confirmText && !window.confirm(confirmText)) return
    setBusy(key)
    try { await adminApi.post(path); load() } catch (e) { setError(errText(e)) } finally { setBusy('') }
  }

  const run = state?.last_run
  return (
    <div>
      <h3>Reconcile</h3>
      <p className="settings-hint">
        What the database says against what is running. Every 10 minutes (and on boot) AppCrane compares deployments, health probes,
        containers and directories. It fixes two things by itself: it pauses a health probe for an environment with no container
        (and resumes it when one appears), and marks older releases of an environment as replaced when several are marked live.
        Everything else waits here. A directory is never deleted: it moves to the trash, kept 30 days, and only a platform admin purges it.
      </p>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' }}>
        <button className="btn" disabled={!!busy} onClick={() => act('run', '/api/state-reconcile/run')}>{busy === 'run' ? 'Checking...' : 'Check now'}</button>
        <select value={status} onChange={e => setStatus(e.target.value)}>
          <option value="active">Open and auto-fixed</option>
          <option value="fixed">Fixed</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
          <option value="all">All</option>
        </select>
        {run && (
          <span style={{ color: 'var(--dim)', fontSize: '.85rem' }}>
            Last check {when(run.finished_at || run.started_at)} ({run.trigger_by})
            {run.docker_ok === 0 && <b style={{ color: 'var(--red)' }}> | Docker did not answer: container checks skipped</b>}
            {run.error && <b style={{ color: 'var(--red)' }}> | failed: {run.error}</b>}
          </span>
        )}
      </div>

      {state && state.findings.length === 0 && <p>Nothing to reconcile.</p>}
      {state && state.findings.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
                <th style={{ padding: 6 }}>Finding</th>
                <th style={{ padding: 6 }}>App / env</th>
                <th style={{ padding: 6 }}>Detail</th>
                <th style={{ padding: 6 }}>Seen</th>
                <th style={{ padding: 6 }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {state.findings.map(f => (
                <tr key={f.id} style={{ borderTop: '1px solid var(--border)', verticalAlign: 'top' }}>
                  <td style={{ padding: 6 }}>
                    <b style={{ color: COLOR[f.severity] }}>{KIND_LABEL[f.kind] || f.kind}</b>
                    <div style={{ fontSize: '.75rem', color: 'var(--dim)' }}>{f.status.replace('_', ' ')}</div>
                  </td>
                  <td style={{ padding: 6 }}>{f.slug || (f.app_id ? `app #${f.app_id}` : '-')}{f.env ? ` / ${f.env}` : ''}</td>
                  <td style={{ padding: 6, maxWidth: 420 }}>
                    <Detail d={f.detail} />
                    {f.fix_result && <div style={{ fontSize: '.8rem' }}>Result: {f.fix_result}</div>}
                  </td>
                  <td style={{ padding: 6, whiteSpace: 'nowrap' }}>{when(f.first_seen_at)}<br />{when(f.last_seen_at)}</td>
                  <td style={{ padding: 6 }}>
                    {f.status === 'open' && f.fix && (
                      <button className="btn btn-sm" disabled={!!busy}
                        onClick={() => act(`fix-${f.id}`, `/api/state-reconcile/findings/${f.id}/fix`, `${f.fix_label}?`)}>
                        {busy === `fix-${f.id}` ? 'Working...' : f.fix_label}
                      </button>
                    )}
                    {(f.status === 'open' || f.status === 'auto_fixed') && (
                      <button className="btn btn-sm btn-ghost" style={{ marginLeft: 4 }} disabled={!!busy}
                        onClick={() => act(`dis-${f.id}`, `/api/state-reconcile/findings/${f.id}/dismiss`)}>Dismiss</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {state && state.paused_probes.length > 0 && (
        <>
          <h4 style={{ marginTop: 20 }}>Paused health probes</h4>
          <ul style={{ fontSize: '.85rem' }}>
            {state.paused_probes.map(p => <li key={`${p.app_id}-${p.env}`}>{p.slug} / {p.env}: {p.reason} (since {when(p.paused_at)})</li>)}
          </ul>
        </>
      )}

      {state && state.trash.length > 0 && (
        <>
          <h4 style={{ marginTop: 20 }}>Trash</h4>
          <ul style={{ fontSize: '.85rem' }}>
            {state.trash.map(t => (
              <li key={t.id}>
                #{t.id} {t.kind} {t.slug ? `(${t.slug})` : ''}: {t.original_path} to {t.trash_path}, {t.reason}, moved {when(t.moved_at)}, kept until {when(t.expires_at)}
                {serverDate(t.expires_at).getTime() <= Date.now() && (
                  <button className="btn btn-sm" style={{ marginLeft: 6 }} disabled={!!busy}
                    onClick={() => act(`purge-${t.id}`, `/api/state-reconcile/trash/${t.id}/purge`, `Permanently delete ${t.trash_path}? This cannot be undone.`)}>
                    Purge
                  </button>
                )}
                <TrashEntryDetail detail={t.detail} />
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
