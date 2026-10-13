import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// Per-app backups for one environment (/api/apps/:slug/backups), with the
// app's managed databases included since v2.102.0. Rendered inside
// AppManager, so it uses that page's .am-* classes.
//
// Who may restore is decided by the server (production, and any backup whose
// database is the one production uses: owner or platform admin). This card
// shows the restore control to everyone with access and relays the server's
// refusal, rather than re-deriving the rule from a role string.

interface BackupDb { engine: string; env: 'production' | 'sandbox' | null; db_name: string; size_bytes: number }
interface Backup {
  id: number; env: 'production' | 'sandbox'; size_bytes: number; created_at: string
  created_by_name?: string | null
  databases: BackupDb[]; includes_database: boolean
}

interface Props {
  slug: string
  env: 'production' | 'sandbox'
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`
}

export function BackupsCard({ slug, env, reload, onMsg }: Props) {
  const [backups, setBackups] = useState<Backup[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [restoring, setRestoring] = useState<Backup | null>(null)
  const [includeDb, setIncludeDb] = useState(true)

  const load = useCallback(() => {
    adminApi.get<{ backups: Backup[] }>(`/api/apps/${slug}/backups`)
      .then(r => setBackups(r.backups))
      .catch(() => setBackups(null))
  }, [slug])

  useEffect(() => { load() }, [load, reload])

  async function backupNow() {
    setBusy(true)
    try {
      const r = await adminApi.post<{ message?: string }>(`/api/apps/${slug}/backup/${env}`, {})
      onMsg({ text: r.message || 'Backup created.', ok: true })
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function restore() {
    if (!restoring) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ message?: string }>(`/api/apps/${slug}/restore/${restoring.id}`, {
        include_database: restoring.includes_database ? includeDb : false,
      })
      onMsg({ text: r.message || 'Restored.', ok: true })
      setRestoring(null)
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!backups) return null
  const rows = backups.filter(b => b.env === env)

  return (
    <div className="am-card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <h3>Backups ({env})</h3>
        <button className="btn btn-sm" disabled={busy} onClick={backupNow}>Back up now</button>
      </div>
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 8 }}>
        A backup holds this environment's /data and a dump of each managed database it uses. Taken on demand; there is no automatic expiry.
      </div>
      {rows.length === 0 ? (
        <div style={{ fontSize: '.8rem', color: 'var(--dim)' }}>No backups of {env} yet.</div>
      ) : (
        <table style={{ width: '100%', fontSize: '.8rem' }}>
          <thead>
            <tr><th style={{ textAlign: 'left' }}>Taken</th><th style={{ textAlign: 'left' }}>Files</th><th style={{ textAlign: 'left' }}>Database</th><th style={{ textAlign: 'left' }}>By</th><th /></tr>
          </thead>
          <tbody>
            {rows.map(b => (
              <tr key={b.id}>
                <td>{b.created_at.replace('T', ' ').slice(0, 16)}</td>
                <td>{fmtBytes(b.size_bytes)}</td>
                <td>
                  {b.includes_database
                    ? `includes database (${b.databases.map(d => `${d.engine}, ${fmtBytes(d.size_bytes)}`).join('; ')})`
                    : '-'}
                </td>
                <td>{b.created_by_name || '-'}</td>
                <td style={{ textAlign: 'right' }}>
                  <button className="btn btn-sm" disabled={busy} onClick={() => { setRestoring(b); setIncludeDb(true) }}>Restore</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {restoring && (
        <div style={{ marginTop: 12, padding: 10, border: '1px solid var(--border)', borderRadius: 6 }}>
          <div style={{ fontSize: '.85rem', marginBottom: 8 }}>
            Restore backup #{restoring.id} ({restoring.created_at.replace('T', ' ').slice(0, 16)}) to {env}? Its files are written over this environment's /data.
          </div>
          {restoring.includes_database && (
            <>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: busy ? 'wait' : 'pointer' }}>
                <input type="checkbox" checked={includeDb} disabled={busy} onChange={e => setIncludeDb(e.target.checked)} />
                Also restore the database ({restoring.databases.map(d => d.engine).join(', ')})
              </label>
              {includeDb && (
                <div className="msg-err" style={{ fontSize: '.75rem', marginTop: 6 }}>
                  This replaces the database's current contents with the backup. Anything written since the backup was taken is lost.
                  {restoring.databases.some(d => d.env === 'production') && env === 'sandbox'
                    ? ' This sandbox uses production\'s database, so production\'s data is replaced too.'
                    : ''}
                </div>
              )}
            </>
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button className="btn btn-sm btn-red" disabled={busy} onClick={restore}>Restore</button>
            <button className="btn btn-sm" disabled={busy} onClick={() => setRestoring(null)}>Cancel</button>
          </div>
        </div>
      )}
    </div>
  )
}
