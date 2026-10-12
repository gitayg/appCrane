import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// The app's managed databases (/api/apps/:slug/database), with the per-app
// "Separate sandbox database" setting (migration 107). Rendered inside
// AppManager, so it uses that page's .am-* classes.
//
// The server says who may do what (can_change_separate_sandbox_db,
// can_drop_database) so this card shows only the controls the request would
// accept, rather than re-deriving the rule from a role string.

interface Db { engine: string; database: string; username: string; env: 'production' | 'sandbox' | null; created_at: string }
interface DbResp {
  databases: Db[]
  separate_sandbox_db: boolean
  can_change_separate_sandbox_db: boolean
  can_drop_database: boolean
  by_env: { production: string[]; sandbox: string[] }
}

interface Props {
  slug: string
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
}

const HINT = "Sandbox gets its own empty database on its next deploy. Production's database is unchanged. Turning this off later does not delete the sandbox database."

export function ManagedDatabaseCard({ slug, reload, onMsg }: Props) {
  const [data, setData] = useState<DbResp | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    adminApi.get<DbResp>(`/api/apps/${slug}/database`)
      .then(setData)
      .catch(() => setData(null))
  }, [slug])

  useEffect(() => { load() }, [load, reload])

  async function toggle(next: boolean) {
    setBusy(true)
    try {
      await adminApi.put(`/api/apps/${slug}`, { separate_sandbox_db: next })
      onMsg({
        text: next
          ? 'Separate sandbox database is on. It takes effect on the next sandbox deploy or restart.'
          : 'Separate sandbox database is off. Sandbox uses the shared database again from its next deploy or restart; the sandbox database was not deleted.',
        ok: true,
      })
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  async function dropSandbox(engine: string) {
    const typed = window.prompt(`This permanently deletes the sandbox ${engine} database and its data. Type the app slug (${slug}) to confirm.`)
    if (typed !== slug) return
    setBusy(true)
    try {
      const q = new URLSearchParams({ engine, env: 'sandbox', confirm: slug })
      const r = await adminApi.del<{ message?: string }>(`/api/apps/${slug}/database?${q.toString()}`)
      onMsg({ text: r.message || 'Sandbox database removed.', ok: true })
      load()
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!data) return null
  if (!data.databases.length && !data.separate_sandbox_db) return null

  const usedBy = (d: Db) => {
    if (d.env === 'production') return data.separate_sandbox_db ? 'Production' : 'Production and Sandbox'
    if (d.env === 'sandbox') return data.separate_sandbox_db ? 'Sandbox' : 'Unused (was Sandbox)'
    return '-'
  }

  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>Managed databases</h3>
      {data.databases.length > 0 && (
        <table style={{ width: '100%', fontSize: '.8rem', marginBottom: 10 }}>
          <thead>
            <tr><th style={{ textAlign: 'left' }}>Engine</th><th style={{ textAlign: 'left' }}>Database</th><th style={{ textAlign: 'left' }}>User</th><th style={{ textAlign: 'left' }}>Used by</th><th /></tr>
          </thead>
          <tbody>
            {data.databases.map(d => (
              <tr key={`${d.engine}:${d.database}`}>
                <td>{d.engine}</td>
                <td className="am-mono">{d.database}</td>
                <td className="am-mono">{d.username}</td>
                <td>{usedBy(d)}</td>
                <td style={{ textAlign: 'right' }}>
                  {d.env === 'sandbox' && data.can_drop_database && (
                    <button className="btn btn-sm btn-red" disabled={busy} onClick={() => dropSandbox(d.engine)}>Drop</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 8 }}>
        Production uses <span className="am-mono">{data.by_env.production.join(', ') || 'none'}</span>
        {' '}· Sandbox uses <span className="am-mono">{data.by_env.sandbox.join(', ') || 'none yet (created on its next deploy)'}</span>
      </div>
      {data.can_change_separate_sandbox_db && (
        <>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: busy ? 'wait' : 'pointer' }}>
            <input
              type="checkbox"
              checked={data.separate_sandbox_db}
              disabled={busy}
              onChange={e => toggle(e.target.checked)}
            />
            Separate sandbox database
          </label>
          <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 6 }}>
            {HINT} Takes effect on the next sandbox deploy or restart.
          </div>
        </>
      )}
    </div>
  )
}
