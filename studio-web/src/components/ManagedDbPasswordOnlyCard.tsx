import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// "Logins without a client certificate" (GET /api/managed-db/logins/password-only,
// POST /api/managed-db/logins/:id/require-certificate; platform admin only).
// Rendered inside ManagedDbSettingsCard.
//
// Converting is never automatic for a catalogue app: its third-party image may
// not speak database TLS, so the admin decides per login, and the app needs a
// redeploy or restart to get its certificate mounted.

interface Login {
  database_id: number
  app_id: number
  app_slug: string | null
  env: string | null
  engine: string
  login: string
  kind: 'owner' | 'app'
  convert_note: string | null
}

interface CertProblem {
  database_id: number
  app_id: number
  app_slug: string | null
  env: string | null
  engine: string
  login: string
  problem: 'not_sent' | 'not_enforced'
  label: string
  checked_at: string
}

interface ListResponse {
  logins: Login[]
  cert_problems?: CertProblem[]
  postgres_strict: boolean | null
}

export function ManagedDbPasswordOnlyCard() {
  const [data, setData] = useState<ListResponse | null>(null)
  const [busy, setBusy] = useState<number | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  const load = useCallback(() => {
    adminApi.get<ListResponse>('/api/managed-db/logins/password-only').then(setData).catch(() => setData(null))
  }, [])
  useEffect(load, [load])

  if (!data) return null

  async function convert(l: Login) {
    const what = `${l.app_slug || `app ${l.app_id}`} (${l.engine}${l.env ? `, ${l.env}` : ''})`
    if (!confirm(`Require a client certificate for ${what}?\n\n${l.convert_note || ''}\n\nThe app keeps its old connection URL until it is redeployed or restarted, and new connections are refused until then. If its image cannot use a client certificate it stays unable to connect.`)) return
    setBusy(l.database_id)
    setMsg(null)
    try {
      const r = await adminApi.post<{ note: string }>(`/api/managed-db/logins/${l.database_id}/require-certificate`, { confirm: true })
      setMsg({ text: r.note, ok: true })
      load()
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div style={{ marginTop: 18 }}>
      <h3 style={{ margin: '0 0 6px' }}>Logins without a client certificate</h3>
      {data.logins.length === 0 ? (
        <div style={{ fontSize: '.82rem', color: 'var(--dim)' }}>
          Every managed database login requires TLS and its own client certificate.
          {data.postgres_strict && ' Postgres refuses every network login without one.'}
        </div>
      ) : (
        <>
          <div style={{ fontSize: '.72rem', color: 'var(--dim)', marginBottom: 6 }}>
            These logins still sign in with a password alone. While any Postgres login is listed, Postgres also accepts a password-only login from any role outside the certificate group.
          </div>
          <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ fontSize: '.8rem', width: '100%' }}>
            <thead>
              <tr><th>App</th><th>Environment</th><th>Engine</th><th>Login</th><th></th></tr>
            </thead>
            <tbody>
              {data.logins.map(l => (
                <tr key={`${l.database_id}:${l.login}`}>
                  <td>{l.app_slug || `app ${l.app_id}`}</td>
                  <td>{l.env || ''}</td>
                  <td>{l.engine}</td>
                  <td><code>{l.login}</code>{l.kind === 'app' && ' (DML-only)'}</td>
                  <td>
                    {l.kind === 'owner' && (
                      <button className="btn btn-sm" disabled={busy !== null} onClick={() => convert(l)}>Require certificate</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </>
      )}
      {(data.cert_problems?.length ?? 0) > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: '.82rem', fontWeight: 600, marginBottom: 4 }}>Certificate logins that need attention</div>
          <div style={{ fontSize: '.72rem', color: 'var(--dim)', marginBottom: 6 }}>
            Found by the app's last deploy or restart. AppCrane does not change these logins on a deploy; fix the app's connection settings, then restart it.
          </div>
          <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ fontSize: '.8rem', width: '100%' }}>
            <thead>
              <tr><th>App</th><th>Environment</th><th>Engine</th><th>Login</th><th>Problem</th></tr>
            </thead>
            <tbody>
              {data.cert_problems!.map(p => (
                <tr key={`${p.database_id}:${p.problem}`}>
                  <td>{p.app_slug || `app ${p.app_id}`}</td>
                  <td>{p.env || ''}</td>
                  <td>{p.engine}</td>
                  <td><code>{p.login}</code></td>
                  <td>{p.label}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
      )}
      {msg && <div style={{ marginTop: 6, fontSize: '.8rem', color: msg.ok ? 'var(--dim)' : 'var(--red)' }}>{msg.text}</div>}
    </div>
  )
}
