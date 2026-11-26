import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'

// "Logins without a client certificate" (GET /api/managed-db/logins/password-only,
// POST /api/managed-db/logins/:id/require-certificate, /tls-check, /require-tls
// and /revert-tls; platform admin only).
//
// Require TLS is two steps. Prepare: a catalogue app whose image names its CA
// variable gets the CA on every deploy, so a redeploy is enough. Check: the
// engine says whether the app's connections use TLS (Postgres: those open
// now; MariaDB: those since "Start TLS check"). Only then Require TLS, which
// Revert to password undoes.
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
  level?: 'password' | 'tls'
  level_label?: string
  tls_available?: boolean
  tls_note?: string | null
  tls_ca_env?: string | null
  catalogue?: boolean
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

interface TlsCheck {
  engine: string
  method: 'current' | 'since'
  since: string | null
  measured: boolean
  reason: string | null
  connections: number
  tls: number
  plain: number
  open_unclassified: number
  ready: boolean
  blocked: { code: string; message: string } | null
}

interface ListResponse {
  logins: Login[]
  tls_logins?: Login[]
  cert_problems?: CertProblem[]
  postgres_strict: boolean | null
}

export function ManagedDbPasswordOnlyCard() {
  const [data, setData] = useState<ListResponse | null>(null)
  const [busy, setBusy] = useState<number | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [checks, setChecks] = useState<Record<number, TlsCheck>>({})

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

  async function runCheck(l: Login, reset: boolean) {
    setBusy(l.database_id)
    setMsg(null)
    try {
      const r = await adminApi.post<TlsCheck>(`/api/managed-db/logins/${l.database_id}/tls-check`, { reset })
      setChecks(c => ({ ...c, [l.database_id]: r }))
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(null)
    }
  }

  async function requireTls(l: Login) {
    const what = `${l.app_slug || `app ${l.app_id}`} (${l.engine}${l.env ? `, ${l.env}` : ''})`
    const c = checks[l.database_id]
    const noConnections = Boolean(c && c.measured && c.connections === 0 && !c.blocked)
    if (!c || (!c.ready && !noConnections)) return
    const measured = noConnections
      ? 'WARNING: the app made no connection to measure, so nothing shows that it uses TLS. If it does not, it cannot reach its database until you revert.'
      : `The engine shows all ${c.connections} measured connection(s) using TLS.`
    if (!confirm(`Require TLS for ${what}?\n\n${measured}\n\nFrom now on the engine refuses this login without TLS. Revert to password undoes it.`)) return
    setBusy(l.database_id)
    setMsg(null)
    try {
      const r = await adminApi.post<{ note: string }>(`/api/managed-db/logins/${l.database_id}/require-tls`, { confirm: true, ...(noConnections ? { confirm_no_connections: true } : {}) })
      setMsg({ text: r.note, ok: true })
      load()
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(null)
    }
  }

  async function revertTls(l: Login) {
    const what = `${l.app_slug || `app ${l.app_id}`} (${l.engine}${l.env ? `, ${l.env}` : ''})`
    if (!confirm(`Revert ${what} to password?\n\nThe engine will accept this login with its password alone, without TLS, again.`)) return
    setBusy(l.database_id)
    setMsg(null)
    try {
      const r = await adminApi.post<{ note: string }>(`/api/managed-db/logins/${l.database_id}/revert-tls`, { confirm: true })
      setMsg({ text: r.note, ok: true })
      load()
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(null)
    }
  }

  function prepareHint(l: Login) {
    if (l.tls_ca_env) return `Each deploy hands the app the CA (${l.tls_ca_env}); redeploy it, then check.`
    if (l.catalogue) return 'This catalogue image names no CA variable: AppCrane cannot tell it to use TLS.'
    return 'Not a catalogue app: its own connection settings must turn TLS on.'
  }

  function checkText(c: TlsCheck) {
    if (!c.measured) return c.blocked?.message || 'Not measured.'
    const scope = c.method === 'since' ? `since ${c.since ? c.since.slice(0, 16).replace('T', ' ') : 'the check started'}` : 'open now'
    return `${c.tls} of ${c.connections} connection(s) ${scope} use TLS.` + (c.blocked && c.connections > 0 ? ` ${c.blocked.message}` : '')
  }

  const tlsLogins = data.tls_logins ?? []

  return (
    <div style={{ marginTop: 18 }}>
      <h3 style={{ margin: '0 0 6px' }}>Logins without a client certificate</h3>
      {data.logins.length === 0 ? (
        <div style={{ fontSize: '.82rem', color: 'var(--dim)' }}>
          {tlsLogins.length ? 'No managed database login signs in with a password alone.' : 'Every managed database login requires TLS and its own client certificate.'}
          {data.postgres_strict && (tlsLogins.length ? ' Postgres refuses every network login without TLS, and without a certificate outside the TLS logins below.' : ' Postgres refuses every network login without one.')}
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
                      <span style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
                        {l.tls_available && (
                          <>
                            {l.engine === 'mariadb' && (
                              <button className="btn btn-sm" disabled={busy !== null} onClick={() => runCheck(l, true)}>Start TLS check</button>
                            )}
                            <button className="btn btn-sm" disabled={busy !== null} onClick={() => runCheck(l, false)}>Check TLS</button>
                            <button className="btn btn-sm" disabled={busy !== null || !checks[l.database_id] || (!checks[l.database_id].ready && !(checks[l.database_id].measured && checks[l.database_id].connections === 0 && !checks[l.database_id].blocked))} onClick={() => requireTls(l)}>Require TLS</button>
                          </>
                        )}
                        <button className="btn btn-sm" disabled={busy !== null} onClick={() => convert(l)}>Require certificate</button>
                      </span>
                    )}
                    {l.kind === 'owner' && l.tls_available && (
                      <div style={{ fontSize: '.7rem', color: 'var(--dim)', marginTop: 4 }}>
                        {checks[l.database_id] ? checkText(checks[l.database_id]) : prepareHint(l)}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </>
      )}
      {tlsLogins.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: '.82rem', fontWeight: 600, marginBottom: 4 }}>TLS + password (no client certificate)</div>
          <div style={{ fontSize: '.72rem', color: 'var(--dim)', marginBottom: 6 }}>
            These logins must use TLS; the password is still the only proof of identity.
          </div>
          <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ fontSize: '.8rem', width: '100%' }}>
            <thead>
              <tr><th>App</th><th>Environment</th><th>Engine</th><th>Login</th><th></th></tr>
            </thead>
            <tbody>
              {tlsLogins.map(l => (
                <tr key={`tls:${l.database_id}:${l.login}`}>
                  <td>{l.app_slug || `app ${l.app_id}`}</td>
                  <td>{l.env || ''}</td>
                  <td>{l.engine}</td>
                  <td><code>{l.login}</code>{l.kind === 'app' && ' (DML-only)'}</td>
                  <td>
                    {l.kind === 'owner' && (
                      <span style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
                        <button className="btn btn-sm" disabled={busy !== null} onClick={() => revertTls(l)}>Revert to password</button>
                        <button className="btn btn-sm" disabled={busy !== null} onClick={() => convert(l)}>Require certificate</button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
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
