import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'

interface ClientError {
  id: number
  message: string
  stack: string | null
  source: string
  count: number
  first_seen: string
  last_seen: string
  last_page: string | null
  pages: string[]
  versions: string[]
  user_agent: string | null
  app_slug: string | null
  last_user_name: string | null
  last_user_email: string | null
}

export function ClientErrors() {
  const [errors, setErrors] = useState<ClientError[] | null>(null)
  const [failure, setFailure] = useState('')
  const [open, setOpen] = useState<Set<number>>(new Set())
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    adminApi.get<{ errors: ClientError[] }>('/api/settings/client-errors')
      .then(r => { setErrors(r.errors || []); setFailure('') })
      .catch(e => setFailure(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => { load() }, [load])

  const toggle = (id: number) => setOpen(prev => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id); else next.add(id)
    return next
  })

  async function resolve(id: number) {
    setBusy(true)
    try { await adminApi.del(`/api/settings/client-errors/${id}`); setErrors(list => (list || []).filter(e => e.id !== id)) }
    catch (e) { setFailure(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  async function clearAll() {
    if (!confirm('Clear every recorded browser error? New ones will be recorded as they happen.')) return
    setBusy(true)
    try { await adminApi.del('/api/settings/client-errors'); setErrors([]) }
    catch (e) { setFailure(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 8 }}>
        <h3 style={{ margin: 0, flex: 1 }}>Client errors</h3>
        <button className="btn" onClick={load} disabled={busy}>Refresh</button>
        <button className="btn" onClick={clearAll} disabled={busy || !errors?.length}>Clear all</button>
      </div>
      <p style={{ color: 'var(--dim)', marginTop: 0, fontSize: '.85rem' }}>
        Uncaught errors from people's browsers in the admin UI, the sign-in page and the app top bar, grouped by
        error. Tokens, query strings and e-mail addresses are removed before anything is stored. Entries not seen
        for 30 days are dropped.
      </p>
      {failure && <div role="alert" style={{ color: 'var(--red)', margin: '8px 0' }}>{failure}</div>}
      {errors === null && !failure && <p style={{ color: 'var(--dim)' }}>Loading…</p>}
      {errors && errors.length === 0 && <p style={{ color: 'var(--dim)' }}>No browser errors recorded.</p>}
      {errors && errors.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th style={{ textAlign: 'left' }}>Error</th>
                <th style={{ textAlign: 'right' }}>Count</th>
                <th style={{ textAlign: 'left' }}>Last seen</th>
                <th style={{ textAlign: 'left' }}>Pages</th>
                <th style={{ textAlign: 'left' }}>Versions</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {errors.map(e => (
                <tr key={e.id} style={{ verticalAlign: 'top' }}>
                  <td style={{ maxWidth: 480 }}>
                    <button
                      type="button"
                      onClick={() => toggle(e.id)}
                      aria-expanded={open.has(e.id)}
                      style={{ background: 'none', border: 'none', color: 'var(--text)', padding: 0, textAlign: 'left', cursor: 'pointer', font: 'inherit', wordBreak: 'break-word' }}
                    >
                      {open.has(e.id) ? '▾ ' : '▸ '}{e.message}
                    </button>
                    <div style={{ color: 'var(--dim)', fontSize: '.75rem' }}>
                      {e.source}{e.app_slug ? ` · ${e.app_slug}` : ''}
                      {e.last_user_name ? ` · last by ${e.last_user_name}` : ''}
                      {` · first ${serverDate(e.first_seen).toLocaleString()}`}
                    </div>
                    {open.has(e.id) && (
                      <>
                        <pre style={{ whiteSpace: 'pre-wrap', fontSize: '.72rem', background: 'var(--surface2)', padding: 8, borderRadius: 6, marginTop: 6 }}>
                          {e.stack || '(no stack)'}
                        </pre>
                        {e.user_agent && <div style={{ color: 'var(--dim)', fontSize: '.72rem' }}>{e.user_agent}</div>}
                      </>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>{e.count}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{serverDate(e.last_seen).toLocaleString()}</td>
                  <td style={{ fontSize: '.8rem' }}>{e.pages.join(', ') || '—'}</td>
                  <td style={{ fontSize: '.8rem' }}>{e.versions.join(', ') || '—'}</td>
                  <td><button className="btn btn-sm" onClick={() => resolve(e.id)} disabled={busy}>Resolve</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
