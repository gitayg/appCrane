import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

interface Link {
  id: number
  label: string
  scopes: string[]
  state: 'active' | 'expired' | 'revoked' | 'completed'
  created_at: string
  expires_at: string
  first_opened_at: string | null
  completed_at: string | null
  changes: Record<string, number>
}

interface Change {
  id: number
  scope: string
  status: string
  applied_at: string | null
  rolled_back_at: string | null
  changed_keys?: string[]
  sso_only_turned_off: boolean
}

const SCOPE_LABEL: Record<string, string> = { oidc: 'OIDC', saml: 'SAML', scim: 'SCIM token and logs', domains: 'Domains', siem: 'SIEM destination' }

export function ItSetupLinksCard() {
  const [links, setLinks] = useState<Link[]>([])
  const [scopes, setScopes] = useState<string[]>([])
  const [label, setLabel] = useState('')
  const [picked, setPicked] = useState<string[]>([])
  const [days, setDays] = useState(7)
  const [url, setUrl] = useState('')
  const [msg, setMsg] = useState('')
  const [open, setOpen] = useState<{ id: number; changes: Change[] } | null>(null)
  const errText = (e: unknown) => (e instanceof Error ? e.message : String(e))

  const load = useCallback(() => {
    adminApi.get<{ links: Link[]; scopes: string[] }>('/api/it-setup-links').then(r => { setLinks(r.links); setScopes(r.scopes) }).catch(() => {})
  }, [])
  useEffect(() => { load() }, [load])

  const create = () => {
    setMsg(''); setUrl('')
    adminApi.post<{ url: string }>('/api/it-setup-links', { label, scopes: picked, expires_in_days: days })
      .then(r => { setUrl(r.url); setLabel(''); setPicked([]); load() })
      .catch(e => setMsg(errText(e)))
  }
  const revoke = (l: Link) => {
    if (!window.confirm(`Revoke the setup link "${l.label}"? It stops working at once.`)) return
    adminApi.post(`/api/it-setup-links/${l.id}/revoke`).then(load).catch(e => setMsg(errText(e)))
  }
  const review = (l: Link) => {
    adminApi.get<{ changes: Change[] }>(`/api/it-setup-links/${l.id}`).then(r => setOpen({ id: l.id, changes: r.changes })).catch(e => setMsg(errText(e)))
  }
  const rollback = (id: number, force = false) => {
    adminApi.post(`/api/it-setup-links/${id}/rollback`, { force })
      .then(() => { setMsg('Rolled back the last applied change.'); load(); review({ id } as Link) })
      .catch(e => {
        const m = errText(e)
        if (!force && /Changed since/i.test(m) && window.confirm(`${m}\n\nRoll back anyway?`)) return rollback(id, true)
        setMsg(m)
      })
  }

  return (
    <div className="card">
      <h3>IT setup links</h3>
      <p style={{ color: 'var(--dim)', fontSize: '.82rem', margin: '4px 0 10px' }}>
        A link for a customer's IT contact who has no AppCrane account. It opens a setup page with only the sections you choose,
        expires, and can be revoked. Changes take effect when they confirm them; you are e-mailed when they finish.
        The page cannot turn off password sign-in or turn on "Require SSO sign-in".
      </p>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input value={label} onChange={e => setLabel(e.target.value)} placeholder="Who it is for" />
        {scopes.map(s => (
          <label key={s} style={{ fontSize: '.85rem' }}>
            <input type="checkbox" checked={picked.includes(s)}
              onChange={e => setPicked(p => e.target.checked ? [...p, s] : p.filter(x => x !== s))} /> {SCOPE_LABEL[s] || s}
          </label>
        ))}
        <label style={{ fontSize: '.85rem' }}>Expires in <input type="number" min={1} max={30} value={days} onChange={e => setDays(Number(e.target.value))} style={{ width: 50 }} /> days</label>
        <button className="btn" onClick={create} disabled={!label.trim() || !picked.length}>Create link</button>
      </div>
      {url && (
        <p style={{ fontSize: '.85rem' }}>Copy this link now; it is not shown again:<br /><code style={{ wordBreak: 'break-all' }}>{url}</code></p>
      )}
      {msg && <p style={{ fontSize: '.85rem' }}>{msg}</p>}
      {links.map(l => (
        <div key={l.id} style={{ borderTop: '1px solid var(--border)', padding: '8px 0', fontSize: '.85rem' }}>
          <strong>{l.label}</strong> <span className="badge">{l.state}</span>{' '}
          <span style={{ color: 'var(--dim)' }}>
            {l.scopes.map(s => SCOPE_LABEL[s] || s).join(', ')} · expires {l.expires_at}
            {l.first_opened_at ? ` · opened ${l.first_opened_at}` : ' · not opened'}
            {l.changes.applied ? ` · ${l.changes.applied} applied` : ''}
          </span>{' '}
          <button className="btn" onClick={() => review(l)}>Review changes</button>{' '}
          {l.state === 'active' && <button className="btn" onClick={() => revoke(l)}>Revoke</button>}
          {open?.id === l.id && (
            <div style={{ marginTop: 6 }}>
              {open.changes.length === 0 && <div style={{ color: 'var(--dim)' }}>No changes.</div>}
              {open.changes.map(c => (
                <div key={c.id}>
                  #{c.id} {c.scope.toUpperCase()} {c.status}
                  {c.applied_at ? ` ${c.applied_at}` : ''}
                  {c.changed_keys?.length ? ` (${c.changed_keys.join(', ')})` : ''}
                  {c.sso_only_turned_off ? ' · left "Require SSO sign-in" off' : ''}
                </div>
              ))}
              {open.changes.some(c => c.status === 'applied') && (
                <button className="btn" onClick={() => rollback(l.id)}>Roll back the last applied change</button>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
