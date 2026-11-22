import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

interface Domain {
  id: number
  domain: string
  status: 'pending' | 'verified' | 'unverified' | 'legacy'
  admits_signups: boolean
  txt_name: string
  txt_value: string
  last_checked_at: string | null
  last_result: string | null
}

const STATUS_TEXT: Record<Domain['status'], string> = {
  pending: 'pending: add the TXT record',
  verified: 'verified',
  unverified: 'record gone or changed',
  legacy: 'added before verification; still admits sign-ups',
}

export function SsoDomainsCard() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [add, setAdd] = useState('')
  const [msg, setMsg] = useState('')
  const errText = (e: unknown) => (e instanceof Error ? e.message : String(e))

  const load = useCallback(() => {
    adminApi.get<{ domains: Domain[] }>('/api/sso-domains').then(r => setDomains(r.domains)).catch(() => {})
  }, [])
  useEffect(() => { load() }, [load])

  const create = () => adminApi.post('/api/sso-domains', { domain: add }).then(() => { setAdd(''); load() }).catch(e => setMsg(errText(e)))
  const verify = (d: Domain) => adminApi.post<{ result: string }>(`/api/sso-domains/${d.id}/verify`)
    .then(r => { setMsg(`${d.domain}: ${r.result}`); load() }).catch(e => setMsg(errText(e)))
  const remove = (d: Domain) => {
    if (!window.confirm(`Remove ${d.domain}? It stops admitting sign-ups.`)) return
    adminApi.del(`/api/sso-domains/${d.id}`).then(load).catch(e => setMsg(errText(e)))
  }

  return (
    <div className="card">
      <h3>Sign-in domains</h3>
      <p style={{ color: 'var(--dim)', fontSize: '.82rem', margin: '4px 0 10px' }}>
        A domain on the OIDC "join without approval" list lets new people in only once a DNS TXT record proves the organization
        controls it. Unverified domains send new people to the sign-up request queue. Checked hourly and on demand.
      </p>
      {domains.map(d => (
        <div key={d.id} style={{ borderTop: '1px solid var(--border)', padding: '6px 0', fontSize: '.85rem' }}>
          <strong>{d.domain}</strong>{' '}
          <span className="badge" style={{ color: d.admits_signups ? 'var(--success, #2a2)' : 'var(--warning, #c90)' }}>{STATUS_TEXT[d.status]}</span>
          {d.status !== 'verified' && <div><code style={{ wordBreak: 'break-all' }}>TXT {d.txt_name} "{d.txt_value}"</code></div>}
          {d.last_result && <div style={{ color: 'var(--dim)' }}>Last check {d.last_checked_at}: {d.last_result}</div>}
          <button className="btn" onClick={() => verify(d)}>Verify now</button>{' '}
          <button className="btn" onClick={() => remove(d)}>Remove</button>
        </div>
      ))}
      <div style={{ marginTop: 8 }}>
        <input value={add} onChange={e => setAdd(e.target.value)} placeholder="example.com" />{' '}
        <button className="btn" onClick={create} disabled={!add.trim()}>Add domain</button> <span style={{ fontSize: '.85rem' }}>{msg}</span>
      </div>
    </div>
  )
}
