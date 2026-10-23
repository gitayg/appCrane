import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

const dim = { color: 'var(--dim)', fontSize: '.82rem' }

/** Settings → Security: the platform switch for immediate vulnerability e-mails. */
export function VulnAlertsCard() {
  const [on, setOn] = useState<boolean | null>(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    adminApi.get<{ value?: string | null }>('/api/settings/vuln_alerts_immediate')
      .then(r => setOn(String(r?.value ?? 'true').trim().toLowerCase() !== 'false'))
      .catch(e => setMsg(String(e?.message || e)))
  }, [])

  async function save(next: boolean) {
    setBusy(true)
    setMsg('')
    try {
      await adminApi.put('/api/settings/vuln_alerts_immediate', { value: next ? 'true' : 'false' })
      setOn(next)
      setMsg('Saved.')
    } catch (e) {
      setMsg((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (on === null) return msg ? <div className="card"><h3>Vulnerability e-mails</h3><p style={dim}>{msg}</p></div> : null
  return (
    <div className="card">
      <h3>Vulnerability e-mails</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        On by default. When a scan finds a vulnerable package that was not reported before, the app's owners and
        every platform admin get one e-mail listing what was found, the fixed version, and what happens next. Each
        finding is mailed once. The daily digest is sent either way.
      </p>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input type="checkbox" checked={on} disabled={busy} onChange={e => save(e.target.checked)} />
        E-mail owners and platform admins as soon as a new vulnerability is found
      </label>
      {msg && <p style={dim}>{msg}</p>}
    </div>
  )
}
