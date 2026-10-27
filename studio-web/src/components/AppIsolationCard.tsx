import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { useFlash } from './formHelpers'

type Isolation = { domain?: string; tls_cert_file?: string; tls_key_file?: string; enabled?: boolean; warning?: string | null }

/**
 * Platform setting app_isolation_domain: when set, every app is served on its
 * own address under that domain (<slug>.<domain>, <slug>-sandbox.<domain>)
 * instead of a path on this host. Empty = off. The certificate pair is
 * optional; without it each app address gets its own certificate on first
 * visit. Read and saved together through /api/settings/isolation, which
 * validates them as a set; its `warning` is shown as is.
 */
export function AppIsolationCard() {
  const [domain, setDomain] = useState('')
  const [certFile, setCertFile] = useState('')
  const [keyFile, setKeyFile] = useState('')
  const [saved, flashSaved] = useFlash()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [warning, setWarning] = useState<string | null>(null)

  function show(r: Isolation | undefined) {
    setDomain(r?.domain || '')
    setCertFile(r?.tls_cert_file || '')
    setKeyFile(r?.tls_key_file || '')
    setWarning(r?.warning || null)
  }

  useEffect(() => {
    adminApi.get<Isolation>('/api/settings/isolation').then(show).catch(() => {})
  }, [])

  async function save() {
    setBusy(true); setError(null); setWarning(null)
    try {
      show(await adminApi.put<Isolation>('/api/settings/isolation', {
        domain: domain.trim(), tls_cert_file: certFile.trim(), tls_key_file: keyFile.trim(),
      }))
      flashSaved()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed')
    } finally {
      setBusy(false)
    }
  }

  const example = domain.trim() || 'apps.example.com'

  return (
    <div className="setting-card">
      <h3>App isolation</h3>
      <p>
        Give each app its own web address, such as <code>myapp.{example}</code>, instead of a path on this
        site. Apps on a shared address can act as the person using them in every other app, and can reach
        their AppCrane session. On their own addresses they can't.
      </p>
      <p style={{ fontSize: '.8rem', color: 'var(--dim)' }}>
        Before turning it on, add a wildcard DNS record <code>*.{example}</code> pointing at this server.
        Old links to apps keep working: they forward to the new address. When you turn it on, everyone has to
        sign in again once. Leave the domain empty to keep apps on this site's address.
      </p>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <label htmlFor="iso-domain" style={{ fontSize: '.82rem', color: 'var(--dim)', minWidth: 150 }}>Apps domain</label>
        <input
          type="text" id="iso-domain" placeholder="apps.example.com (empty = off)"
          value={domain} onChange={e => setDomain(e.target.value)}
          style={{ flex: 1, maxWidth: 320 }}
        />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <label htmlFor="iso-cert" style={{ fontSize: '.82rem', color: 'var(--dim)', minWidth: 150 }}>Wildcard certificate file</label>
        <input
          type="text" id="iso-cert" placeholder="optional, e.g. /etc/ssl/apps.pem"
          value={certFile} onChange={e => setCertFile(e.target.value)}
          style={{ flex: 1, maxWidth: 320 }}
        />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <label htmlFor="iso-key" style={{ fontSize: '.82rem', color: 'var(--dim)', minWidth: 150 }}>Certificate key file</label>
        <input
          type="text" id="iso-key" placeholder="optional, e.g. /etc/ssl/apps.key"
          value={keyFile} onChange={e => setKeyFile(e.target.value)}
          style={{ flex: 1, maxWidth: 320 }}
        />
      </div>
      <p style={{ fontSize: '.78rem', color: 'var(--dim)' }}>
        Without a certificate, each app address gets its own certificate automatically the first time it is
        opened. Paths are files on this server.
      </p>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button className="btn btn-accent" onClick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
        {saved && <span className="saved-msg">Saved ✓</span>}
      </div>
      {warning && <div style={{ fontSize: '.82rem', color: 'var(--yellow, #f59e0b)', marginTop: 6 }}>⚠ {warning}</div>}
      {error && <div style={{ fontSize: '.82rem', color: 'var(--red)', marginTop: 6 }}>{error}</div>}
    </div>
  )
}
