import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { ClientSourcesPolicy } from './blueprintTypes'

// Settings > Security (platform admin): which kinds of MCP client sign-in are
// accepted besides dynamic registration. Backed by /api/oauth/admin/policy.
export function ClientSourcesCard() {
  const [p, setP] = useState<ClientSourcesPolicy | null>(null)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    adminApi.get<ClientSourcesPolicy>('/api/oauth/admin/policy').then(setP).catch(e => setMsg({ text: (e as Error).message, ok: false }))
  }, [])

  const save = async (field: 'cimd_enabled' | 'id_jag_enabled', value: boolean) => {
    setBusy(true)
    setMsg(null)
    try {
      setP(await adminApi.put<ClientSourcesPolicy>('/api/oauth/admin/policy', { [field]: value }))
      setMsg({ text: 'Saved', ok: true })
    } catch (e) { setMsg({ text: (e as Error).message, ok: false }) } finally { setBusy(false) }
  }

  if (!p) return msg ? <div className="setting-card"><p role="alert">{msg.text}</p></div> : null
  const jagBlocked = !p.crane_domain_set
  return (
    <div className="setting-card">
      <h3>How MCP clients identify themselves</h3>
      {msg && <div role={msg.ok ? 'status' : 'alert'} style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.8rem', marginBottom: 8 }}>{msg.text}</div>}
      <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: '.85rem', margin: '6px 0' }}>
        <input type="checkbox" checked={p.cimd_enabled} disabled={busy} onChange={e => save('cimd_enabled', e.target.checked)} />
        <span><strong>Accept client metadata documents</strong><br />
          <span style={{ color: 'var(--dim)' }}>
            An app can use a web address it controls as its ID (the current MCP standard). AppCrane downloads that small file
            to read the app's name and where it may send people back, and shows the address's host on the approval screen.
            The registration rule above still applies.
          </span></span>
      </label>
      <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: '.85rem', margin: '10px 0 6px' }}>
        <input type="checkbox" checked={p.id_jag_enabled} disabled={busy || (jagBlocked && !p.id_jag_enabled)} onChange={e => save('id_jag_enabled', e.target.checked)} />
        <span><strong>Accept sign-in assertions from your identity provider (ID-JAG)</strong><br />
          <span style={{ color: 'var(--dim)' }}>
            Your SSO provider can vouch for a person so an approved agent gets a short-lived MCP token without anyone clicking
            Approve. Only clients a platform admin approved, that use a client secret and have a pinned blueprint, may use it.
            Assertions must come from the SSO provider configured for sign-in.
          </span></span>
      </label>
      {jagBlocked && (
        <p role="alert" style={{ fontSize: '.8rem', margin: '4px 0 0 24px', padding: '6px 10px', borderRadius: 6, border: '1px solid var(--red)', color: 'var(--red)' }}>
          Blocked: set CRANE_DOMAIN on this server first. Without it, the address an assertion must be made out to would come
          from each request, which the caller controls.
        </p>
      )}
      {!p.oidc_configured && (
        <p role="note" style={{ fontSize: '.8rem', margin: '4px 0 0 24px', color: 'var(--yellow-text, #a16207)' }}>
          No OIDC sign-in provider is configured, so no assertion can be accepted yet.
        </p>
      )}
    </div>
  )
}
