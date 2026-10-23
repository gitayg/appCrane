import { useState, useEffect } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'

// Personal app sign-in keys (dhk_uak_*), v2.108.0. Each one signs its owner in
// to ONE app's gate — for a script or a cron job that has no browser — and is
// refused by the rest of AppCrane. See server/routes/userAppKeys.js.

interface AppKey {
  id: number
  label: string | null
  app_slug: string
  app_name: string
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  revoked_at: string | null
}
interface EnterableApp { slug: string; name: string }
interface Created { label: string | null; app_name: string; api_key: string }

const th = { textAlign: 'left' as const, color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }
const td = { padding: '4px 8px' }
const dim = { ...td, color: 'var(--dim)', fontSize: '.78rem' }

export function AppKeysCard() {
  const [keys, setKeys] = useState<AppKey[] | null>(null)
  const [apps, setApps] = useState<EnterableApp[]>([])
  const [app, setApp] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState<Created | null>(null)
  const [copied, setCopied] = useState(false)

  function load() {
    adminApi.get<{ keys: AppKey[]; apps: EnterableApp[] }>('/api/me/app-keys')
      .then(r => { setKeys(r.keys ?? []); setApps(r.apps ?? []) })
      .catch(() => setKeys([]))
  }
  useEffect(() => { load() }, [])

  async function createKey() {
    if (busy || !app) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ key: AppKey; api_key: string }>('/api/me/app-keys', { app, label: label.trim() || null })
      if (!r?.api_key) throw new Error('Server returned no key')
      setCreated({ label: r.key.label, app_name: r.key.app_name, api_key: r.api_key })
      setCopied(false)
      setLabel('')
      load()
    } catch (e) {
      alert('Create failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function revokeKey(k: AppKey) {
    if (!confirm(`Revoke the ${k.app_name} key "${k.label || `#${k.id}`}"?\n\nIt stops working immediately.`)) return
    await adminApi.del(`/api/me/app-keys/${k.id}`).catch(e => alert('Revoke failed: ' + e.message))
    load()
  }

  function copyKey() {
    if (!created) return
    navigator.clipboard.writeText(created.api_key).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1800) })
  }

  const expired = (k: AppKey) => !!k.expires_at && serverDate(k.expires_at).getTime() < Date.now()

  return (
    <div className="setting-card">
      <h3>App sign-in keys</h3>
      <p>
        A key that signs you in to <strong>one app</strong>, for a script or scheduled job that has no browser
        (for example the Work Review uploader). It is refused everywhere else in AppCrane, carries only the role
        you hold on that app right now, and expires after 180 days.
      </p>

      {keys && keys.length > 0 && (
        <table style={{ width: '100%', fontSize: '.8rem', marginBottom: 12 }}>
          <thead>
            <tr><th style={th}>App</th><th style={th}>Label</th><th style={th}>Last used</th><th style={th}>Expires</th><th style={th}>Status</th><th></th></tr>
          </thead>
          <tbody>
            {keys.map(k => {
              const dead = !!k.revoked_at || expired(k)
              return (
                <tr key={k.id} style={{ opacity: dead ? 0.5 : 1 }}>
                  <td style={td}>{k.app_name}</td>
                  <td style={td}>{k.label || <span style={{ color: 'var(--dim)' }}>(no label)</span>}</td>
                  <td style={dim}>{k.last_used_at ? serverDate(k.last_used_at).toLocaleString() : 'never'}</td>
                  <td style={dim}>{k.expires_at ? serverDate(k.expires_at).toLocaleDateString() : '—'}</td>
                  <td style={{ ...td, fontSize: '.78rem' }}>
                    {k.revoked_at ? <span style={{ color: 'var(--red)' }}>revoked</span>
                      : expired(k) ? <span style={{ color: 'var(--yellow)' }}>expired</span>
                      : <span style={{ color: 'var(--green)' }}>active</span>}
                  </td>
                  <td style={{ ...td, textAlign: 'right' }}>
                    {!dead && <button className="btn btn-xs btn-red" onClick={() => revokeKey(k)} disabled={busy}>Revoke</button>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <select value={app} onChange={e => setApp(e.target.value)} style={{
          padding: '6px 10px', fontSize: '.85rem', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)',
        }}>
          <option value="">Choose an app…</option>
          {apps.map(a => <option key={a.slug} value={a.slug}>{a.name}</option>)}
        </select>
        <input value={label} onChange={e => setLabel(e.target.value)} placeholder="Optional label (e.g. work-laptop uploader)" style={{
          flex: 1, minWidth: 180, padding: '6px 10px', fontSize: '.85rem', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)',
        }} />
        <button className="btn btn-accent" onClick={createKey} disabled={busy || !app}>{busy ? 'Creating…' : 'Issue key'}</button>
      </div>

      {created && (
        <div onClick={() => setCreated(null)} style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
        }}>
          <div onClick={e => e.stopPropagation()} style={{
            background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, padding: 28, maxWidth: 600, width: '92%',
          }}>
            <h3 style={{ margin: '0 0 6px', color: 'var(--green)', fontSize: '1.1rem' }}>✓ Key created</h3>
            <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 18 }}>
              <strong style={{ color: 'var(--text)' }}>{created.label || 'Unlabelled key'}</strong> · signs in to {created.app_name} only
            </p>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>App sign-in key</span>
              <button className="btn btn-accent" onClick={copyKey} style={{ fontSize: '.78rem', padding: '4px 14px' }}>{copied ? '✓ Copied' : 'Copy key'}</button>
            </div>
            <code onClick={copyKey} style={{
              display: 'block', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '12px 14px',
              fontFamily: 'monospace', fontSize: '.85rem', wordBreak: 'break-all', cursor: 'pointer', fontWeight: 700, userSelect: 'all', marginBottom: 14,
            }}>{created.api_key}</code>
            <div style={{
              padding: '10px 14px', background: 'rgba(234,179,8,.08)', border: '1px solid rgba(234,179,8,.3)', borderRadius: 6,
              fontSize: '.82rem', color: 'var(--yellow)', marginBottom: 16,
            }}>
              ⚠ This key will <strong>not be shown again</strong>. Copy it now.
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setCreated(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
