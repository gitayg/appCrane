import { useState, useEffect } from 'react'
import { adminApi } from '../adminApi'

interface AppKey {
  id: number
  label: string | null
  scope: 'read' | 'deploy' | 'full'
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  revoked_at: string | null
  created_by_name: string | null
  created_by_email: string | null
}

interface CreatedKey {
  id: number
  label: string | null
  scope: string
  api_key: string
  rotated?: boolean
}

interface Props {
  slug: string
  appName: string
}

const SCOPE_BLURBS: Record<AppKey['scope'], string> = {
  read:   'Read-only — list/get/logs/requests. No mutations.',
  deploy: 'Read + trigger deploys + claim/ship requests. No env-var writes.',
  full:   'Full app control — adds env-var read/write. Mirrors Owner power on this app.',
}

export function AppKeysPanel({ slug, appName }: Props) {
  const [keys, setKeys] = useState<AppKey[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [draftLabel, setDraftLabel] = useState('')
  const [draftScope, setDraftScope] = useState<AppKey['scope']>('full')
  const [created, setCreated] = useState<CreatedKey | null>(null)
  const [copied, setCopied] = useState(false)

  function load() {
    adminApi.get<{ keys: AppKey[] }>(`/api/apps/${slug}/keys`)
      .then(r => setKeys(r.keys ?? []))
      .catch(e => setError(e?.message || 'Failed to load keys'))
  }

  useEffect(() => { load() }, [slug])

  async function createKey() {
    if (busy) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ key?: AppKey; api_key?: string }>(
        `/api/apps/${slug}/keys`,
        { label: draftLabel.trim() || null, scope: draftScope },
      )
      const apiKey = r?.api_key ?? ''
      if (!apiKey) throw new Error('Server returned no key')
      setCreated({ id: r.key!.id, label: r.key!.label, scope: r.key!.scope, api_key: apiKey })
      setCopied(false)
      setCreateOpen(false)
      setDraftLabel('')
      setDraftScope('full')
      load()
    } catch (e) {
      alert('Create failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function rotateKey(k: AppKey) {
    if (!confirm(`Rotate key "${k.label || `#${k.id}`}"?\n\nThe current key stops working immediately. Anything using it must be updated.`)) return
    setBusy(true)
    try {
      const r = await adminApi.post<{ key?: AppKey; api_key?: string }>(
        `/api/apps/${slug}/keys/${k.id}/rotate`,
        {},
      )
      const apiKey = r?.api_key ?? ''
      if (!apiKey) throw new Error('Server returned no key')
      setCreated({ id: k.id, label: k.label, scope: k.scope, api_key: apiKey, rotated: true })
      setCopied(false)
      load()
    } catch (e) {
      alert('Rotate failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }

  async function revokeKey(k: AppKey) {
    if (!confirm(`Revoke key "${k.label || `#${k.id}`}"?\n\nThe key stops working immediately. This cannot be undone.`)) return
    await adminApi.del(`/api/apps/${slug}/keys/${k.id}`).catch(e => alert('Revoke failed: ' + e.message))
    load()
  }

  function copyCreatedKey() {
    if (!created) return
    navigator.clipboard.writeText(created.api_key).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }

  if (error) {
    return (
      <div style={{ padding: '12px 16px', color: 'var(--red)', fontSize: '.85rem' }}>
        {error}
      </div>
    )
  }

  return (
    <div style={{ padding: '12px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
        <div style={{ fontWeight: 600, fontSize: '.78rem', textTransform: 'uppercase', letterSpacing: '.5px', color: 'var(--dim)' }}>
          App-scoped Keys · {appName}
        </div>
        <button
          className="btn btn-xs btn-accent"
          style={{ marginLeft: 'auto' }}
          onClick={() => setCreateOpen(true)}
          disabled={busy}
        >
          + New Key
        </button>
      </div>

      {keys && keys.length === 0 && (
        <div style={{ fontSize: '.82rem', color: 'var(--dim)', padding: '6px 0' }}>
          No keys yet. Click <strong>+ New Key</strong> to issue one for CI / MCP / scripts.
        </div>
      )}

      {keys && keys.length > 0 && (
        <table style={{ width: '100%', fontSize: '.8rem' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Label</th>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Scope</th>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Created</th>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Last used</th>
              <th style={{ textAlign: 'left', color: 'var(--dim)', fontWeight: 500, padding: '4px 8px' }}>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {keys.map(k => {
              const revoked = !!k.revoked_at
              return (
                <tr key={k.id} style={{ opacity: revoked ? 0.5 : 1 }}>
                  <td style={{ padding: '4px 8px' }}>
                    {k.label || <span style={{ color: 'var(--dim)' }}>(no label)</span>}
                  </td>
                  <td style={{ padding: '4px 8px' }}>
                    <span title={SCOPE_BLURBS[k.scope]} style={{
                      fontFamily: 'monospace', fontSize: '.72rem',
                      background: 'var(--surface2)', border: '1px solid var(--border)',
                      borderRadius: 3, padding: '1px 7px',
                    }}>{k.scope}</span>
                  </td>
                  <td style={{ padding: '4px 8px', color: 'var(--dim)', fontSize: '.78rem' }}>
                    {new Date(k.created_at).toLocaleDateString()}
                    {k.created_by_name && <span title={k.created_by_email || ''} style={{ marginLeft: 6 }}>· {k.created_by_name}</span>}
                  </td>
                  <td style={{ padding: '4px 8px', color: 'var(--dim)', fontSize: '.78rem' }}>
                    {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : <span>never</span>}
                  </td>
                  <td style={{ padding: '4px 8px', fontSize: '.78rem' }}>
                    {revoked
                      ? <span style={{ color: 'var(--red)' }}>revoked</span>
                      : <span style={{ color: 'var(--green)' }}>active</span>}
                  </td>
                  <td style={{ padding: '4px 8px', textAlign: 'right' }}>
                    {!revoked && (
                      <span style={{ display: 'inline-flex', gap: 4 }}>
                        <button className="btn btn-xs" onClick={() => rotateKey(k)} disabled={busy}>Rotate</button>
                        <button className="btn btn-xs btn-red" onClick={() => revokeKey(k)} disabled={busy}>Revoke</button>
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      {/* Create modal */}
      {createOpen && (
        <div onClick={() => !busy && setCreateOpen(false)} style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
        }}>
          <div onClick={e => e.stopPropagation()} style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 12, padding: 24, width: '92%', maxWidth: 460,
          }}>
            <h3 style={{ margin: '0 0 12px', fontSize: '1rem' }}>New key for {appName}</h3>
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: '.78rem', color: 'var(--dim)', display: 'block', marginBottom: 4 }}>Label (optional)</label>
              <input
                value={draftLabel}
                onChange={e => setDraftLabel(e.target.value)}
                placeholder="e.g. github-actions-prod-deploy"
                style={{
                  width: '100%', padding: '6px 10px', fontSize: '.85rem',
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, color: 'var(--text)',
                }}
              />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: '.78rem', color: 'var(--dim)', display: 'block', marginBottom: 4 }}>Scope</label>
              <select
                value={draftScope}
                onChange={e => setDraftScope(e.target.value as AppKey['scope'])}
                style={{
                  width: '100%', padding: '6px 10px', fontSize: '.85rem',
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, color: 'var(--text)',
                }}
              >
                <option value="read">read — list / get / logs / requests</option>
                <option value="deploy">deploy — read + trigger deploys + ship</option>
                <option value="full">full — deploy + env vars (Owner power)</option>
              </select>
              <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 6, lineHeight: 1.5 }}>
                {SCOPE_BLURBS[draftScope]}
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button className="btn" onClick={() => setCreateOpen(false)} disabled={busy}>Cancel</button>
              <button className="btn btn-accent" onClick={createKey} disabled={busy}>
                {busy ? 'Creating…' : 'Create key'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* "Created" copy-once modal */}
      {created && (
        <div onClick={() => setCreated(null)} style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
        }}>
          <div onClick={e => e.stopPropagation()} style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 12, padding: 28, maxWidth: 580, width: '92%',
          }}>
            <h3 style={{ margin: '0 0 6px', color: 'var(--green)', fontSize: '1.1rem' }}>
              ✓ {created.rotated ? 'Key rotated' : 'Key created'}
            </h3>
            <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 18 }}>
              <strong style={{ color: 'var(--text)' }}>{created.label || `#${created.id}`}</strong> · scope <code style={{ fontFamily: 'monospace' }}>{created.scope}</code> · app <code style={{ fontFamily: 'monospace' }}>{slug}</code>
            </p>
            <div style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>API key</span>
                <button className="btn btn-accent" onClick={copyCreatedKey} style={{ fontSize: '.78rem', padding: '4px 14px' }}>
                  {copied ? '✓ Copied' : 'Copy key'}
                </button>
              </div>
              <code onClick={copyCreatedKey} style={{
                display: 'block', background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '12px 14px', fontFamily: 'monospace',
                fontSize: '.85rem', wordBreak: 'break-all', cursor: 'pointer',
                fontWeight: 700, userSelect: 'all',
              }}>
                {created.api_key}
              </code>
            </div>
            <div style={{
              padding: '10px 14px', background: 'rgba(234,179,8,.08)',
              border: '1px solid rgba(234,179,8,.3)', borderRadius: 6,
              fontSize: '.82rem', color: 'var(--yellow)', marginBottom: 16,
            }}>
              ⚠ This key will <strong>not be shown again</strong>. Copy it now.
            </div>
            <p style={{ fontSize: '.78rem', color: 'var(--dim)', marginBottom: 16 }}>
              Use it in MCP setup, CI env, or any non-human integration:
              <br />
              <code style={{ fontFamily: 'monospace', color: 'var(--text)' }}>
                X-API-Key: {created.api_key.slice(0, 20)}…
              </code>
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn" onClick={() => setCreated(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
