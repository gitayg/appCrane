import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

interface Run {
  id: number
  advisory_id: string
  package: string
  from_version: string | null
  to_version: string | null
  status: string
  reason: string | null
  finished_at: string | null
}

interface Resp {
  in_scope: boolean
  enabled: boolean
  reason: string
  platform_enabled: boolean
  cooldown_hours: number
  opted_out: boolean
  opted_out_by_role: 'owner' | 'platform_admin' | null
  can_change: boolean
  runs: Run[]
}

const dim = { fontSize: '.75rem', color: 'var(--dim)' }

/** Manage page: RCE auto-patch for this app — what it does, the opt-out, recent runs. */
export function AutoPatchAppCard({ slug, reload, onMsg }: {
  slug: string
  reload: number
  onMsg: (m: { text: string; ok: boolean }) => void
}) {
  const [d, setD] = useState<Resp | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    adminApi.get<Resp>(`/api/apps/${encodeURIComponent(slug)}/auto-patch`)
      .then(r => { if (!cancelled) setD(r) })
      .catch(() => { if (!cancelled) setD(null) })
    return () => { cancelled = true }
  }, [slug, reload])

  async function set(optedOut: boolean) {
    setBusy(true)
    try {
      const r = await adminApi.put<Resp>(`/api/apps/${encodeURIComponent(slug)}/auto-patch`, { opted_out: optedOut })
      setD(r)
      onMsg({ text: optedOut ? 'Auto-patch is off for this app.' : 'Auto-patch is on for this app.', ok: true })
    } catch (e) {
      onMsg({ text: (e as Error).message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  if (!d) return null
  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 6 }}>RCE auto-patch</h3>
      <p style={{ ...dim, margin: '0 0 8px' }}>
        On by default. When the dependency scan finds a remote-code-execution advisory with a published fix,
        AppCrane bumps only that package in package-lock.json, deploys it to sandbox, runs the release check
        and promotes it to production without waiting for a person. Production is rolled back if its health
        check fails. Every other fix, and any fix where a guardrail does not hold, stays with a person.
        Owners get an e-mail for each one.
      </p>
      {!d.in_scope ? (
        <div style={dim}>{d.reason}.</div>
      ) : (
        <>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: busy ? 'wait' : d.can_change ? 'pointer' : 'default' }}>
            <input type="checkbox" checked={!d.opted_out} disabled={busy || !d.can_change || !d.platform_enabled}
              onChange={e => set(!e.target.checked)} />
            Auto-approve RCE fixes for this app
          </label>
          <div style={{ ...dim, marginTop: 6 }}>
            {d.enabled ? `On. A fixed version is applied once it has been on the registry for ${d.cooldown_hours}h.` : `Off: ${d.reason}.`}
            {' '}Only npm (package-lock.json) is auto-patched.
            {d.opted_out_by_role === 'platform_admin' && !d.can_change ? ' A platform admin turned this off; only a platform admin can turn it back on.' : ''}
            {!d.can_change && d.opted_out_by_role !== 'platform_admin' ? ' The owner or a platform admin can change this.' : ''}
          </div>
          {d.runs.length > 0 && (
            <ul style={{ listStyle: 'none', padding: 0, margin: '10px 0 0', display: 'flex', flexDirection: 'column', gap: 4 }}>
              {d.runs.map(r => (
                <li key={r.id} style={{ fontSize: '.78rem' }}>
                  <b>{r.status.replace('_', ' ')}</b> {r.package} {r.from_version}{r.to_version ? ` → ${r.to_version}` : ''} ({r.advisory_id})
                  {r.reason && <div style={dim}>{r.reason}</div>}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}
