import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

interface Policy { name: string; enabled: boolean; cooldown_hours: number }
interface Run { id: number; app_slug: string; package: string; from_version: string | null; to_version: string | null; advisory_id: string; status: string; reason: string | null }

const dim = { color: 'var(--dim)', fontSize: '.82rem' }

/** Settings → Security: the platform switch for RCE auto-patch. */
export function AutoPatchPolicyCard() {
  const [p, setP] = useState<Policy | null>(null)
  const [recent, setRecent] = useState<Run[]>([])
  const [hours, setHours] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    adminApi.get<{ policy: Policy; recent: Run[] }>('/api/auto-patch/policy')
      .then(r => { setP(r.policy); setRecent(r.recent); setHours(String(r.policy.cooldown_hours)) })
      .catch(e => setMsg(String(e?.message || e)))
  }, [])

  async function save(patch: Partial<Policy>) {
    setBusy(true)
    setMsg('')
    try {
      const r = await adminApi.put<{ policy: Policy }>('/api/auto-patch/policy', patch)
      setP(r.policy)
      setHours(String(r.policy.cooldown_hours))
      setMsg('Saved.')
    } catch (e) {
      setMsg((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (!p) return msg ? <div className="card"><h3>RCE auto-patch</h3><p style={dim}>{msg}</p></div> : null
  return (
    <div className="card">
      <h3>RCE auto-patch</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        On by default. A written policy ({p.name}) approves, in place of a person, a dependency fix for a
        remote-code-execution advisory on apps whose repository AppCrane hosts. It bumps only the vulnerable npm
        package to the fixed version, deploys to sandbox, and promotes to production only if sandbox is healthy,
        the fixed version has no advisory of its own and has been published for the cooldown, and the release
        check passes. Production is rolled back if it fails its health check. Each run is audited as
        change.auto_approved and owners get an e-mail. Every other fix keeps the human approval step. App owners
        can opt their app out on its Manage page.
      </p>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <input type="checkbox" checked={p.enabled} disabled={busy} onChange={e => save({ enabled: e.target.checked })} />
        Auto-approve fixes needed to prevent remote code execution
      </label>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        Cooldown after the fixed version is published (hours)
        <input type="number" min={0} max={168} value={hours} disabled={busy} style={{ width: 80 }} onChange={e => setHours(e.target.value)} />
        <button className="btn" disabled={busy || hours === String(p.cooldown_hours)} onClick={() => save({ cooldown_hours: Number(hours) })}>Save</button>
      </label>
      {msg && <p style={dim}>{msg}</p>}
      {recent.length > 0 && (
        <>
          <h4 style={{ margin: '10px 0 4px' }}>Recent runs</h4>
          <ul style={{ ...dim, margin: 0 }}>
            {recent.map(r => <li key={r.id}>{r.app_slug}: {r.status.replace('_', ' ')} {r.package} {r.from_version}{r.to_version ? ` → ${r.to_version}` : ''} ({r.advisory_id}){r.reason ? ` — ${r.reason}` : ''}</li>)}
          </ul>
        </>
      )}
    </div>
  )
}
