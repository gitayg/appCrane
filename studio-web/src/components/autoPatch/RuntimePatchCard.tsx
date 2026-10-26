import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

interface RuntimePolicy { auto_patch_enabled: boolean; policy: string; pull_app_dockerfiles: boolean }
interface Exposure {
  slug: string; env: string; runtime: string; version: string; fixed_version: string | null
  advisories: string[]; handling: 'auto' | 'person'; why: string
}
interface Run { id: number; app_slug: string; runtime: string; advisory_key: string; from_version: string | null; to_version: string | null; status: string; reason: string | null }
interface View { policy: RuntimePolicy; survey: { at: string | null; rows: Exposure[] }; recent: Run[] }

const dim = { color: 'var(--dim)', fontSize: '.82rem' }
const label = (rt: string) => (rt === 'php' ? 'PHP' : rt === 'node' ? 'Node.js' : rt)

/** Settings → Security: apps on a runtime with a remote-code-execution flaw, and fresh base images. */
export function RuntimePatchCard() {
  const [v, setV] = useState<View | null>(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    adminApi.get<View>('/api/runtime-patch').then(setV).catch(e => setMsg(String(e?.message || e)))
  }, [])

  async function setPull(on: boolean) {
    setBusy(true)
    setMsg('')
    try {
      const r = await adminApi.put<{ policy: RuntimePolicy }>('/api/runtime-patch/policy', { pull_app_dockerfiles: on })
      setV(cur => (cur ? { ...cur, policy: r.policy } : cur))
      setMsg('Saved.')
    } catch (e) {
      setMsg((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (!v) return msg ? <div className="card"><h3>Runtime patching</h3><p style={dim}>{msg}</p></div> : null
  const rows = v.survey.rows
  return (
    <div className="card">
      <h3>Runtime patching</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        Every build pulls a fresh copy of its base image, so a rebuild gets the latest security fixes of that tag; if the
        pull fails the build uses the copy already on this server and says so in the deploy log. When an app runs a
        language runtime with a remote-code-execution flaw and a fixed base image exists, AppCrane rebuilds the same
        code on it, sandbox first, then production, under {v.policy.policy}
        {v.policy.auto_patch_enabled ? '' : ' (currently off)'}. Apps deployed from a prebuilt image, and runtimes with
        no fix on their branch, are listed for a person.
      </p>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <input type="checkbox" checked={v.policy.pull_app_dockerfiles} disabled={busy} onChange={e => setPull(e.target.checked)} />
        Also pull fresh base images for apps that ship their own Dockerfile
      </label>
      {msg && <p style={dim}>{msg}</p>}
      <h4 style={{ margin: '10px 0 4px' }}>Apps on an affected runtime{v.survey.at ? ` (checked ${new Date(v.survey.at).toLocaleString()})` : ''}</h4>
      {rows.length === 0
        ? <p style={dim}>{v.survey.at ? 'None.' : 'Not checked yet since AppCrane started.'}</p>
        : (
          <table style={{ ...dim, width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr><th align="left">App</th><th align="left">Runtime</th><th align="left">Fixed in</th><th align="left">Advisories</th><th align="left">Who acts</th></tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={`${r.slug}-${r.env}`}>
                  <td>{r.slug} ({r.env})</td>
                  <td>{label(r.runtime)} {r.version}</td>
                  <td>{r.fixed_version || 'no fix on this branch'}</td>
                  <td>{r.advisories.join(', ')}</td>
                  <td title={r.why}>{r.handling === 'auto' ? 'AppCrane' : `A person: ${r.why}`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      {v.recent.length > 0 && (
        <>
          <h4 style={{ margin: '10px 0 4px' }}>Recent rebuilds</h4>
          <ul style={{ ...dim, margin: 0 }}>
            {v.recent.map(r => <li key={r.id}>{r.app_slug}: {r.status.replace('_', ' ')} {label(r.runtime)} {r.from_version}{r.to_version ? ` → ${r.to_version}` : ''} ({r.advisory_key}){r.reason ? ` — ${r.reason}` : ''}</li>)}
          </ul>
        </>
      )}
    </div>
  )
}
