import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { useFlash } from '../formHelpers'

type Runtime = 'runc' | 'runsc'
type Settings = {
  default: Runtime
  host: { runtimes: string[]; runsc: boolean; error: string | null }
  exceptions: { slug: string; runtime: Runtime; reason: string | null; updated_at: string }[]
  takes_effect: string
}

/**
 * Platform setting container_runtime_default (/api/container-runtime/settings):
 * runc, or runsc (gVisor) for every app without an override. The server
 * refuses runsc while this host's Docker daemon has no runsc runtime, and a
 * start that needs it is refused rather than run on runc.
 */
export function ContainerRuntimeCard() {
  const [s, setS] = useState<Settings | null>(null)
  const [choice, setChoice] = useState<Runtime>('runc')
  const [saved, flashSaved] = useFlash()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function show(r: Settings) { setS(r); setChoice(r.default) }

  useEffect(() => {
    adminApi.get<Settings>('/api/container-runtime/settings').then(show).catch(() => {})
  }, [])

  async function save() {
    setBusy(true); setError(null)
    try {
      show(await adminApi.put<Settings>('/api/container-runtime/settings', { default: choice }))
      flashSaved()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="setting-card">
      <h3>Container runtime</h3>
      <p>
        Run app containers under gVisor (<code>runsc</code>), a sandbox kernel between each app and this server,
        so apps from people who don't trust each other can share it. Apps start a little slower and system-call
        heavy work is slower. Owners can move their own app to gVisor; only a platform admin can move an app
        back to <code>runc</code>.
      </p>
      {s && (
        <p style={{ fontSize: '.8rem', color: s.host.runsc ? 'var(--dim)' : 'var(--yellow, #f59e0b)' }}>
          {s.host.runsc
            ? 'gVisor is installed on this server.'
            : 'gVisor is not installed on this server. Install it from Settings > Job Health > Host limits, then come back.'}
          {s.host.error && <> ({s.host.error})</>}
        </p>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <label htmlFor="rt-default" style={{ fontSize: '.82rem', color: 'var(--dim)', minWidth: 150 }}>Default for all apps</label>
        <select id="rt-default" value={choice} onChange={e => setChoice(e.target.value as Runtime)}>
          <option value="runc">runc (standard Docker)</option>
          <option value="runsc" disabled={!!s && !s.host.runsc}>runsc (gVisor)</option>
        </select>
        <button className="btn btn-accent" onClick={save} disabled={busy || !s || choice === s.default}>{busy ? 'Saving...' : 'Save'}</button>
        {saved && <span className="saved-msg">Saved</span>}
      </div>
      {s && <p style={{ fontSize: '.78rem', color: 'var(--dim)' }}>Applies {s.takes_effect}.</p>}
      {s && s.exceptions.length > 0 && (
        <div style={{ fontSize: '.82rem', marginTop: 6 }}>
          <div style={{ color: 'var(--dim)' }}>Apps kept on runc by a platform admin:</div>
          <ul style={{ margin: '4px 0 0 18px' }}>
            {s.exceptions.map(x => <li key={x.slug}><code>{x.slug}</code>{x.reason ? `: ${x.reason}` : ''}</li>)}
          </ul>
        </div>
      )}
      {error && <div style={{ fontSize: '.82rem', color: 'var(--red)', marginTop: 6 }}>{error}</div>}
    </div>
  )
}
