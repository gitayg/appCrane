import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { downloadAuthed } from './download'

const dim = { color: 'var(--dim)', fontSize: '.82rem' }

interface Policy { mode: string; modes: string[]; denied: string[]; flagged: string[]; key_id: string | null }
interface EnvState { app: string; env: string; image_id: string | null; state: string; detail?: string }

const toList = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

/** Settings → Security: verify-before-run mode, license policy, and signing what already runs. */
export function ImageTrustPolicyCard() {
  const [p, setP] = useState<Policy | null>(null)
  const [denied, setDenied] = useState('')
  const [flagged, setFlagged] = useState('')
  const [envs, setEnvs] = useState<EnvState[] | null>(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  const show = (x: Policy) => { setP(x); setDenied(x.denied.join(', ')); setFlagged(x.flagged.join(', ')) }
  useEffect(() => { adminApi.get<Policy>('/api/image-trust/policy').then(show).catch((e) => setMsg((e as Error).message)) }, [])

  async function act(fn: () => Promise<void>) {
    setBusy(true)
    setMsg('')
    try { await fn() } catch (e) { setMsg((e as Error).message) } finally { setBusy(false) }
  }
  const save = (patch: Partial<Policy>) => act(async () => {
    show({ ...(p as Policy), ...(await adminApi.put<Policy>('/api/image-trust/policy', patch)) })
    setMsg('Saved.')
  })

  if (!p) return msg ? <div className="card"><h3>Image signing</h3><p style={dim}>{msg}</p></div> : null
  const unsigned = envs?.filter((e) => e.state === 'unsigned').length ?? 0
  return (
    <div className="card">
      <h3>Image signing</h3>
      <p style={{ ...dim, margin: '4px 0 10px' }}>
        Every deploy signs its image with this instance&apos;s key and records an SBOM and SLSA provenance. Before a
        container starts, its image must carry that signature: <b>warn</b> logs an unsigned or changed image and starts
        it, <b>enforce</b> refuses it. Check the census before turning enforce on.
      </p>
      <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        Verify before run
        <select value={p.mode} disabled={busy} onChange={(e) => save({ mode: e.target.value })}>
          {p.modes.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </label>
      <div style={{ display: 'grid', gap: 6, marginTop: 10 }}>
        <label>Denied licenses (fail the license check)
          <input className="am-input" value={denied} onChange={(e) => setDenied(e.target.value)} placeholder="GPL-3.0-only, SSPL-1.0" />
        </label>
        <label>Flagged licenses (warn)
          <input className="am-input" value={flagged} onChange={(e) => setFlagged(e.target.value)} placeholder="AGPL-3.0-only, unknown" />
        </label>
        <div><button className="btn btn-sm" disabled={busy} onClick={() => save({ denied: toList(denied), flagged: toList(flagged) })}>Save license policy</button></div>
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
        <button className="btn btn-sm" disabled={busy} onClick={() => act(async () => setEnvs((await adminApi.get<{ envs: EnvState[] }>('/api/image-trust/census')).envs))}>Census of running images</button>
        <button className="btn btn-sm" disabled={busy || !envs || unsigned === 0} onClick={() => act(async () => setEnvs((await adminApi.post<{ envs: EnvState[] }>('/api/image-trust/sign-current')).envs))}>Sign {unsigned} running unsigned image(s)</button>
        {p.key_id && <button className="btn btn-sm" disabled={busy} onClick={() => act(() => downloadAuthed('/api/image-trust/public-key', 'appcrane-signing.pub'))}>Public key ({p.key_id.slice(0, 12)})</button>}
      </div>
      {envs && (
        <ul style={{ ...dim, listStyle: 'none', padding: 0, margin: '8px 0 0' }}>
          {envs.map((e) => <li key={`${e.app}/${e.env}`}>{e.app}/{e.env}: <b>{e.state}</b>{e.detail ? ` (${e.detail})` : ''}</li>)}
        </ul>
      )}
      {msg && <p style={dim}>{msg}</p>}
    </div>
  )
}
