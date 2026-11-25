import { useEffect, useState } from 'react'
import { adminApi, ApiError } from '../../adminApi'
import { downloadAuthed } from './download'
import { LicenseFindingsList } from './LicenseFindingsList'

const dim = { color: 'var(--dim)', fontSize: '.82rem' }

interface Policy { mode: string; modes: string[]; denied: string[]; flagged: string[]; key_id: string | null }
interface EnvState { app: string; env: string; image_id: string | null; state: string; detail?: string }
interface DiskImage { app: string | null; env: string | null; image_ref: string; image_id: string; state: string; detail?: string }
interface TrustEvent { app: string; env: string; kind: string; what: string | null; image_ref: string | null; count: number; last_at: string; reason: string | null }
interface Census { envs: EnvState[]; enforce_ready: boolean; on_disk: DiskImage[]; on_disk_error?: string; events: TrustEvent[] }

const toList = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

/** Settings → Security: verify-before-run mode, license policy, and signing what already runs. */
export function ImageTrustPolicyCard() {
  const [p, setP] = useState<Policy | null>(null)
  const [denied, setDenied] = useState('')
  const [flagged, setFlagged] = useState('')
  const [envs, setEnvs] = useState<EnvState[] | null>(null)
  const [census, setCensus] = useState<Census | null>(null)
  const [blocked, setBlocked] = useState<EnvState[] | null>(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  const show = (x: Policy) => { setP(x); setDenied(x.denied.join(', ')); setFlagged(x.flagged.join(', ')) }
  useEffect(() => { adminApi.get<Policy>('/api/image-trust/policy').then(show).catch((e) => setMsg((e as Error).message)) }, [])

  async function act(fn: () => Promise<void>) {
    setBusy(true)
    setMsg('')
    try { await fn() } catch (e) { setMsg((e as Error).message) } finally { setBusy(false) }
  }
  const save = (patch: Partial<Policy> & { acknowledge_unsigned?: boolean }) => act(async () => {
    try {
      show({ ...(p as Policy), ...(await adminApi.put<Policy>('/api/image-trust/policy', patch)) })
      setBlocked(null)
      setMsg('Saved.')
    } catch (e) {
      if (e instanceof ApiError && e.code === 'IMAGE_TRUST_NOT_READY') {
        setBlocked((e.details.running_unsigned as EnvState[]) || [])
        return
      }
      throw e
    }
  })
  const loadCensus = async () => {
    const c = await adminApi.get<Census>('/api/image-trust/census')
    setCensus(c)
    setEnvs(c.envs)
  }
  const signRunning = () => act(async () => {
    setEnvs((await adminApi.post<{ envs: EnvState[] }>('/api/image-trust/sign-current')).envs)
    setBlocked(null)
    await loadCensus()
  })
  const signDisk = () => act(async () => {
    const r = await adminApi.post<{ images: DiskImage[] }>('/api/image-trust/backfill-disk')
    setMsg(`Signed ${r.images.filter((i) => i.state === 'backfilled').length} release image(s) on disk.`)
    await loadCensus()
  })

  if (!p) return msg ? <div className="card"><h3>Image signing</h3><p style={dim}>{msg}</p></div> : null
  const unsigned = envs?.filter((e) => e.state === 'unsigned' || e.state === 'sbom-missing').length ?? 0
  const diskUnsigned = census?.on_disk.filter((i) => i.state === 'unsigned').length ?? 0
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
      {blocked && (
        <div style={{ border: '1px solid var(--orange)', borderRadius: 6, padding: 8, marginTop: 8 }}>
          <b>Enforce not turned on.</b> {blocked.length} running image(s) are not signed by this instance; under enforce
          each of these apps would have its next restart refused:
          <ul style={{ ...dim, margin: '4px 0' }}>
            {blocked.map((e) => <li key={`${e.app}/${e.env}`}>{e.app}/{e.env} <span className="am-mono">{e.image_id?.slice(0, 19)}</span></li>)}
          </ul>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <button className="btn btn-sm" disabled={busy} onClick={signRunning}>Sign current images</button>
            <button className="btn btn-sm" disabled={busy} onClick={() => save({ mode: 'enforce', acknowledge_unsigned: true })}>Switch to enforce anyway</button>
          </div>
        </div>
      )}
      <div style={{ display: 'grid', gap: 6, marginTop: 10 }}>
        <label>Denied licenses (fail the license check)
          <input className="am-input" value={denied} onChange={(e) => setDenied(e.target.value)} placeholder="GPL-3.0-only, SSPL-1.0" />
        </label>
        <label>Flagged licenses (warn)
          <input className="am-input" value={flagged} onChange={(e) => setFlagged(e.target.value)} placeholder="AGPL-3.0-only, unknown" />
        </label>
        <div><button className="btn btn-sm" disabled={busy} onClick={() => save({ denied: toList(denied), flagged: toList(flagged) })}>Save license policy</button></div>
        <LicenseFindingsList />
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
        <button className="btn btn-sm" disabled={busy} onClick={() => act(loadCensus)}>Census of running images</button>
        <button className="btn btn-sm" disabled={busy || !envs || unsigned === 0} onClick={signRunning}>Sign {unsigned} running unsigned or SBOM-less image(s)</button>
        <button className="btn btn-sm" disabled={busy || !census || diskUnsigned === 0} onClick={signDisk}>Sign {diskUnsigned} release image(s) on disk</button>
        {p.key_id && <button className="btn btn-sm" disabled={busy} onClick={() => act(() => downloadAuthed('/api/image-trust/public-key', 'appcrane-signing.pub'))}>Public key ({p.key_id.slice(0, 12)})</button>}
      </div>
      {envs && (
        <ul style={{ ...dim, listStyle: 'none', padding: 0, margin: '8px 0 0' }}>
          {envs.map((e) => <li key={`${e.app}/${e.env}`}>{e.app}/{e.env}: <b>{e.state}</b>{e.detail ? ` (${e.detail})` : ''}</li>)}
        </ul>
      )}
      {census && (
        <div style={{ ...dim, marginTop: 6 }}>
          {census.enforce_ready ? 'Every running image is signed: enforce will not refuse a restart of a running app.' : 'Enforce is not safe yet: sign the running images first.'}
          {census.on_disk_error && <div>On-disk images: {census.on_disk_error}</div>}
          {census.on_disk.filter((i) => i.state !== 'signed').length > 0 && (
            <ul style={{ listStyle: 'none', padding: 0, margin: '4px 0' }}>
              {census.on_disk.filter((i) => i.state !== 'signed').map((i) => <li key={`${i.image_ref}|${i.image_id}`}>on disk {i.image_ref}: <b>{i.state}</b>{i.detail ? ` (${i.detail})` : ''}</li>)}
            </ul>
          )}
          {census.events.length > 0 && (
            <ul style={{ listStyle: 'none', padding: 0, margin: '4px 0' }}>
              {census.events.map((e) => <li key={`${e.app}/${e.env}/${e.kind}/${e.image_ref}`} style={{ color: e.kind === 'refused' ? 'var(--red)' : undefined }}>
                {e.app}/{e.env}: {e.kind === 'refused' ? 'refused' : 'started unsigned'} {e.what || ''} x{e.count}, last {e.last_at}</li>)}
            </ul>
          )}
        </div>
      )}
      {msg && <p style={dim}>{msg}</p>}
    </div>
  )
}
