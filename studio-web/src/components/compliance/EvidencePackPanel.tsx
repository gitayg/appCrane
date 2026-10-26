import { useEffect, useRef, useState } from 'react'
import { adminApi, authHeaders } from '../../adminApi'
import { serverDate } from '../../utils/serverDate'

type Degraded = { file: string; source: string; reason: string }
type Pack = {
  id: string; status: 'running' | 'ready' | 'failed'; progress: number; step: string | null
  period: { from: string; to: string }; file_name: string | null; bytes: number | null; sha256: string | null
  degraded: Degraded[]; error: string | null; created_at: string; finished_at: string | null
}
type Verify = { ok: boolean; signature_ok: boolean; manifest_ok: boolean; files: { path: string; ok: boolean }[]; missing: string[]; unexpected: string[]; errors: string[]; pack_id?: string | null }

const BASE = '/api/evidence-packs'
const iso = (d: Date) => d.toISOString().slice(0, 10)
const fmtBytes = (n: number | null) => (n == null ? '-' : n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`)

const CONTROLS: [string, string][] = [
  ['CC6', 'Logical access: users and roles, SSO / SCIM / MFA / session settings, API key policy and ages, access reviews'],
  ['CC7', 'Operations and monitoring: audit log, audit chain verification, events, critical events, SIEM sinks, Job Health, dependency scans'],
  ['CC8', 'Change management: deploys and release checks'],
  ['A1', 'Availability: backup configuration and history, restore drills with RPO and RTO'],
  ['C1', 'Confidentiality: what is encrypted, and key rotation status'],
]

/**
 * Settings → Compliance: build, download and verify a compliance evidence
 * pack for a period. Evidence to support an audit, not a certification.
 */
export function EvidencePackPanel() {
  const today = new Date()
  const [from, setFrom] = useState(iso(new Date(today.getTime() - 89 * 86400000)))
  const [to, setTo] = useState(iso(today))
  const [packs, setPacks] = useState<Pack[]>([])
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [verify, setVerify] = useState<{ label: string; r: Verify } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const load = () => adminApi.get<{ packs: Pack[] }>(BASE).then((d) => setPacks(d.packs)).catch((e) => setMsg({ ok: false, text: (e as Error).message }))
  useEffect(() => { load() }, [])
  const building = packs.some((p) => p.status === 'running')
  useEffect(() => {
    if (!building) return
    const t = setInterval(load, 1500)
    return () => clearInterval(t)
  }, [building])

  async function act(label: string, fn: () => Promise<void>) {
    setBusy(true); setMsg(null)
    try { await fn() } catch (e) { setMsg({ ok: false, text: `${label}: ${(e as Error).message}` }) } finally { setBusy(false) }
  }

  const create = () => act('Build', async () => {
    await adminApi.post(BASE, { from, to })
    setMsg({ ok: true, text: 'Building the evidence pack in the background.' })
    await load()
  })

  const download = (p: Pack) => act('Download', async () => {
    const r = await fetch(`${BASE}/${encodeURIComponent(p.id)}/download`, { headers: authHeaders() })
    if (!r.ok) {
      const body = await r.json().catch(() => ({}))
      throw new Error(body?.error?.message || `HTTP ${r.status}`)
    }
    const url = URL.createObjectURL(await r.blob())
    const a = document.createElement('a')
    a.href = url; a.download = p.file_name || 'evidence-pack.tar.gz'; document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
  })

  const verifyStored = (p: Pack) => act('Verify', async () => {
    setVerify({ label: p.file_name || p.id, r: await adminApi.post<Verify>(`${BASE}/${encodeURIComponent(p.id)}/verify`, {}) })
  })

  const verifyUpload = (f: File) => act('Verify', async () => {
    const r = await fetch(`${BASE}/verify`, { method: 'POST', headers: { ...authHeaders(), 'Content-Type': 'application/gzip' }, body: f })
    const body = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(body?.error?.message || `HTTP ${r.status}`)
    setVerify({ label: f.name, r: body as Verify })
  })

  return (
    <div>
      <h2>Compliance evidence</h2>
      <p style={{ background: 'var(--bg-warn, #fff4d6)', border: '1px solid var(--border-warn, #e0c060)', padding: 10, borderRadius: 6 }}>
        An evidence pack supports an audit. It is <b>not</b> a SOC 2 report, an attestation or a certification.
      </p>
      <p style={{ color: 'var(--text-muted, #888)', fontSize: '.9rem' }}>
        A pack is a <code>.tar.gz</code> with a README, an <code>index.html</code> and evidence files mapped to SOC 2 Trust Services
        Criteria. It never contains passwords, keys, tokens, encrypted values or environment variable values; every file is scanned
        before the pack is written. A signed manifest of SHA-256 hashes lets this instance verify the pack later.
      </p>
      <ul style={{ fontSize: '.9rem' }}>
        {CONTROLS.map(([id, text]) => <li key={id}><b>{id}</b> {text}</li>)}
      </ul>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <label>From <input type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} /></label>
        <label>To <input type="date" value={to} max={iso(today)} onChange={(e) => setTo(e.target.value)} /></label>
        <button className="btn" onClick={create} disabled={busy || building}>{building ? 'Building…' : 'Build evidence pack'}</button>
        <button className="btn" onClick={() => fileRef.current?.click()} disabled={busy}>Verify a pack file…</button>
        <input ref={fileRef} type="file" accept=".tar.gz,.tgz,application/gzip" style={{ display: 'none' }}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) verifyUpload(f); e.target.value = '' }} />
      </div>
      {msg && <p style={{ color: msg.ok ? 'var(--green)' : 'var(--red)' }}>{msg.text}</p>}
      {verify && (
        <div style={{ marginTop: 12, padding: 10, border: `1px solid ${verify.r.ok ? 'var(--green)' : 'var(--red)'}`, borderRadius: 6 }}>
          <b style={{ color: verify.r.ok ? 'var(--green)' : 'var(--red)' }}>{verify.r.ok ? 'Verified' : 'Verification failed'}</b>: {verify.label}
          <div style={{ fontSize: '.85rem' }}>
            Signature {verify.r.signature_ok ? 'valid' : 'invalid'}; {verify.r.files.filter((f) => f.ok).length} of {verify.r.files.length} files match their hashes
            {verify.r.missing.length ? `; missing: ${verify.r.missing.join(', ')}` : ''}
            {verify.r.unexpected.length ? `; not in manifest: ${verify.r.unexpected.join(', ')}` : ''}
          </div>
          {verify.r.errors.length > 0 && <ul style={{ margin: '4px 0 0', fontSize: '.85rem' }}>{verify.r.errors.map((e) => <li key={e}>{e}</li>)}</ul>}
        </div>
      )}
      <h3 style={{ marginTop: 24 }}>Packs</h3>
      {packs.length === 0 && <p>No evidence pack has been built yet.</p>}
      {packs.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ fontSize: '.85rem' }}>
            <thead><tr><th>Created</th><th>Period</th><th>Status</th><th>Size</th><th>Gaps</th><th></th></tr></thead>
            <tbody>
              {packs.map((p) => (
                <tr key={p.id}>
                  <td>{serverDate(p.created_at).toLocaleString()}</td>
                  <td>{p.period.from} to {p.period.to}</td>
                  <td style={{ color: p.status === 'ready' ? 'var(--green)' : p.status === 'failed' ? 'var(--red)' : undefined }}>
                    {p.status === 'running' ? `${p.progress}% ${p.step || ''}` : p.status}{p.error ? ` - ${p.error}` : ''}
                  </td>
                  <td>{fmtBytes(p.bytes)}</td>
                  <td title={p.degraded.map((d) => `${d.file}: ${d.reason}`).join('\n')}>{p.degraded.length || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {p.status === 'ready' && <>
                      <button className="btn" onClick={() => download(p)} disabled={busy}>Download</button>{' '}
                      <button className="btn" onClick={() => verifyStored(p)} disabled={busy}>Verify</button>
                    </>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
