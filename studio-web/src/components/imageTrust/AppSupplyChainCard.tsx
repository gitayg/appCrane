import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { downloadAuthed } from './download'
import { LicenseFindingsList } from './LicenseFindingsList'

const dim = { color: 'var(--dim)', fontSize: '.78rem' }

interface LicenseCheck { status: 'pass' | 'warn' | 'fail'; reasons: string[] }
export interface Attestation {
  id: number
  deployment_id: number | null
  env: string
  origin: string
  image_ref: string
  image_id: string | null
  status: string
  error: string | null
  key_id: string | null
  verified: boolean
  problems: string[]
  sbom: { status: string | null; error: string | null; components: number | null; with_hash: number | null; with_license: number | null }
  license_check: LicenseCheck | null
  documents: string[]
  created_at: string
}

const FILE_NAMES: Record<string, string> = {
  sbom: 'sbom.cdx.json',
  provenance: 'provenance.intoto.json',
  'sbom-attestation': 'sbom.intoto.json',
  'signature-payload': 'image.sig.payload.json',
  signature: 'image.sig',
}

function Badge({ a }: { a: Attestation }) {
  const [text, color] = a.verified ? ['Verified', 'var(--green)']
    : a.status === 'signed' ? ['Signed, does not verify', 'var(--red)']
      : ['Not signed', 'var(--orange)']
  return <span style={{ color, fontWeight: 700, fontSize: '.75rem' }}>{text}</span>
}

/** One deploy's signature status, SBOM summary and downloads. */
export function DeploySupplyChain({ slug, a, onError }: { slug: string; a: Attestation; onError: (m: string) => void }) {
  const lic = a.license_check
  return (
    <li style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: '6px 0', borderTop: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', fontSize: '.8rem' }}>
        <b>#{a.deployment_id ?? '-'}</b>
        <span>{a.env}</span>
        <Badge a={a} />
        {a.origin === 'backfill' && <span style={dim}>signed while running (trust on first use)</span>}
        <span className="am-mono" style={dim}>{a.image_id ? a.image_id.slice(0, 19) : a.image_ref}</span>
        {a.key_id && <span className="am-mono" style={dim}>key {a.key_id.slice(0, 12)}</span>}
      </div>
      {a.sbom.status === 'ok'
        ? <div style={dim}>SBOM: {a.sbom.components} component(s), hash {a.sbom.with_hash}/{a.sbom.components}, license {a.sbom.with_license}/{a.sbom.components}
          {lic && <> · License policy <b style={{ color: lic.status === 'pass' ? 'var(--green)' : lic.status === 'warn' ? 'var(--orange)' : 'var(--red)' }}>{lic.status}</b>: {lic.reasons[0]}</>}
        </div>
        : <div style={dim}>No SBOM: {a.sbom.error || a.error || 'not generated'}</div>}
      {a.problems.length > 0 && <div style={{ ...dim, color: 'var(--red)' }}>{a.problems.join('; ')}</div>}
      {a.documents.length > 0 && a.deployment_id != null && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {a.documents.map((d) => (
            <button key={d} className="btn btn-sm" onClick={() => downloadAuthed(
              `/api/apps/${encodeURIComponent(slug)}/deployments/${a.deployment_id}/attestation/${d}`,
              `${slug}-${a.env}-${a.deployment_id}-${FILE_NAMES[d] || d}`,
            ).catch((e) => onError((e as Error).message))}>{d}</button>
          ))}
        </div>
      )}
    </li>
  )
}

interface TrustEvent { env: string; kind: string; what: string | null; image_ref: string | null; image_id: string | null; reason: string | null; count: number; last_at: string }

/** Manage page: SBOM and signature status of this app's recent deploys. */
export function AppSupplyChainCard({ slug, reload = 0 }: { slug: string; reload?: number }) {
  const [data, setData] = useState<{ mode: string; attestations: Attestation[]; trust_events?: TrustEvent[] } | null>(null)
  const [msg, setMsg] = useState('')

  useEffect(() => {
    setMsg('')
    adminApi.get<{ mode: string; attestations: Attestation[]; trust_events?: TrustEvent[] }>(`/api/apps/${encodeURIComponent(slug)}/attestations`)
      .then(setData)
      .catch((e) => setMsg((e as Error).message))
  }, [slug, reload])

  return (
    <div className="card">
      <h3>Supply chain</h3>
      <p style={{ ...dim, margin: '4px 0 8px' }}>
        Each deploy records a CycloneDX SBOM of its image, SLSA provenance and a signature from this AppCrane instance.
        {data && <> Verify-before-run is <b>{data.mode}</b>.</>}
      </p>
      {msg && <p style={{ ...dim, color: 'var(--red)' }}>{msg}</p>}
      {(data?.trust_events || []).map((e) => (
        <p key={`${e.env}/${e.kind}/${e.image_id}`} style={{ ...dim, color: e.kind === 'refused' ? 'var(--red)' : 'var(--orange)' }}>
          <b>{e.kind === 'refused' ? `Image trust refused to ${e.what || 'start'} ${e.env}` : `${e.env} runs an unsigned image`}</b>
          {' '}({e.count}x, last {e.last_at}): {e.reason}. {e.kind === 'refused' ? 'The container was left as it was. Redeploy, or ask a platform admin to sign the running images.' : 'Enforce mode would refuse its next restart.'}
        </p>
      ))}
      {data && data.attestations.length > 0 && <LicenseFindingsList slug={slug} reload={reload} />}
      {data && data.attestations.length === 0 && <p style={dim}>No deploy of this app has been signed yet.</p>}
      {data && data.attestations.length > 0 && (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {data.attestations.slice(0, 10).map((a) => <DeploySupplyChain key={a.id} slug={slug} a={a} onError={setMsg} />)}
        </ul>
      )}
    </div>
  )
}
