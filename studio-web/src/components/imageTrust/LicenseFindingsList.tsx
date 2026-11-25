import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

const dim = { color: 'var(--dim)', fontSize: '.78rem' }

export interface LicenseFinding {
  app: string
  component: string
  version: string | null
  license: string
  rule: 'denied' | 'flagged'
  rule_detail: string
  envs: string[]
  deploys: number
  first_seen: string | null
  last_seen: string
}
interface Findings { count: number; by_rule: Record<string, number>; findings: LicenseFinding[]; incomplete: string[] }

const MAX_SHOWN = 50

/** License-policy findings counted once per (app, component, version, license), not once per deploy. */
export function LicenseFindingsList({ slug, reload = 0 }: { slug?: string; reload?: number }) {
  const [data, setData] = useState<Findings | null>(null)
  const [msg, setMsg] = useState('')
  const url = slug ? `/api/apps/${encodeURIComponent(slug)}/license-findings` : '/api/image-trust/license-findings'

  useEffect(() => {
    setMsg('')
    adminApi.get<Findings>(url).then(setData).catch((e) => setMsg((e as Error).message))
  }, [url, reload])

  if (msg) return <p style={{ ...dim, color: 'var(--red)' }}>License findings: {msg}</p>
  if (!data) return null
  const rules = Object.entries(data.by_rule).map(([r, n]) => `${n} ${r}`).join(', ')
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ fontSize: '.8rem' }}>
        <b>License findings: {data.count}</b>
        <span style={dim}> unique (app, component, version, license){rules ? `; ${rules}` : ''}, from each environment&apos;s newest signed deploy</span>
      </div>
      {data.incomplete.length > 0 && (
        <div style={dim}>Recorded before findings were stored in full, so only the first 10 components are listed: {data.incomplete.join(', ')}. The next deploy records all of them.</div>
      )}
      {data.count > 0 && (
        <ul style={{ ...dim, listStyle: 'none', padding: 0, margin: '4px 0 0' }}>
          {data.findings.slice(0, MAX_SHOWN).map((f) => (
            <li key={`${f.app}|${f.component}|${f.version}|${f.license}`}>
              {!slug && <>{f.app}: </>}
              <span className="am-mono">{f.component}{f.version ? `@${f.version}` : ''}</span>{' '}
              <b style={{ color: f.rule === 'denied' ? 'var(--red)' : 'var(--orange)' }}>{f.license}</b>{' '}
              ({f.rule}: {f.rule_detail}) · {f.envs.join(', ')} · reported by {f.deploys} deploy(s)
            </li>
          ))}
          {data.count > MAX_SHOWN && <li>and {data.count - MAX_SHOWN} more</li>}
        </ul>
      )}
    </div>
  )
}
