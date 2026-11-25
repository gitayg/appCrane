import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'

type Severity = 'high' | 'medium' | 'low' | 'info'

interface Finding {
  id: string
  severity: Severity
  message: string
  fix: string | null
}

interface Entry {
  proto: 'tcp' | 'udp'
  port: number
  slug?: string
  env?: string
  reason?: string
}

interface Stray {
  container: string
  proto: string
  port: number
  host_ip: string
  claimed_by: { slug: string; env: string } | null
}

interface ChainRead {
  state: string
  exists?: boolean
  entries?: Entry[]
  error?: string
}

interface HostNetwork {
  posture: {
    applicable: boolean
    reason: string | null
    at: string
    findings: Finding[]
    families: Record<string, { state: string; skeleton?: string; ext_interface?: string | null; input_policy?: string | null }>
  }
  chain: Record<string, ChainRead>
  desired: Entry[]
  strays: Stray[]
  last_sync: { status: string; at: string; reason: string | null } | null
}

const PATH = '/api/platform/host-network'

const SEVERITY_COLOR: Record<Severity, string> = {
  high: 'var(--red)',
  medium: 'var(--orange)',
  low: 'var(--dim)',
  info: 'var(--dim)',
}

const REASON_LABEL: Record<string, string> = {
  published: 'Published',
  pending_port_release: 'Kept until the container is recreated',
  draining: 'Old port, kept until the container is recreated',
}

function SeverityPill({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLOR[severity] || 'var(--dim)'
  return (
    <span className="badge" style={{
      color, background: `color-mix(in srgb, ${color} 14%, transparent)`,
      whiteSpace: 'nowrap', textTransform: 'capitalize',
    }}>
      {severity}
    </span>
  )
}

function inChain(chain: ChainRead | undefined, e: Entry) {
  return !!chain?.entries?.some(c => c.proto === e.proto && c.port === e.port)
}

export function HostNetworkCard() {
  const [data, setData] = useState<HostNetwork | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    adminApi.get<HostNetwork>(PATH)
      .then(r => { setData(r); setError(null) })
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => { load() }, [load])

  const findings = data?.posture.findings || []

  return (
    <div className="setting-card" style={{ marginTop: 20 }}>
      <h3>Host network</h3>
      <p>Which host ports are reachable from outside. AppCrane opens the ports it publishes for tcp and dual apps; host hardening drops every other port Docker publishes.</p>

      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}
      {!data && !error && <p style={{ color: 'var(--dim)' }}>Loading...</p>}

      {data && !data.posture.applicable && (
        <p style={{ color: 'var(--dim)' }}>{data.posture.reason || 'Not applicable on this server.'}</p>
      )}

      {data && data.posture.applicable && (
        <>
          {findings.length === 0
            ? <p style={{ fontWeight: 600, color: 'var(--green)' }}>No findings.</p>
            : (
              <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse', marginBottom: 12 }}>
                <tbody>
                  {findings.map(f => (
                    <tr key={f.id} style={{ borderTop: '1px solid var(--border)' }}>
                      <td style={{ padding: '8px 6px', width: 90, verticalAlign: 'top' }}><SeverityPill severity={f.severity} /></td>
                      <td style={{ padding: '8px 6px' }}>
                        <div>{f.message}</div>
                        {f.fix && <div style={{ color: 'var(--dim)', fontSize: '.75rem', marginTop: 2 }}>Fix: {f.fix}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

          <h4 style={{ margin: '12px 0 6px' }}>Published ports</h4>
          {data.desired.length === 0
            ? <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>AppCrane publishes no host port on 0.0.0.0.</p>
            : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
                      <th style={{ padding: 6 }}>Port</th>
                      <th style={{ padding: 6 }}>App</th>
                      <th style={{ padding: 6 }}>Why</th>
                      <th style={{ padding: 6 }}>IPv4</th>
                      <th style={{ padding: 6 }}>IPv6</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.desired.map(e => (
                      <tr key={`${e.proto}/${e.port}`} style={{ borderTop: '1px solid var(--border)' }}>
                        <td style={{ padding: 6, fontFamily: 'monospace' }}>{e.port}/{e.proto}</td>
                        <td style={{ padding: 6 }}>{e.slug} <span style={{ color: 'var(--dim)' }}>{e.env}</span></td>
                        <td style={{ padding: 6 }}>{REASON_LABEL[e.reason || ''] || e.reason}</td>
                        {(['v4', 'v6'] as const).map(fam => (
                          <td key={fam} style={{ padding: 6, color: inChain(data.chain[fam], e) ? 'var(--green)' : 'var(--orange)' }}>
                            {inChain(data.chain[fam], e) ? (data.chain[fam]?.state === 'helper' ? 'Open (written by the helper)' : 'Open') : 'Not open'}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

          {data.strays.length > 0 && (
            <>
              <h4 style={{ margin: '12px 0 6px' }}>Published by something else</h4>
              <ul style={{ fontSize: '.85rem', margin: 0, paddingLeft: 18 }}>
                {data.strays.map(s => (
                  <li key={`${s.container}:${s.proto}/${s.port}`}>
                    <span style={{ fontFamily: 'monospace' }}>{s.container}</span> on {s.host_ip}:{s.port}/{s.proto}
                    {s.claimed_by ? ` (port belongs to ${s.claimed_by.slug} ${s.claimed_by.env})` : ''}
                  </li>
                ))}
              </ul>
            </>
          )}

          <p style={{ fontSize: '.75rem', color: 'var(--dim)', marginTop: 10 }}>
            Checked {serverDate(data.posture.at).toLocaleString()}
            {data.last_sync && <> · last firewall sync {serverDate(data.last_sync.at).toLocaleString()} ({data.last_sync.status})</>}
            {' '}<button className="btn" style={{ marginLeft: 6 }} onClick={load}>Refresh</button>
          </p>
        </>
      )}
    </div>
  )
}
