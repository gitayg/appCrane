import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

// The 24h CPU and memory chart from the apps list's activity dialog
// (Applications.tsx ResourceChart), for the Resources tab.

export interface Series { label: string; color: string; points: { x: number; v: number }[] }
export function ResourceChart({ title, unit, series }: { title: string; unit: string; series: Series[] }) {
  const W = 520, H = 130, PL = 44, PR = 12, PT = 12, PB = 22
  const cw = W - PL - PR, ch = H - PT - PB
  const xs = series.flatMap(s => s.points.map(p => p.x))
  const minX = Math.min(...xs, 0), maxX = Math.max(...xs, 1)
  const maxV = Math.max(...series.flatMap(s => s.points.map(p => p.v)), 1)
  const xOf = (x: number) => PL + ((x - minX) / (maxX - minX || 1)) * cw
  const yOf = (v: number) => PT + ch - (v / maxV) * ch
  const has = series.some(s => s.points.length > 1)
  return (
    <div>
      <div style={{ fontSize: '.8rem', fontWeight: 600, marginBottom: 4 }}>{title}</div>
      {has ? (
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', display: 'block' }}>
          <line x1={PL} y1={PT} x2={PL} y2={PT + ch} stroke="var(--border)" />
          <line x1={PL} y1={PT + ch} x2={W - PR} y2={PT + ch} stroke="var(--border)" />
          <text x={PL - 5} y={PT + 8} textAnchor="end" fontSize="9" fill="var(--dim)">{Math.round(maxV)}{unit}</text>
          <text x={PL - 5} y={PT + ch} textAnchor="end" fontSize="9" fill="var(--dim)">0</text>
          {series.map((s, i) => s.points.length > 1 && (
            <polyline key={i} fill="none" stroke={s.color} strokeWidth="1.5"
              points={s.points.map(p => `${xOf(p.x).toFixed(1)},${yOf(p.v).toFixed(1)}`).join(' ')} />
          ))}
        </svg>
      ) : (
        <div style={{ fontSize: '.78rem', color: 'var(--dim)', padding: '14px 0' }}>No samples yet — collected every 5 minutes while running.</div>
      )}
      <div style={{ display: 'flex', gap: 14, fontSize: '.72rem', color: 'var(--dim)', marginTop: 2 }}>
        {series.map((s, i) => <span key={i}><span style={{ color: s.color }}>●</span> {s.label}</span>)}
      </div>
    </div>
  )
}

type MetricRow = { env: string; cpu_percent: number; mem_mb: number; recorded_at: string }

export function MetricsHistory({ slug, reload }: { slug: string; reload: number }) {
  const [rows, setRows] = useState<MetricRow[] | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    adminApi.get<{ metrics: MetricRow[] }>(`/api/apps/${slug}/metrics?hours=24`)
      .then(r => { setRows(r.metrics || []); setError('') })
      .catch(e => { setRows([]); setError((e as Error).message) })
  }, [slug, reload])
  const toX = (s: string) => new Date(s.includes('T') ? s : s.replace(' ', 'T') + 'Z').getTime()
  const mk = (env: string, field: 'cpu_percent' | 'mem_mb') => (rows || []).filter(r => r.env === env).map(r => ({ x: toX(r.recorded_at), v: r[field] }))
  const series = (field: 'cpu_percent' | 'mem_mb'): Series[] => [
    { label: 'production', color: '#22c55e', points: mk('production', field) },
    { label: 'sandbox', color: '#f5a623', points: mk('sandbox', field) },
  ]
  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>CPU and memory, last 24h</h3>
      {rows === null ? <div style={{ color: 'var(--dim)', fontSize: '.82rem' }}>Loading…</div> : error ? <div style={{ color: 'var(--dim)', fontSize: '.82rem' }}>{error}</div> : (
        <div style={{ display: 'grid', gap: 18, gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
          <ResourceChart title="CPU" unit="%" series={series('cpu_percent')} />
          <ResourceChart title="Memory" unit="MB" series={series('mem_mb')} />
        </div>
      )}
    </div>
  )
}
