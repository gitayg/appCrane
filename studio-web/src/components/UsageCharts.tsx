// Plain-SVG charts for the usage cards: no chart dependency. Each chart scales
// to its container's width through the viewBox; values are in the tooltips.

const W = 600
const PAD = { l: 34, r: 8, t: 8, b: 20 }

export interface Series { name: string; color: string; values: (number | null)[] }

function niceMax(v: number): number {
  if (v <= 4) return Math.max(1, Math.ceil(v))
  const p = Math.pow(10, Math.floor(Math.log10(v)))
  const n = v / p
  return (n <= 2 ? 2 : n <= 5 ? 5 : 10) * p
}

function Axis({ max, h, labels }: { max: number; h: number; labels: string[] }) {
  const ih = h - PAD.t - PAD.b
  const every = Math.max(1, Math.ceil(labels.length / 6))
  const step = (W - PAD.l - PAD.r) / Math.max(1, labels.length)
  return (
    <g fontSize="10" fill="var(--dim)">
      {[0, 0.5, 1].map(f => (
        <g key={f}>
          <line x1={PAD.l} x2={W - PAD.r} y1={PAD.t + ih * (1 - f)} y2={PAD.t + ih * (1 - f)} stroke="var(--border)" strokeWidth="1" />
          <text x={PAD.l - 4} y={PAD.t + ih * (1 - f) + 3} textAnchor="end">{Math.round(max * f)}</text>
        </g>
      ))}
      {labels.map((l, i) => i % every === 0 && (
        <text key={l + i} x={PAD.l + step * (i + 0.5)} y={h - 6} textAnchor="middle">{l}</text>
      ))}
    </g>
  )
}

export function LineChart({ labels, series, height = 160 }: { labels: string[]; series: Series[]; height?: number }) {
  const max = niceMax(Math.max(0, ...series.flatMap(s => s.values.map(v => v ?? 0))))
  const ih = height - PAD.t - PAD.b
  const step = (W - PAD.l - PAD.r) / Math.max(1, labels.length)
  const x = (i: number) => PAD.l + step * (i + 0.5)
  const y = (v: number) => PAD.t + ih * (1 - v / max)
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" role="img" aria-label={series.map(s => s.name).join(', ')}>
        <Axis max={max} h={height} labels={labels} />
        {series.map(s => (
          <g key={s.name}>
            <polyline fill="none" stroke={s.color} strokeWidth="2"
              points={s.values.map((v, i) => (v == null ? null : `${x(i)},${y(v)}`)).filter(Boolean).join(' ')} />
            {s.values.map((v, i) => v != null && (
              <circle key={i} cx={x(i)} cy={y(v)} r={labels.length > 60 ? 0 : 2} fill={s.color}>
                <title>{`${labels[i]} ${s.name}: ${v}`}</title>
              </circle>
            ))}
          </g>
        ))}
      </svg>
      <Legend series={series} />
    </div>
  )
}

export function BarChart({ labels, series, height = 140 }: { labels: string[]; series: Series[]; height?: number }) {
  const totals = labels.map((_, i) => series.reduce((n, s) => n + (s.values[i] ?? 0), 0))
  const max = niceMax(Math.max(0, ...totals))
  const ih = height - PAD.t - PAD.b
  const step = (W - PAD.l - PAD.r) / Math.max(1, labels.length)
  const bw = Math.max(1, step * 0.7)
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" role="img" aria-label={series.map(s => s.name).join(', ')}>
        <Axis max={max} h={height} labels={labels} />
        {labels.map((l, i) => {
          let base = 0
          return (
            <g key={l + i}>
              {series.map(s => {
                const v = s.values[i] ?? 0
                const top = base + v
                const rect = (
                  <rect key={s.name} x={PAD.l + step * i + (step - bw) / 2} width={bw}
                    y={PAD.t + ih * (1 - top / max)} height={ih * (v / max)} fill={s.color}>
                    <title>{`${l} ${s.name}: ${v}`}</title>
                  </rect>
                )
                base = top
                return rect
              })}
            </g>
          )
        })}
      </svg>
      {series.length > 1 && <Legend series={series} />}
    </div>
  )
}

function Legend({ series }: { series: Series[] }) {
  return (
    <div style={{ display: 'flex', gap: 12, fontSize: '.75rem', color: 'var(--dim)' }}>
      {series.map(s => (
        <span key={s.name} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ width: 10, height: 10, background: s.color, display: 'inline-block', borderRadius: 2 }} />{s.name}
        </span>
      ))}
    </div>
  )
}

export function Funnel({ stages }: { stages: { label: string; value: number }[] }) {
  const top = Math.max(1, stages[0]?.value ?? 1)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {stages.map((s, i) => (
        <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '.8rem' }}>
          <span style={{ width: 190, color: 'var(--dim)' }}>{s.label}</span>
          <svg viewBox="0 0 100 10" preserveAspectRatio="none" style={{ flex: 1, height: 14 }}>
            <rect x="0" y="0" width="100" height="10" fill="var(--border)" />
            <rect x="0" y="0" width={(100 * s.value) / top} height="10" fill="var(--accent)" />
          </svg>
          <span style={{ width: 90, textAlign: 'right' }}>
            {s.value}{i > 0 && stages[0].value > 0 ? ` (${Math.round((100 * s.value) / stages[0].value)}%)` : ''}
          </span>
        </div>
      ))}
    </div>
  )
}
