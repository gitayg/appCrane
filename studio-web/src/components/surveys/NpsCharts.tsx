// Small, dependency-free charts for the NPS page: a score distribution and an
// NPS trend. Colours follow the NPS bands: detractors 0-6, passives 7-8,
// promoters 9-10.

export interface NpsStats {
  total: number
  responses: number
  promoters: number
  passives: number
  detractors: number
  nps: number | null
}

export const bandColor = (score: number) => (score >= 9 ? 'var(--green, #22c55e)' : score >= 7 ? 'var(--orange, #f59e0b)' : 'var(--red, #ef4444)')

export function npsText(n: number | null): string {
  return n === null ? '–' : n > 0 ? `+${n}` : String(n)
}

export function StatTiles({ s }: { s: NpsStats }) {
  const pct = (n: number) => (s.responses ? `${Math.round((n / s.responses) * 100)}%` : '–')
  const tiles: [string, string, string?][] = [
    ['NPS', npsText(s.nps), s.nps === null ? undefined : s.nps >= 0 ? 'var(--green, #22c55e)' : 'var(--red, #ef4444)'],
    ['Answers', String(s.total)],
    ['Promoters (9-10)', `${s.promoters} · ${pct(s.promoters)}`],
    ['Passives (7-8)', `${s.passives} · ${pct(s.passives)}`],
    ['Detractors (0-6)', `${s.detractors} · ${pct(s.detractors)}`],
  ]
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10, margin: '12px 0' }}>
      {tiles.map(([label, value, color]) => (
        <div key={label} className="am-card" style={{ padding: '10px 12px' }}>
          <div style={{ color: 'var(--dim)', fontSize: '.75rem' }}>{label}</div>
          <div style={{ fontSize: '1.35rem', fontWeight: 700, color }}>{value}</div>
        </div>
      ))}
    </div>
  )
}

export function Distribution({ rows }: { rows: { score: number; count: number }[] }) {
  const max = Math.max(1, ...rows.map(r => r.count))
  return (
    <div role="img" aria-label={`Score distribution: ${rows.map(r => `${r.score}: ${r.count}`).join(', ')}`}
      style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 120 }}>
      {rows.map(r => (
        <div key={r.score} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, height: '100%', justifyContent: 'flex-end' }}>
          <span style={{ fontSize: '.7rem', color: 'var(--dim)' }}>{r.count || ''}</span>
          <div title={`${r.score}: ${r.count}`} style={{ width: '100%', height: `${(r.count / max) * 80}%`, minHeight: r.count ? 2 : 0, background: bandColor(r.score), borderRadius: '3px 3px 0 0' }} />
          <span style={{ fontSize: '.72rem' }}>{r.score}</span>
        </div>
      ))}
    </div>
  )
}

export function Trend({ rows }: { rows: ({ period: string } & NpsStats)[] }) {
  if (!rows.length) return <p style={{ color: 'var(--dim)' }}>No answers in this range.</p>
  return (
    <table>
      <thead><tr><th>Period</th><th>Answers</th><th>NPS</th><th style={{ width: '45%' }}></th></tr></thead>
      <tbody>
        {rows.map(r => (
          <tr key={r.period}>
            <td style={{ fontFamily: 'monospace', fontSize: '.8rem' }}>{r.period}</td>
            <td>{r.total}</td>
            <td style={{ fontWeight: 600 }}>{npsText(r.nps)}</td>
            <td>
              {r.nps !== null && (
                <div style={{ position: 'relative', height: 10, background: 'var(--surface2, #2a2d3a)', borderRadius: 3 }} aria-hidden="true">
                  <div style={{ position: 'absolute', left: '50%', top: -2, bottom: -2, width: 1, background: 'var(--border)' }} />
                  <div style={{
                    position: 'absolute', top: 0, bottom: 0, borderRadius: 3,
                    left: r.nps >= 0 ? '50%' : `${50 + r.nps / 2}%`, width: `${Math.abs(r.nps) / 2}%`,
                    background: r.nps >= 0 ? 'var(--green, #22c55e)' : 'var(--red, #ef4444)',
                  }} />
                </div>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
