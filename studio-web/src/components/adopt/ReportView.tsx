import { SEVERITY_COLOR, VERDICT_TEXT, type Analysis, type ReportItem } from './adoptTypes'

function Item({ item }: { item: ReportItem }) {
  const color = item.severity ? SEVERITY_COLOR[item.severity] : item.level === 'ok' ? '#22c55e' : item.level === 'decision' ? '#60a5fa' : '#eab308'
  return (
    <li style={{ display: 'flex', gap: 10, padding: '8px 0', borderTop: '1px solid var(--border)' }}>
      <span style={{ flex: '0 0 auto', marginTop: 5, width: 8, height: 8, borderRadius: 4, background: color }} aria-hidden />
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: '.85rem', fontWeight: 600 }}>
          {item.severity && <span style={{ color, textTransform: 'uppercase', fontSize: '.7rem', marginRight: 6 }}>{item.severity}</span>}
          {item.title}
          {item.blocking && <span style={{ marginLeft: 6, fontSize: '.7rem', color: '#f97316' }}>blocks the deploy</span>}
          {item.request && <span style={{ marginLeft: 6, fontSize: '.7rem', color: 'var(--dim)' }}>request for the coder</span>}
        </div>
        <div style={{ fontSize: '.8rem', color: 'var(--dim)', wordBreak: 'break-word' }}>
          {item.detail}{item.preview ? ` (${item.preview})` : ''}
        </div>
      </div>
    </li>
  )
}

function Section({ title, items, empty }: { title: string; items: ReportItem[]; empty?: string }) {
  if (!items.length && !empty) return null
  return (
    <section style={{ marginTop: 14 }}>
      <h3 style={{ margin: '0 0 4px', fontSize: '.95rem' }}>{title}</h3>
      {items.length ? <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>{items.map(i => <Item key={i.id} item={i} />)}</ul>
        : <div style={{ fontSize: '.8rem', color: 'var(--dim)' }}>{empty}</div>}
    </section>
  )
}

export function ReportView({ analysis }: { analysis: Analysis }) {
  const r = analysis.report
  const p = r.project
  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontSize: '1.1rem' }}>{analysis.source.label}</h2>
        <span style={{ fontSize: '.8rem', color: 'var(--dim)' }}>{p.label}{p.origin.tool !== 'generic' ? ` from ${p.origin.label}` : ''} | {r.file_count} files</span>
      </div>
      <div style={{ marginTop: 6, fontSize: '.9rem', fontWeight: 600, color: r.verdict === 'critical_risks' ? SEVERITY_COLOR.critical : r.verdict === 'ready' ? '#22c55e' : '#eab308' }}>
        {VERDICT_TEXT[r.verdict]}
      </div>
      <Section title="Risks" items={r.risks} />
      <Section title="Needs changes or a decision" items={r.changes} />
      <Section title="Works as is" items={r.works} />
      {r.supabase_edge_env.length > 0 && (
        <p style={{ fontSize: '.8rem', color: 'var(--dim)' }}>
          Supabase Edge Function secrets stay in Supabase: {r.supabase_edge_env.join(', ')}.
        </p>
      )}
      {r.skipped.length > 0 && (
        <p style={{ fontSize: '.8rem', color: 'var(--dim)' }}>
          Not imported: {r.skipped.slice(0, 10).map(s => `${s.path} (${s.reason})`).join(', ')}{r.skipped.length > 10 ? ` and ${r.skipped.length - 10} more` : ''}.
        </p>
      )}
    </div>
  )
}
