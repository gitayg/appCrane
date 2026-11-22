import type { PlatformImport } from './adoptTypes'

const small: React.CSSProperties = { fontSize: '.8rem', color: 'var(--dim)', wordBreak: 'break-word' }
const row: React.CSSProperties = { padding: '6px 0', borderTop: '1px solid var(--border)' }

export function PlatformImportView({ platform }: { platform: PlatformImport }) {
  const names = [...new Set(platform.sources.map(s => s.platform))].join(', ')
  return (
    <section style={{ marginTop: 14 }}>
      <h3 style={{ margin: '0 0 4px', fontSize: '.95rem' }}>Imported from {names}</h3>
      <div style={small}>Read from {platform.sources.map(s => s.file).join(', ')}. Values in these files are never imported; only variable names are.</div>
      {platform.mapped.length > 0 && (
        <ul style={{ listStyle: 'none', margin: '6px 0 0', padding: 0 }}>
          {platform.mapped.map((m, i) => (
            <li key={`m${i}`} style={row}>
              <div style={{ fontSize: '.85rem' }}><code>{m.from}</code> &rarr; {m.to}</div>
              <div style={small}><code>{m.value}</code></div>
            </li>
          ))}
        </ul>
      )}
      {platform.notes.map((n, i) => <p key={`n${i}`} style={{ ...small, margin: '6px 0 0' }}>{n}</p>)}
      <h4 style={{ margin: '12px 0 4px', fontSize: '.85rem' }}>Could not be mapped ({platform.unmapped.length})</h4>
      {platform.unmapped.length === 0
        ? <div style={small}>Everything in these files was mapped.</div>
        : (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {platform.unmapped.map((u, i) => (
              <li key={`u${i}`} style={row}>
                <div style={{ fontSize: '.85rem', fontWeight: 600 }}>{u.title}</div>
                <div style={small}><code>{u.source}{u.field && !u.field.startsWith('(') ? ` ${u.field}` : ''}</code> {u.detail}</div>
              </li>
            ))}
          </ul>
        )}
    </section>
  )
}
