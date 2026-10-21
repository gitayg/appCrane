import type { Severity } from './eventTypes'

const COLOR: Record<Severity, string> = {
  info: 'var(--accent)',
  warning: 'var(--orange)',
  critical: 'var(--red)',
}

export function SeverityChip({ severity, active, onClick }: { severity: Severity; active?: boolean; onClick?: () => void }) {
  const color = COLOR[severity] || 'var(--dim)'
  const style = {
    color,
    background: active === false ? 'transparent' : `color-mix(in srgb, ${color} 14%, transparent)`,
    border: `1px solid color-mix(in srgb, ${color} ${active === false ? 30 : 45}%, transparent)`,
    whiteSpace: 'nowrap' as const,
    textTransform: 'capitalize' as const,
  }
  if (!onClick) return <span className="badge" style={style}>{severity}</span>
  return (
    <button type="button" className="badge" aria-pressed={!!active} onClick={onClick} style={{ ...style, cursor: 'pointer', font: 'inherit', fontSize: '.72rem' }}>
      {severity}
    </button>
  )
}
