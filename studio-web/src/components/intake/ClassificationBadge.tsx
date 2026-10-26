import type { Level } from './types'

const COLORS: Record<Level, string> = {
  public: 'var(--dim)',
  internal: 'var(--accent)',
  confidential: 'var(--orange)',
  restricted: 'var(--red)',
}

/** A small pill naming an app's data classification. */
export function ClassificationBadge({ level, title }: { level?: Level | null; title?: string }) {
  if (!level) return null
  const c = COLORS[level] || 'var(--dim)'
  return (
    <span
      title={title || `Data classification: ${level}`}
      style={{
        display: 'inline-block', padding: '0 6px', borderRadius: 8, fontSize: '.65rem', lineHeight: '16px',
        fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.03em',
        color: c, border: `1px solid ${c}`, whiteSpace: 'nowrap',
      }}
    >{level}</span>
  )
}
