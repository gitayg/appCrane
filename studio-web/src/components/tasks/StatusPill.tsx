import { STATUS_LABEL, STATUS_STYLE, type TaskStatus } from './taskTypes'

export function StatusPill({ status }: { status: TaskStatus }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.open
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 10, fontSize: '.72rem', fontWeight: 600,
      color: s.fg, background: s.bg, border: `1px solid ${s.border}`, whiteSpace: 'nowrap',
    }}>
      {STATUS_LABEL[status] || status}
    </span>
  )
}
