import { SeverityChip } from './SeverityChip'
import { actorLabel, eventTime, type AppEvent } from './eventTypes'

export function EventRow({ event, selected, onSelect, showApp = true }: {
  event: AppEvent
  selected?: boolean
  onSelect?: (e: AppEvent) => void
  showApp?: boolean
}) {
  return (
    <li
      style={{
        listStyle: 'none', padding: '8px 10px', borderBottom: '1px solid var(--border)',
        background: selected ? 'var(--surface2)' : 'transparent',
      }}
    >
      <button
        type="button"
        onClick={() => onSelect?.(event)}
        aria-current={selected ? 'true' : undefined}
        style={{ all: 'unset', cursor: onSelect ? 'pointer' : 'default', display: 'block', width: '100%' }}
      >
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <SeverityChip severity={event.severity} />
          <code style={{ fontSize: '.72rem', color: 'var(--dim)' }}>{event.kind}</code>
          <span style={{ flex: 1, minWidth: 180, color: 'var(--text)', wordBreak: 'break-word' }}>{event.summary}</span>
        </div>
        <div style={{ color: 'var(--dim)', fontSize: '.75rem', marginTop: 2 }}>
          {eventTime(event)}
          {` · ${actorLabel(event)}`}
          {event.subject_user_name ? ` · about ${event.subject_user_name}` : ''}
          {showApp && event.app_slug ? ` · ${event.app_slug}` : ''}
        </div>
      </button>
    </li>
  )
}
