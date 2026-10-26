import { useEffect, useState } from 'react'
import { EventRow } from './EventRow'
import { SeverityChip } from './SeverityChip'
import { actorLabel, eventTime, fetchRelated, type AppEvent } from './eventTypes'

export function EventDetail({ event, onSelect, onClose }: {
  event: AppEvent
  onSelect: (e: AppEvent) => void
  onClose: () => void
}) {
  const [related, setRelated] = useState<AppEvent[] | null>(null)
  const [failure, setFailure] = useState('')

  useEffect(() => {
    let live = true
    setRelated(null)
    setFailure('')
    fetchRelated(event.id)
      .then(r => { if (live) setRelated(r.related || []) })
      .catch(e => { if (live) setFailure(e instanceof Error ? e.message : String(e)) })
    return () => { live = false }
  }, [event.id])

  return (
    <section aria-label="Event details" style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 12, background: 'var(--surface)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <SeverityChip severity={event.severity} />
        <code style={{ fontSize: '.75rem' }}>{event.kind}</code>
        <span style={{ flex: 1 }} />
        <button type="button" className="btn btn-sm" onClick={onClose}>Close</button>
      </div>
      <p style={{ margin: '0 0 8px', wordBreak: 'break-word' }}>{event.summary}</p>
      <dl style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '2px 12px', fontSize: '.8rem', margin: 0 }}>
        <dt style={{ color: 'var(--dim)' }}>When</dt><dd style={{ margin: 0 }}>{eventTime(event)}</dd>
        <dt style={{ color: 'var(--dim)' }}>Actor</dt><dd style={{ margin: 0 }}>{actorLabel(event)}</dd>
        {event.subject_user_id != null && <><dt style={{ color: 'var(--dim)' }}>About</dt><dd style={{ margin: 0 }}>{event.subject_user_name || `user #${event.subject_user_id}`}</dd></>}
        {event.app_slug && <><dt style={{ color: 'var(--dim)' }}>App</dt><dd style={{ margin: 0 }}>{event.app_slug}</dd></>}
        {event.ref_table && <><dt style={{ color: 'var(--dim)' }}>Source</dt><dd style={{ margin: 0 }}>{event.ref_table} #{event.ref_id}</dd></>}
      </dl>
      {event.data && (
        <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '.72rem', background: 'var(--surface2)', padding: 8, borderRadius: 6, marginTop: 8, maxHeight: 240, overflow: 'auto' }}>
          {JSON.stringify(event.data, null, 2)}
        </pre>
      )}
      <h4 style={{ margin: '12px 0 4px', fontSize: '.85rem' }}>Related (same app or person, within 2 hours)</h4>
      {failure && <div role="alert" style={{ color: 'var(--red)', fontSize: '.8rem' }}>{failure}</div>}
      {related === null && !failure && <p style={{ color: 'var(--dim)', fontSize: '.8rem' }}>Loading…</p>}
      {related && related.length === 0 && <p style={{ color: 'var(--dim)', fontSize: '.8rem' }}>Nothing else happened around this time.</p>}
      {related && related.length > 0 && (
        <ul style={{ margin: 0, padding: 0, maxHeight: 360, overflow: 'auto' }}>
          {related.map(r => <EventRow key={r.id} event={r} onSelect={onSelect} />)}
        </ul>
      )}
    </section>
  )
}
