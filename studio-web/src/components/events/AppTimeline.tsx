import { useCallback, useEffect, useState } from 'react'
import { ApiError } from '../../adminApi'
import { EventDetail } from './EventDetail'
import { EventRow } from './EventRow'
import { fetchEvents, type AppEvent } from './eventTypes'

/** Compact recent-events list for one app (its owner, an admin of the app, or a platform admin). */
export function AppTimeline({ slug, limit = 15 }: { slug: string; limit?: number }) {
  const [events, setEvents] = useState<AppEvent[] | null>(null)
  const [cursor, setCursor] = useState<number | null>(null)
  const [failure, setFailure] = useState('')
  const [hidden, setHidden] = useState(false)
  const [selected, setSelected] = useState<AppEvent | null>(null)
  const base = `/api/apps/${encodeURIComponent(slug)}/events`

  const load = useCallback((before: number | null = null) => {
    fetchEvents(base, {}, before, limit)
      .then(r => {
        setEvents(prev => (before ? [...(prev || []), ...r.events] : r.events))
        setCursor(r.next_cursor)
        setFailure('')
      })
      .catch(e => {
        if (e instanceof ApiError && e.status === 403) { setHidden(true); return }
        setFailure(e instanceof Error ? e.message : String(e))
      })
  }, [base, limit])

  useEffect(() => { setEvents(null); setSelected(null); setHidden(false); load() }, [load])

  if (hidden) return null

  return (
    <div className="card" style={{ padding: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <h4 style={{ margin: 0, flex: 1 }}>Recent events</h4>
        <button type="button" className="btn btn-sm" onClick={() => load()}>Refresh</button>
      </div>
      {failure && <div role="alert" style={{ color: 'var(--red)', fontSize: '.8rem' }}>{failure}</div>}
      {events === null && !failure && <p style={{ color: 'var(--dim)', fontSize: '.8rem' }}>Loading…</p>}
      {events && events.length === 0 && <p style={{ color: 'var(--dim)', fontSize: '.8rem' }}>No events recorded for this app yet.</p>}
      {events && events.length > 0 && (
        <ul style={{ margin: 0, padding: 0 }}>
          {events.map(e => (
            <EventRow key={e.id} event={e} showApp={false} selected={selected?.id === e.id} onSelect={ev => setSelected(selected?.id === ev.id ? null : ev)} />
          ))}
        </ul>
      )}
      {cursor && <button type="button" className="btn btn-sm" style={{ marginTop: 8 }} onClick={() => load(cursor)}>Older</button>}
      {selected && <div style={{ marginTop: 10 }}><EventDetail event={selected} onSelect={setSelected} onClose={() => setSelected(null)} /></div>}
    </div>
  )
}
