import { useCallback, useEffect, useState } from 'react'
import { ApiError } from '../adminApi'
import { EventDetail } from '../components/events/EventDetail'
import { EventRow } from '../components/events/EventRow'
import { SeverityChip } from '../components/events/SeverityChip'
import { KIND_GROUPS, SEVERITIES, fetchEvents, type AppEvent, type EventFilters, type Severity } from '../components/events/eventTypes'

const EMPTY: EventFilters = { kind: '', severity: '', app: '', user: '', from: '', to: '', q: '' }

/**
 * The shared event timeline. A platform admin sees every event
 * (/api/events); anyone else sees their own activity (/api/me/events).
 */
export function Events() {
  const [scope, setScope] = useState<'all' | 'mine'>('all')
  const [draft, setDraft] = useState<EventFilters>(EMPTY)
  const [filters, setFilters] = useState<EventFilters>(EMPTY)
  const [events, setEvents] = useState<AppEvent[] | null>(null)
  const [cursor, setCursor] = useState<number | null>(null)
  const [failure, setFailure] = useState('')
  const [selected, setSelected] = useState<AppEvent | null>(null)
  const base = scope === 'all' ? '/api/events' : '/api/me/events'

  const load = useCallback((before: number | null = null) => {
    fetchEvents(base, filters, before)
      .then(r => {
        setEvents(prev => (before ? [...(prev || []), ...r.events] : r.events))
        setCursor(r.next_cursor)
        setFailure('')
      })
      .catch(e => {
        if (scope === 'all' && e instanceof ApiError && e.status === 403) { setScope('mine'); return }
        setFailure(e instanceof Error ? e.message : String(e))
      })
  }, [base, filters, scope])

  useEffect(() => { setEvents(null); load() }, [load])

  const selectedSeverities = (filters.severity || '').split(',').filter(Boolean)
  function toggleSeverity(s: Severity) {
    const next = selectedSeverities.includes(s) ? selectedSeverities.filter(x => x !== s) : [...selectedSeverities, s]
    const sev = next.join(',')
    setDraft(d => ({ ...d, severity: sev }))
    setFilters(f => ({ ...f, severity: sev }))
  }

  function apply(e: React.FormEvent) {
    e.preventDefault()
    setFilters(draft)
  }

  const field = (key: keyof EventFilters, label: string, props: React.InputHTMLAttributes<HTMLInputElement> = {}) => (
    <label style={{ display: 'flex', flexDirection: 'column', fontSize: '.75rem', color: 'var(--dim)', gap: 2 }}>
      {label}
      <input value={draft[key] || ''} onChange={ev => setDraft(d => ({ ...d, [key]: ev.target.value }))} {...props} />
    </label>
  )

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 8 }}>
        <h2 style={{ margin: 0, flex: 1 }}>{scope === 'all' ? 'Events' : 'My activity'}</h2>
        <button className="btn" onClick={() => load()}>Refresh</button>
      </div>
      <p style={{ color: 'var(--dim)', marginTop: 0, fontSize: '.85rem' }}>
        {scope === 'all'
          ? 'Audit entries, deploys, dependency scan findings, browser errors, background jobs, server alerts and memory admission in one timeline. Info events are kept 30 days, warnings 90 and critical events 365 unless changed in Settings.'
          : 'What you did on AppCrane, and what was done to your account, such as failed sign-ins.'}
      </p>

      <form onSubmit={apply} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 8 }}>
        <label style={{ display: 'flex', flexDirection: 'column', fontSize: '.75rem', color: 'var(--dim)', gap: 2 }}>
          Kind
          <select value={draft.kind || ''} onChange={ev => setDraft(d => ({ ...d, kind: ev.target.value }))}>
            <option value="">All kinds</option>
            {KIND_GROUPS.map(k => <option key={k} value={k}>{k}</option>)}
          </select>
        </label>
        {scope === 'all' && field('app', 'App (slug)', { placeholder: 'any', style: { width: 120 } })}
        {scope === 'all' && field('user', 'User id', { placeholder: 'any', inputMode: 'numeric', style: { width: 80 } })}
        {field('from', 'From', { type: 'datetime-local' })}
        {field('to', 'To', { type: 'datetime-local' })}
        {field('q', 'Search', { placeholder: 'summary contains', style: { width: 180 } })}
        <button type="submit" className="btn">Apply</button>
        <button type="button" className="btn" onClick={() => { setDraft(EMPTY); setFilters(EMPTY) }}>Clear</button>
      </form>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontSize: '.75rem', color: 'var(--dim)' }}>Severity:</span>
        {SEVERITIES.map(s => (
          <SeverityChip key={s} severity={s} active={selectedSeverities.length === 0 || selectedSeverities.includes(s)} onClick={() => toggleSeverity(s)} />
        ))}
      </div>

      {failure && <div role="alert" style={{ color: 'var(--red)', margin: '8px 0' }}>{failure}</div>}
      {events === null && !failure && <p style={{ color: 'var(--dim)' }}>Loading…</p>}
      {events && events.length === 0 && <p style={{ color: 'var(--dim)' }}>No events match these filters.</p>}

      <div style={{ display: 'grid', gridTemplateColumns: selected ? 'minmax(0, 1fr) minmax(0, 1fr)' : 'minmax(0, 1fr)', gap: 12, alignItems: 'start' }}>
        {events && events.length > 0 && (
          <div>
            <ul style={{ margin: 0, padding: 0, border: '1px solid var(--border)', borderRadius: 8 }}>
              {events.map(e => (
                <EventRow key={e.id} event={e} selected={selected?.id === e.id} onSelect={ev => setSelected(selected?.id === ev.id ? null : ev)} />
              ))}
            </ul>
            {cursor && <button type="button" className="btn" style={{ marginTop: 8 }} onClick={() => load(cursor)}>Older</button>}
          </div>
        )}
        {selected && <EventDetail event={selected} onSelect={setSelected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  )
}
