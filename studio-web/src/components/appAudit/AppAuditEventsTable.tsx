import type { AppAuditEvent } from './types'
import { serverDate } from '../../utils/serverDate'

// One page of app audit events. Each row is labelled "app" (written by the
// app, not by AppCrane); an actor AppCrane could not vouch for is marked.

function actorLabel(e: AppAuditEvent) {
  const a = e.actor
  const who = a.name ? `${a.name} (${a.type}:${a.id})` : `${a.type}:${a.id}`
  return a.verified ? who : `${who}, as reported`
}

export function AppAuditEventsTable({ events, showApp = false }: { events: AppAuditEvent[]; showApp?: boolean }) {
  if (!events.length) return <div style={{ fontSize: '.85rem', color: 'var(--text-dim)' }}>No events.</div>
  return (
    <table style={{ width: '100%', fontSize: '.8rem', borderCollapse: 'collapse' }}>
      <thead><tr style={{ textAlign: 'left' }}><th>When</th>{showApp && <th>App</th>}<th>Action</th><th>Actor</th><th>Targets</th><th>From</th></tr></thead>
      <tbody>
        {events.map(e => (
          <tr key={e.id} title={e.metadata ? JSON.stringify(e.metadata) : undefined} style={{ borderTop: '1px solid var(--border)' }}>
            <td>{serverDate(e.occurred_at).toLocaleString()}</td>
            {showApp && <td>{e.app.slug}</td>}
            <td><span className="badge">app</span> {e.action}{e.unregistered ? ' (unregistered)' : ''}</td>
            <td>{actorLabel(e)}</td>
            <td>{e.targets.map(t => `${t.type}:${t.id}`).join(', ')}</td>
            <td>{e.context.location || ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
