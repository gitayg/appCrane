import { useState } from 'react'

// Asked when a request is marked shipped: an optional note, for the person who
// filed it, saying what was done. It goes into their completion email and their
// My Requests list. Empty is fine (Ship works straight away), so the one-click
// path still exists, just behind one more click.

export const DONE_NOTE_MAX = 2000

interface Props {
  requestId: number
  message: string
  onCancel: () => void
  onShip: (note: string) => Promise<void>
}

export function ShipNoteModal({ requestId, message, onCancel, onShip }: Props) {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const tooLong = note.trim().length > DONE_NOTE_MAX

  async function ship() {
    setBusy(true)
    setError(null)
    try {
      await onShip(note.trim())
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 10500, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={busy ? undefined : onCancel}
    >
      <div
        style={{ width: 'min(520px, 92vw)', background: 'var(--surface, #1a1a1a)', color: 'var(--text)', border: '1px solid var(--border, #333)', borderRadius: 8, boxShadow: '0 16px 48px rgba(0,0,0,.5)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-label={`Mark request #${requestId} shipped`}
      >
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border, #333)', background: 'var(--surface2, #232323)', fontWeight: 600, fontSize: '.95rem' }}>
          Mark #{String(requestId).padStart(4, '0')} shipped
        </div>
        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12, fontSize: '.85rem' }}>
          <p style={{ margin: 0, color: 'var(--dim)', wordBreak: 'break-word' }}>"{message.length > 200 ? message.slice(0, 200) + '…' : message}"</p>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span>What was done <span style={{ color: 'var(--dim)' }}>(optional, sent to the requester)</span></span>
            <textarea
              value={note}
              onChange={e => setNote(e.target.value)}
              rows={4}
              autoFocus
              placeholder="e.g. The header now stays visible while you scroll."
              style={{ fontSize: '.85rem', fontFamily: 'inherit', resize: 'vertical' }}
            />
          </label>
          <span style={{ fontSize: '.72rem', color: tooLong ? 'var(--red)' : 'var(--dim)', alignSelf: 'flex-end' }}>
            {note.trim().length} / {DONE_NOTE_MAX}
          </span>
          {error && <p style={{ margin: 0, color: 'var(--red)' }}>{error}</p>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button className="btn btn-xs" disabled={busy} onClick={onCancel}>Cancel</button>
            <button className="btn btn-xs btn-accent" disabled={busy || tooLong} onClick={ship}>
              {busy ? 'Shipping…' : 'Ship'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
