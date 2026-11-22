import { useState } from 'react'
import { adminApi } from '../../adminApi'
import type { LiteracyStatement } from './types'

/** The AI-literacy statement with its acknowledge button. Shown once per user and statement version. */
export function LiteracyAck({ statement, onDone, onCancel }: { statement: LiteracyStatement; onDone: () => void; onCancel: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function ack() {
    setBusy(true)
    try {
      await adminApi.post('/api/ai-act/literacy/acknowledge', { version: statement.version })
      onDone()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="am-card" style={{ borderColor: 'var(--orange)', marginTop: 8 }}>
      <div style={{ fontWeight: 600, marginBottom: 6 }}>AI-literacy statement (version {statement.version})</div>
      <div style={{ whiteSpace: 'pre-wrap', fontSize: '.85rem', marginBottom: 8 }}>{statement.text}</div>
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', marginBottom: 8 }}>AppCrane records who acknowledged which version and when; the record goes into the compliance evidence pack.</div>
      {error && <div style={{ color: 'var(--red)', marginBottom: 6 }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn btn-sm" disabled={busy} onClick={ack}>I acknowledge this statement</button>
        <button className="btn btn-sm btn-dim" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  )
}
