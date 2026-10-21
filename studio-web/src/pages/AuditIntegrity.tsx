import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { serverDate } from '../utils/serverDate'
import { downloadExport } from '../components/accessReviews/types'

interface Chain {
  src: string
  entries: number
  head_row_id: number | null
  last_sealed_at: string | null
  unsealed: number
  last_checkpoint: { id: number; upto_row_id: number; chain_fp: string; created_at: string } | null
  compacted_up_to: number | null
}

interface Problem { type: string; src?: string; row_id?: number; checkpoint_id?: number; detail: string }

interface Verification {
  ran_at?: string
  ok: boolean
  checked: number
  trigger?: string
  problems?: Problem[]
  first_broken?: Record<string, number>
  total?: number
  total_problems?: number
}

interface Status {
  chains: Chain[]
  last_verification: Verification | null
  history: { id: number; ran_at: string; ok: boolean; checked: number; trigger_by: string }[]
}

const when = (ts: string | null | undefined) => (ts ? serverDate(ts).toLocaleString() : 'never')

function Result({ v }: { v: Verification }) {
  const firsts = Object.entries(v.first_broken || {})
  return (
    <div className="card" style={{ padding: 12, marginBottom: 16, borderColor: v.ok ? 'var(--green)' : 'var(--red)' }}>
      <b style={{ color: v.ok ? 'var(--green)' : 'var(--red)' }}>
        {v.ok ? `Intact: ${v.checked} sealed row(s) verified` : `Integrity check FAILED: ${v.total ?? v.total_problems ?? v.problems?.length} problem(s)`}
      </b>
      {v.ran_at && <span style={{ color: 'var(--dim)', fontSize: '.85rem' }}> | {when(v.ran_at)}</span>}
      {firsts.length > 0 && <div style={{ marginTop: 6 }}>First broken: {firsts.map(([s, id]) => `${s} row ${id}`).join(', ')}</div>}
      {!v.ok && v.problems && (
        <ul style={{ fontSize: '.85rem', marginTop: 6 }}>
          {v.problems.slice(0, 50).map((p, i) => (
            <li key={i}><b>{p.type}</b> {p.src || 'checkpoints'} {p.row_id != null ? `row ${p.row_id}` : `checkpoint ${p.checkpoint_id}`}: {p.detail}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** Platform admin: the audit hash chain, its last verification, and checkpoints to hold outside AppCrane. */
export function AuditIntegrity() {
  const [status, setStatus] = useState<Status | null>(null)
  const [run, setRun] = useState<Verification | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    adminApi.get<Status>('/api/audit-chain/status')
      .then(s => { setStatus(s); setError('') })
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [])
  useEffect(() => { load() }, [load])

  async function verify() {
    setBusy(true)
    try { setRun(await adminApi.post<Verification>('/api/audit-chain/verify')); load() } catch (e) { setError(e instanceof Error ? e.message : String(e)) } finally { setBusy(false) }
  }

  const shown = run || status?.last_verification || null

  return (
    <div>
      <h3>Audit integrity</h3>
      <p className="settings-hint">
        Every audit log entry and event is sealed into a hash chain every few minutes, and the head of each chain is signed with a key
        derived from this server's encryption key. Verification recomputes the chain and names the first row that was changed,
        deleted or inserted out of order. Limits: rows changed before they were sealed cannot be detected, and someone holding both
        the database and the encryption key could rebuild and re-sign the chain. Checkpoints held outside AppCrane (the SIEM stream
        or an exported copy) catch that.
      </p>
      {error && <p style={{ color: 'var(--red)' }}>{error}</p>}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button className="btn" disabled={busy} onClick={verify}>{busy ? 'Verifying...' : 'Verify now'}</button>
        <button className="btn" onClick={() => downloadExport('/api/audit-chain/checkpoints', 'audit-chain-checkpoints.json').catch(e => setError(String(e)))}>
          Export checkpoints
        </button>
      </div>
      {shown && <Result v={shown} />}
      {status && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '.85rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--dim)' }}>
                <th style={{ padding: 6 }}>Chain</th>
                <th style={{ padding: 6 }}>Sealed rows</th>
                <th style={{ padding: 6 }}>Waiting</th>
                <th style={{ padding: 6 }}>Last sealed</th>
                <th style={{ padding: 6 }}>Last signed checkpoint</th>
              </tr>
            </thead>
            <tbody>
              {status.chains.map(c => (
                <tr key={c.src} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: 6 }}>{c.src}</td>
                  <td style={{ padding: 6 }}>{c.entries}{c.compacted_up_to ? ` (compacted to ${c.compacted_up_to})` : ''}</td>
                  <td style={{ padding: 6 }}>{c.unsealed}</td>
                  <td style={{ padding: 6 }}>{when(c.last_sealed_at)}</td>
                  <td style={{ padding: 6 }}>{c.last_checkpoint ? `row ${c.last_checkpoint.upto_row_id}, ${c.last_checkpoint.chain_fp}... (${when(c.last_checkpoint.created_at)})` : 'none yet'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {status && status.history.length > 0 && (
        <details style={{ marginTop: 12 }}>
          <summary style={{ cursor: 'pointer' }}>Verification history</summary>
          <ul style={{ fontSize: '.85rem' }}>
            {status.history.map(h => (
              <li key={h.id} style={{ color: h.ok ? undefined : 'var(--red)' }}>{when(h.ran_at)}: {h.ok ? 'intact' : 'FAILED'}, {h.checked} rows ({h.trigger_by})</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}
