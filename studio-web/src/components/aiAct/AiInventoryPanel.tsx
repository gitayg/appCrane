import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { AI_USE_LABELS, type InventoryRow } from './types'

interface Retention { configured_days: number; ai_floor_days: number; ai_effective_days: number; min_days: number; max_days: number }

/** Platform admin: every app using AI, from LLM gateway traffic and the intake answer, with the log retention setting. */
export function AiInventoryPanel() {
  const [rows, setRows] = useState<InventoryRow[] | null>(null)
  const [retention, setRetention] = useState<Retention | null>(null)
  const [days, setDays] = useState('')
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  const load = useCallback(() => {
    adminApi.get<{ apps: InventoryRow[] }>('/api/ai-act/inventory').then(r => setRows(r.apps)).catch(e => setMsg({ text: (e as Error).message, ok: false }))
    adminApi.get<Retention>('/api/ai-act/retention').then(r => { setRetention(r); setDays(String(r.configured_days)) }).catch(() => {})
  }, [])
  useEffect(() => { load() }, [load])

  async function exportCsv() {
    const text = await adminApi.getText('/api/ai-act/inventory?format=csv')
    const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `ai-inventory-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  async function saveDays() {
    try {
      const r = await adminApi.put<Retention>('/api/ai-act/retention', { days: Number(days) })
      setRetention(r)
      setMsg({ text: `LLM gateway logs: ${r.configured_days} days; apps using AI: ${r.ai_effective_days} days`, ok: true })
    } catch (e) {
      setMsg({ text: (e as Error).message, ok: false })
    }
  }

  const mismatches = rows?.filter(r => r.mismatch).length || 0
  return (
    <div style={{ marginTop: 24 }}>
      <h2 style={{ margin: 0 }}>AI-system inventory</h2>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem' }}>
        Apps with LLM gateway traffic or an intake AI-use answer. Traffic covers calls made through AppCrane's gateway only.
        {mismatches ? ` ${mismatches} app(s) have gateway traffic but an intake answer of none or no answer.` : ''}
      </p>
      {msg && <div style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', marginBottom: 8 }}>{msg.text}</div>}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
        <button className="btn btn-sm btn-dim" onClick={exportCsv}>Export CSV</button>
        {retention && (
          <>
            <span style={{ fontSize: '.85rem' }}>Keep LLM gateway logs</span>
            <input className="am-input" style={{ width: 80 }} type="number" min={retention.min_days} max={retention.max_days} value={days} onChange={e => setDays(e.target.value)} />
            <span style={{ fontSize: '.85rem' }}>days (apps using AI: at least {retention.ai_floor_days})</span>
            <button className="btn btn-sm btn-dim" onClick={saveDays}>Save</button>
          </>
        )}
      </div>
      {rows === null ? 'Loading...' : rows.length === 0 ? <span style={{ color: 'var(--dim)' }}>No app uses AI.</span> : (
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead><tr><th>App</th><th>AI use</th><th>Providers / models</th><th>First seen</th><th>Last seen</th><th>Calls</th><th>Notice</th><th>Log days</th><th></th></tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.app}>
                  <td className="am-mono">{r.app}</td>
                  <td>{r.ai_use ? AI_USE_LABELS[r.ai_use] : 'Not answered'}{r.annex_iii_category ? ` (${r.annex_iii_category})` : ''}</td>
                  <td>{r.providers.join(', ') || '-'}{r.models.length ? ` / ${r.models.join(', ')}` : ''}</td>
                  <td>{r.first_seen || '-'}</td>
                  <td>{r.last_seen || '-'}</td>
                  <td>{r.calls}</td>
                  <td>{r.transparency_notice ? 'on' : 'off'}</td>
                  <td>{r.llm_log_retention_days}</td>
                  <td style={{ color: 'var(--orange)' }}>{r.mismatch ? 'Traffic without an AI answer' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
