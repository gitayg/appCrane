import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { UsageRow } from './llmTypes'

// LLM gateway usage per day, app, environment and model. Metadata only: the
// gateway never stores prompts or responses.

interface Props {
  url: string
  showApp?: boolean
  reload?: number
}

const fmt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString())
const usd = (n: number | null | undefined) => (n == null ? '—' : `$${n.toFixed(n < 1 ? 4 : 2)}`)

export function LlmUsageTable({ url, showApp = false, reload = 0 }: Props) {
  const [days, setDays] = useState(30)
  const [rows, setRows] = useState<UsageRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setError(null)
    adminApi.get<{ rows: UsageRow[] }>(`${url}?days=${days}`)
      .then(d => setRows(d.rows))
      .catch(e => setError((e as Error).message))
  }, [url, days, reload])

  if (error) return <p style={{ color: 'var(--dim)', fontSize: '.82rem' }}>Usage unavailable: {error}</p>
  if (!rows) return null

  const total = rows.reduce((t, r) => ({
    requests: t.requests + r.requests,
    tokens: t.tokens + r.input_tokens + r.output_tokens,
    cost: t.cost + (r.cost_usd || 0),
  }), { requests: 0, tokens: 0, cost: 0 })

  return (
    <div>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', margin: '6px 0' }}>
        <label>Last{' '}
          <select value={days} onChange={e => setDays(Number(e.target.value))}>
            {[1, 7, 30, 90].map(d => <option key={d} value={d}>{d} day{d > 1 ? 's' : ''}</option>)}
          </select>
        </label>
        <span style={{ color: 'var(--dim)', fontSize: '.82rem' }}>
          {fmt(total.requests)} requests · {fmt(total.tokens)} tokens · {usd(total.cost)} estimated
        </span>
      </div>
      {rows.length === 0 ? (
        <p style={{ color: 'var(--dim)', fontSize: '.82rem' }}>No LLM gateway requests in this period.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Day</th>{showApp && <th>App</th>}<th>Env</th><th>Model</th>
              <th>Requests</th><th>Failed</th><th>Input tokens</th><th>Output tokens</th><th>Est. cost</th><th>Avg latency</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={`${r.day}/${r.app_id}/${r.env}/${r.provider}/${r.model}`}>
                <td>{r.day}</td>
                {showApp && <td className="am-mono">{r.app_slug || r.app_id}</td>}
                <td>{r.env}</td>
                <td className="am-mono">{r.provider}/{r.model || '—'}</td>
                <td>{fmt(r.requests)}</td>
                <td>{r.failed ? `${fmt(r.failed)}${r.refused ? ` (${fmt(r.refused)} refused)` : ''}` : '0'}</td>
                <td>{fmt(r.input_tokens)}</td>
                <td>{fmt(r.output_tokens)}</td>
                <td>{usd(r.cost_usd)}</td>
                <td>{r.avg_latency_ms == null ? '—' : `${fmt(r.avg_latency_ms)} ms`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
