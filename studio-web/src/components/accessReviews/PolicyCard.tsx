import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { Policy } from './types'

const LEVELS = ['public', 'internal', 'confidential', 'restricted']

const NUMBERS: { key: 'cadence_days' | 'due_days' | 'reminder_days' | 'grace_days'; label: string }[] = [
  { key: 'cadence_days', label: 'Review every (days)' },
  { key: 'due_days', label: 'Due after (days)' },
  { key: 'reminder_days', label: 'Remind before due (days)' },
  { key: 'grace_days', label: 'Grace after due (days)' },
]

/** The access-review policy: cadence, due date, reminders, grace and per-classification cadence. */
export function PolicyCard() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    adminApi.get<{ policy: Policy }>('/api/access-reviews/policy')
      .then(r => setPolicy(r.policy))
      .catch(e => setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) }))
  }, [])

  if (!policy) return msg ? <p style={{ color: 'var(--red)' }}>{msg.text}</p> : null

  const set = (patch: Partial<Policy>) => setPolicy({ ...policy, ...patch })
  const setLevel = (lvl: string, v: string) => {
    const next = { ...policy.by_classification }
    if (v === '') delete next[lvl]
    else next[lvl] = Number(v)
    set({ by_classification: next })
  }

  async function save() {
    try {
      const r = await adminApi.put<{ policy: Policy }>('/api/access-reviews/policy', policy)
      setPolicy(r.policy)
      setMsg({ ok: true, text: 'Saved' })
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) })
    }
  }

  return (
    <div className="card" style={{ padding: 12, marginBottom: 16 }}>
      <b>Policy</b>
      <label style={{ display: 'flex', gap: 6, alignItems: 'center', margin: '8px 0' }}>
        <input type="checkbox" checked={policy.enabled} onChange={e => set({ enabled: e.target.checked })} />
        Start campaigns automatically on this cadence
      </label>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {NUMBERS.map(n => (
          <label key={n.key} style={{ display: 'flex', flexDirection: 'column', fontSize: '.75rem', color: 'var(--dim)', gap: 2 }}>
            {n.label}
            <input type="number" style={{ width: 110 }} value={policy[n.key]} onChange={e => set({ [n.key]: Number(e.target.value) } as Partial<Policy>)} />
          </label>
        ))}
        <label style={{ display: 'flex', flexDirection: 'column', fontSize: '.75rem', color: 'var(--dim)', gap: 2 }}>
          Unreviewed after grace
          <select value={policy.overdue_action} onChange={e => set({ overdue_action: e.target.value as Policy['overdue_action'] })}>
            <option value="none">Do nothing</option>
            <option value="report">E-mail a report to platform admins</option>
          </select>
        </label>
      </div>
      <div style={{ fontSize: '.75rem', color: 'var(--dim)', margin: '10px 0 4px' }}>
        Own cadence per data classification (blank: reviewed in the default campaign)
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {LEVELS.map(l => (
          <label key={l} style={{ display: 'flex', flexDirection: 'column', fontSize: '.75rem', color: 'var(--dim)', gap: 2 }}>
            {l}
            <input type="number" style={{ width: 90 }} value={policy.by_classification[l] ?? ''} onChange={e => setLevel(l, e.target.value)} />
          </label>
        ))}
      </div>
      <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center' }}>
        <button className="btn" onClick={save}>Save policy</button>
        {msg && <span style={{ color: msg.ok ? 'var(--green)' : 'var(--red)', fontSize: '.85rem' }}>{msg.text}</span>}
      </div>
    </div>
  )
}
