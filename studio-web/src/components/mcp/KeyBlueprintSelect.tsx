import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { Blueprint } from '../oauth/blueprintTypes'

/** Optional blueprint for a new personal MCP key (GET /api/oauth/blueprints). */
export function KeyBlueprintSelect({ value, onChange, disabled }: { value: string; onChange: (name: string) => void; disabled: boolean }) {
  const [list, setList] = useState<Blueprint[]>([])
  useEffect(() => {
    adminApi.get<{ blueprints: Blueprint[] }>('/api/oauth/blueprints').then(r => setList(r.blueprints)).catch(() => {})
  }, [])
  if (!list.length) return null
  return (
    <select aria-label="Blueprint for the new key" value={value} disabled={disabled} onChange={e => onChange(e.target.value)}
      style={{ padding: '6px 8px', fontSize: '.85rem', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}>
      <option value="">Full access (your role)</option>
      {list.map(b => <option key={b.id} value={b.name} title={b.description}>Limit to: {b.name}</option>)}
    </select>
  )
}
