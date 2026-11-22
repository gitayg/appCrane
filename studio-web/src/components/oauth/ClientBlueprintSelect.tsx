import type { Blueprint } from './blueprintTypes'

/** Pin a blueprint to one OAuth client, or leave it unpinned. */
export function ClientBlueprintSelect({ value, blueprints, disabled, onChange }: {
  value: number | null
  blueprints: Blueprint[]
  disabled: boolean
  onChange: (id: number | null) => void
}) {
  return (
    <select aria-label="Pinned blueprint" value={value ?? ''} disabled={disabled}
      onChange={e => onChange(e.target.value ? Number(e.target.value) : null)} style={{ fontSize: '.78rem' }}>
      <option value="">No pinned blueprint</option>
      {blueprints.map(b => <option key={b.id} value={b.id}>Pinned: {b.name}</option>)}
      {value != null && !blueprints.some(b => b.id === value) && <option value={value}>Pinned: deleted blueprint</option>}
    </select>
  )
}
