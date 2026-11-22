import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { Blueprint, ScopeGroup } from './blueprintTypes'

interface Props {
  groups: ScopeGroup[]
  initial: Blueprint | null
  busy: boolean
  onSave: (body: { name?: string; description: string; scopes: string[]; apps: string[] | null }) => void
  onCancel: () => void
}

/** Create or edit one blueprint: scope checkboxes from the server's list, and an optional app limit. */
export function BlueprintEditor({ groups, initial, busy, onSave, onCancel }: Props) {
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [scopes, setScopes] = useState<string[]>(initial?.scopes ?? ['mcp:read'])
  const [limitApps, setLimitApps] = useState(initial?.apps != null)
  const [apps, setApps] = useState<string[]>(initial?.apps ?? [])
  const [allApps, setAllApps] = useState<string[]>([])

  useEffect(() => {
    adminApi.get<{ apps: { slug: string }[] }>('/api/apps').then(r => setAllApps(r.apps.map(a => a.slug).sort())).catch(() => {})
  }, [])

  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter(x => x !== v) : [...list, v])

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 12, margin: '8px 0' }}>
      {!initial && (
        <label style={{ display: 'block', fontSize: '.82rem', marginBottom: 6 }}>
          Name (lowercase letters, digits and dashes)
          <input value={name} onChange={e => setName(e.target.value)} placeholder="deploy-alpha" style={{ display: 'block', width: '100%' }} />
        </label>
      )}
      <label style={{ display: 'block', fontSize: '.82rem', marginBottom: 8 }}>
        What it is for
        <input value={description} onChange={e => setDescription(e.target.value)} style={{ display: 'block', width: '100%' }} />
      </label>
      <fieldset style={{ border: 0, padding: 0, margin: '0 0 8px' }}>
        <legend style={{ fontSize: '.82rem', fontWeight: 600 }}>It may</legend>
        {groups.map(g => (
          <label key={g.scope} title={g.tools.join(', ')} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: '.82rem', margin: '4px 0' }}>
            <input type="checkbox" checked={scopes.includes(g.scope)} onChange={() => setScopes(toggle(scopes, g.scope))} />
            <span><strong>{g.label}</strong> <code style={{ fontSize: '.72rem' }}>{g.scope}</code><br />
              <span style={{ color: 'var(--dim)' }}>{g.description}{g.tools.length > 0 && ` (${g.tools.length} AppCrane tool${g.tools.length === 1 ? '' : 's'})`}</span></span>
          </label>
        ))}
      </fieldset>
      <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: '.82rem' }}>
        <input type="checkbox" checked={limitApps} onChange={e => setLimitApps(e.target.checked)} />
        Only these apps (otherwise: every app the person can reach)
      </label>
      {limitApps && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 12px', margin: '6px 0 0 24px', fontSize: '.8rem' }}>
          {allApps.length === 0 && <span style={{ color: 'var(--dim)' }}>No apps yet.</span>}
          {allApps.map(slug => (
            <label key={slug} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
              <input type="checkbox" checked={apps.includes(slug)} onChange={() => setApps(toggle(apps, slug))} />{slug}
            </label>
          ))}
        </div>
      )}
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 10 }}>
        <button type="button" className="btn btn-xs" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="button" className="btn btn-xs btn-primary" disabled={busy || scopes.length === 0 || (!initial && !name)}
          onClick={() => onSave({ ...(initial ? {} : { name }), description, scopes, apps: limitApps ? apps : null })}>
          {initial ? 'Save changes' : 'Create blueprint'}
        </button>
      </div>
    </div>
  )
}
