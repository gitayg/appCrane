import { useState, type CSSProperties } from 'react'
import type { MaskedEnvVar } from './envVarsApi'
import { SecretValue } from '../secret/SecretValue'
import { PasswordInput } from '../secret/PasswordInput'

interface Props {
  v: MaskedEnvVar
  canReveal: boolean
  revealRefusal?: string
  busy: boolean
  onReveal: () => Promise<string>
  onSave: (value: string) => Promise<boolean>
  onDelete: () => void
  compact?: boolean
}

const mono: CSSProperties = { fontFamily: "'SF Mono',Monaco,monospace", fontSize: '.8rem' }

export function EnvVarRow({ v, canReveal, revealRefusal, busy, onReveal, onSave, onDelete, compact }: Props) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const btn = compact ? 'btn btn-xs' : 'btn btn-sm'

  async function save() {
    if (!draft) return
    if (await onSave(draft)) { setEditing(false); setDraft('') }
  }

  return (
    <tr data-env-key={v.key}>
      <td style={{ ...mono, whiteSpace: 'nowrap' }}>{v.key}</td>
      <td style={{ ...mono, wordBreak: 'break-all' }}>
        {editing ? (
          <PasswordInput
            label={`new value for ${v.key}`}
            autoFocus
            autoComplete="new-password"
            spellCheck={false}
            placeholder="Enter a new value"
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') save(); if (e.key === 'Escape') { setEditing(false); setDraft('') } }}
            style={{ ...mono, width: '100%', padding: '4px 8px' }}
          />
        ) : v.error ? (
          <span style={{ color: 'var(--red)' }}>cannot decrypt</span>
        ) : (
          <SecretValue
            key={v.updated_at}
            name={v.key}
            masked={v.preview || v.value}
            fingerprint={v.fingerprint}
            disabled={!canReveal || busy}
            disabledReason={canReveal ? undefined : revealRefusal}
            compact={compact}
            reveal={onReveal}
          />
        )}
      </td>
      <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
        {editing ? (
          <>
            <button className={btn} disabled={!draft || busy} onClick={save}>Save</button>{' '}
            <button className={btn + ' btn-dim'} onClick={() => { setEditing(false); setDraft('') }}>Cancel</button>
          </>
        ) : (
          <>
            <button className={btn} onClick={() => setEditing(true)}>Edit</button>{' '}
            <button className={btn + ' btn-red'} onClick={onDelete}>Del</button>
          </>
        )}
      </td>
    </tr>
  )
}
