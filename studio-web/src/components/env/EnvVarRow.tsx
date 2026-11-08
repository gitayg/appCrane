import { useState, type CSSProperties } from 'react'
import type { EnvStore, MaskedEnvVar } from './envVarsApi'
import { StoreInSecretsManager } from './StoreInSecretsManager'
import { SecretValue } from '../secret/SecretValue'
import { PasswordInput } from '../secret/PasswordInput'

interface Props {
  v: MaskedEnvVar
  canReveal: boolean
  revealRefusal?: string
  busy: boolean
  offerSecretsManager: boolean
  onReveal: () => Promise<string>
  onSave: (value: string, store?: EnvStore) => Promise<boolean>
  onDelete: () => void
  compact?: boolean
}

const mono: CSSProperties = { fontFamily: "'SF Mono',Monaco,monospace", fontSize: '.8rem' }

export function EnvVarRow({ v, canReveal, revealRefusal, busy, offerSecretsManager, onReveal, onSave, onDelete, compact }: Props) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const inSecretsManager = v.source === 'secrets_manager'
  const [store, setStore] = useState(inSecretsManager)
  const btn = compact ? 'btn btn-xs' : 'btn btn-sm'

  async function save() {
    if (!draft) return
    if (await onSave(draft, store ? 'secrets_manager' : undefined)) { setEditing(false); setDraft('') }
  }

  return (
    <tr data-env-key={v.key}>
      <td style={{ ...mono, whiteSpace: 'nowrap' }}>{v.key}</td>
      <td style={{ ...mono, wordBreak: 'break-all' }}>
        {editing ? (
          <>
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
          {/* A reference always offers it, so a failed status call cannot turn it into a stored value unnoticed. */}
          {(offerSecretsManager || inSecretsManager) && (
            <StoreInSecretsManager name={v.key} checked={store} onChange={setStore} />
          )}
          </>
        ) : v.error ? (
          <span style={{ color: 'var(--red)' }}>cannot decrypt</span>
        ) : inSecretsManager ? (
          <>
            <span
              className="badge badge-pending"
              title="AppCrane reads this value from AWS Secrets Manager at each deploy and restart, and stores only this reference."
              style={{ marginRight: 8, whiteSpace: 'nowrap' }}
            >Secrets Manager</span>
            <span data-secret-ref>{v.value}</span>
          </>
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
