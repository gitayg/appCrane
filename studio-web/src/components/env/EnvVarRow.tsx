import { useState, type CSSProperties } from 'react'
import type { MaskedEnvVar } from './envVarsApi'

interface Props {
  v: MaskedEnvVar
  revealed: string | undefined
  canReveal: boolean
  revealRefusal?: string
  busy: boolean
  onReveal: () => void
  onHide: () => void
  onSave: (value: string) => Promise<boolean>
  onDelete: () => void
  compact?: boolean
}

const mono: CSSProperties = { fontFamily: "'SF Mono',Monaco,monospace", fontSize: '.8rem' }

export function EnvVarRow({ v, revealed, canReveal, revealRefusal, busy, onReveal, onHide, onSave, onDelete, compact }: Props) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const [copied, setCopied] = useState(false)
  const btn = compact ? 'btn btn-xs' : 'btn btn-sm'

  async function save() {
    if (!draft) return
    if (await onSave(draft)) { setEditing(false); setDraft('') }
  }

  async function copy() {
    if (revealed === undefined) return
    try {
      await navigator.clipboard.writeText(revealed)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard denied: the value is on screen */ }
  }

  return (
    <tr data-env-key={v.key}>
      <td style={{ ...mono, whiteSpace: 'nowrap' }}>{v.key}</td>
      <td style={{ ...mono, wordBreak: 'break-all' }}>
        {editing ? (
          <input
            type="text"
            autoFocus
            autoComplete="off"
            spellCheck={false}
            placeholder="Enter a new value"
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') save(); if (e.key === 'Escape') { setEditing(false); setDraft('') } }}
            style={{ ...mono, width: '100%', padding: '4px 8px' }}
          />
        ) : revealed !== undefined ? (
          <span>{revealed}</span>
        ) : v.error ? (
          <span style={{ color: 'var(--red)' }}>cannot decrypt</span>
        ) : (
          <span>
            {v.preview || v.value}
            {v.fingerprint && <span style={{ color: 'var(--dim)', marginLeft: 8 }} title="sha256 fingerprint of the value">#{v.fingerprint}</span>}
          </span>
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
            {revealed !== undefined ? (
              <>
                <button className={btn} onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>{' '}
                <button className={btn + ' btn-dim'} onClick={onHide}>Hide</button>
              </>
            ) : (
              <button
                className={btn + ' btn-dim'}
                disabled={!canReveal || busy || !!v.error}
                title={canReveal ? 'Decrypt this one value (audited; the app owners are notified)' : revealRefusal}
                style={canReveal ? undefined : { opacity: 0.5, cursor: 'not-allowed' }}
                onClick={onReveal}
              >Reveal</button>
            )}{' '}
            <button className={btn} onClick={() => setEditing(true)}>Edit</button>{' '}
            <button className={btn + ' btn-red'} onClick={onDelete}>Del</button>
          </>
        )}
      </td>
    </tr>
  )
}
