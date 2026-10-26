import { useState, type CSSProperties, type ReactNode } from 'react'
import { Icon } from '../icons'

// A stored secret, masked until the viewer presses the eye. Nothing plaintext
// is held before that press: reveal() is the only thing that fetches it, and
// that server call is what audits the read and alerts the owners. Hiding
// drops the value from state again.

export interface SecretValueProps {
  name: string
  reveal: () => Promise<string>
  masked?: ReactNode
  fingerprint?: string
  disabled?: boolean
  disabledReason?: string
  multiline?: boolean
  compact?: boolean
  onError?: (message: string) => void
}

const mono: CSSProperties = { fontFamily: "'SF Mono',Monaco,monospace", fontSize: '.8rem' }

export function SecretValue({ name, reveal, masked, fingerprint, disabled, disabledReason, multiline, compact, onError }: SecretValueProps) {
  const [value, setValue] = useState<string | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const shown = value !== undefined
  const btn = compact ? 'btn btn-xs btn-icon' : 'btn btn-sm btn-icon'

  async function toggle() {
    if (shown) { setValue(undefined); setCopied(false); return }
    setBusy(true)
    setError(null)
    try {
      setValue(await reveal())
    } catch (e) {
      const m = (e as Error)?.message || 'Cannot reveal'
      setError(m)
      onError?.(m)
    } finally {
      setBusy(false)
    }
  }

  async function copy() {
    if (value === undefined) return
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard denied: the value is on screen */ }
  }

  const title = disabled ? disabledReason : shown ? `Hide ${name}` : `Show ${name} (audited; the owners are alerted)`

  return (
    <span className="secret-value" style={{ display: 'inline-flex', alignItems: multiline && shown ? 'flex-start' : 'center', gap: 6, maxWidth: '100%', flexWrap: 'wrap' }}>
      {shown ? (
        multiline
          ? <pre style={{ ...mono, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 240, overflow: 'auto' }}>{value}</pre>
          : <span style={{ ...mono, wordBreak: 'break-all' }}>{value}</span>
      ) : (
        <span style={{ ...mono, wordBreak: 'break-all' }}>
          {masked ?? '••••••••'}
          {fingerprint && <span style={{ color: 'var(--dim)', marginLeft: 8 }} title="Fingerprint of the value: it changes when the value changes">#{fingerprint}</span>}
        </span>
      )}
      <button
        type="button"
        className={btn + ' btn-dim'}
        aria-label={shown ? `Hide ${name}` : `Show ${name}`}
        aria-pressed={shown}
        title={title}
        disabled={disabled || busy}
        style={disabled ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}
        onClick={toggle}
      >
        {shown ? <Icon.EyeOff size={14} /> : <Icon.Eye size={14} />}
      </button>
      {shown && (
        <button type="button" className={compact ? 'btn btn-xs' : 'btn btn-sm'} onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
      )}
      {error && <span role="alert" style={{ color: 'var(--red)', fontSize: '.75rem' }}>{error}</span>}
    </span>
  )
}
