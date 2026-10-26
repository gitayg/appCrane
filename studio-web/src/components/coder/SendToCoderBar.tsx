import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { coderApi } from './api'
import { Icon } from '../icons'

/** Same cap the server enforces (server/services/builder/requestsPrompt.js). */
export const MAX_CODER_BATCH = 10

interface Props {
  slug: string
  /** In the order the user picked them — the order the coder works them. */
  ids: number[]
  onClear: () => void
  onSent: (ids: number[]) => void
}

/**
 * The Requests page's "Send to coder" action for a selection from ONE app.
 * The requests go to the coder as one prompt in one session; afterwards the
 * app opens on Sandbox with the coder panel showing that session, which is
 * where the work is watched, reviewed and released.
 */
/** The app's Sandbox with the coder panel open on one session. */
export function coderSessionHref(slug: string, sessionId: string) {
  return `/launch/${encodeURIComponent(slug)}?coder=1&session=${encodeURIComponent(sessionId)}`
}

export function SendToCoderBar({ slug, ids, onClear, onSent }: Props) {
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function send() {
    setBusy(true)
    setError(null)
    try {
      const r = await coderApi.dispatchRequests(slug, ids)
      onSent(ids)
      navigate(coderSessionHref(slug, r.session_id))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const n = ids.length
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
      padding: '8px 12px', margin: '8px 0', borderRadius: 6,
      background: 'var(--surface2)', border: '1px solid var(--border)', fontSize: '.82rem',
    }}>
      <span>
        <strong>{n}</strong> request{n === 1 ? '' : 's'} from <strong>{slug}</strong> selected
        <span style={{ color: 'var(--dim)' }}>
          {n > 1 ? ' — the coder works through them in one session, in the order you picked them' : ''}
        </span>
      </span>
      <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
        <button className="btn btn-xs" onClick={onClear} disabled={busy}>Clear</button>
        <button className="btn btn-xs btn-accent" onClick={send} disabled={busy || n === 0}>
          <Icon.Sparkles size={12} /> {busy ? 'Sending…' : 'Send to coder'}
        </button>
      </span>
      {error && <div style={{ flexBasis: '100%', color: 'var(--red)' }}>{error}</div>}
    </div>
  )
}
