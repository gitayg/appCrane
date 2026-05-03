import { useEffect, useState } from 'react'
import { useEnhancementSubmit } from '../../hooks/useEnhancementSubmit'
import { useMe, isAdmin } from '../../hooks/useMe'

interface Props {
  slug:    string | null | undefined
  appName: string
  open:    boolean
  onClose: () => void
  width?:  number
}

/**
 * Right drawer for "Request" — file an enhancement request against the
 * app. Matches the portal's planPanel UX visually but trims the
 * planner/refine loop: submit goes straight to /api/enhancements and the
 * Jobs button already surfaces status. Plan-review/refine UI is a
 * follow-up.
 */
export function RequestPanel({ slug, appName, open, onClose, width = 420 }: Props) {
  const { submit, busy, last, reset } = useEnhancementSubmit(slug)
  const me = useMe()
  const canBuild = isAdmin(me)
  const [text, setText] = useState('')

  useEffect(() => {
    if (!open) { setText(''); reset() }
  }, [open, reset])

  if (!open) return null

  async function onSubmit() {
    if (!text.trim() || busy) return
    const r = await submit(text)
    if (r.ok) setText('')
  }

  return (
    <div className="ask-panel open" style={{ width }}>
      <div className="ask-header">
        <span>💡 Request</span>
        <span className="ask-app-label">{appName}</span>
        <div className="ask-header-right">
          <button type="button" className="ask-close" onClick={onClose}>×</button>
        </div>
      </div>

      <div className="ask-messages">
        <div className="ask-empty">
          Describe an enhancement or feature you want for this app. AppCrane
          will plan it, generate code, and open a PR — you can track progress
          in the 📋 Jobs panel.
        </div>

        {last && last.ok && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%' }}>
            ✅ Request {last.enhancementId ? `#${last.enhancementId} ` : ''}submitted.
            <div style={{ fontSize: '.78rem', color: 'var(--dim)', marginTop: 6 }}>
              Track its progress in the 📋 Jobs panel.
            </div>
          </div>
        )}
        {last && !last.ok && last.message && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%', borderColor: '#ef4444' }}>
            ⚠️ {last.message}
          </div>
        )}
      </div>

      <div className="ask-input-area">
        <div className="ask-input-row">
          <textarea
            className="ask-textarea"
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSubmit() }
            }}
            placeholder="Describe the enhancement or feature you want…"
            rows={3}
            disabled={busy}
          />
          <button
            type="button"
            className="ask-send"
            onClick={onSubmit}
            disabled={busy || !text.trim()}
            title={canBuild
              ? 'Admin: AppCrane will plan, code, and open a PR automatically'
              : 'Submit for review by an admin — they decide what to build'}
          >{busy
            ? 'Submitting…'
            : (canBuild ? '🔨 Build' : '📤 Submit for Review')}</button>
        </div>
      </div>
    </div>
  )
}
