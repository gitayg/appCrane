import { useEffect, useRef, useState } from 'react'
import { useAskSession } from '../../hooks/useAskSession'

interface Props {
  slug:    string | null | undefined
  appName: string
  open:    boolean
  onClose: () => void
  width?:  number
}

/**
 * Right-side drawer for "Learn" — ask Claude about the codebase.
 * Same shape and behavior as the portal's askPanel, minus the History
 * picker and the 🎯 element-peek (those are deferred — they need a
 * session-listing UI and a DOM picker overlay respectively).
 */
export function AskPanel({ slug, appName, open, onClose, width = 380 }: Props) {
  const { messages, working, busy, send, reset } = useAskSession(slug)
  const [input, setInput] = useState('')
  const messagesRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to newest message + working indicator
  useEffect(() => {
    if (!messagesRef.current) return
    messagesRef.current.scrollTop = messagesRef.current.scrollHeight
  }, [messages, working.active])

  if (!open) return null

  function submit() {
    if (!input.trim() || busy) return
    send(input)
    setInput('')
  }

  return (
    <div className="ask-panel open" style={{ width }}>
      <div className="ask-header">
        <span>🤖 Learn</span>
        <span className="ask-app-label">{appName}</span>
        <div className="ask-header-right">
          <button
            type="button"
            className="ask-sessions-btn"
            onClick={() => { if (confirm('Clear this conversation?')) reset() }}
            title="Start a fresh thread (does not delete history on the server)"
          >New</button>
          <button type="button" className="ask-close" onClick={onClose}>×</button>
        </div>
      </div>

      <div ref={messagesRef} className="ask-messages">
        {messages.length === 0 && (
          <div className="ask-empty">
            Learn about this application — Claude will read the source code to answer.
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`ask-msg ${m.role}`}>{m.content}</div>
        ))}
      </div>

      {working.active && (
        <div className="ask-working">
          <div className="ask-spinner" />
          <div className="ask-working-text">{working.text || 'Working…'}</div>
          <span className="ask-live-stats">
            {working.tokens > 0
              ? `${working.elapsedSec}s · ${working.tokens.toLocaleString()} tok`
              : `${working.elapsedSec}s`}
          </span>
        </div>
      )}

      <div className="ask-input-area">
        <div className="ask-input-row">
          <textarea
            className="ask-textarea"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit() }
            }}
            placeholder="Learn about this application…"
            rows={2}
            disabled={busy}
          />
          <button
            type="button"
            className="ask-send"
            onClick={submit}
            disabled={busy || !input.trim()}
          >Send</button>
        </div>
      </div>
    </div>
  )
}
