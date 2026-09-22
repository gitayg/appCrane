import { useEffect, useRef, useState } from 'react'
import { peekToPromptPrefix, type PeekCtx } from '../../hooks/usePeek'
import { Icon } from '../icons'
import { CoderChanges } from './CoderChanges'
import { CoderRefusal } from './CoderRefusal'
import { useCoderSession, type Entry } from './useCoderSession'

interface Props {
  slug:       string
  appName:    string
  open:       boolean
  onClose:    () => void
  /** Offset from the top of the frame — the <crane-app-topbar> height. */
  top:        number
  width?:     number
  /** admin/owner on this app: the bar POST .../release enforces. */
  canRelease: boolean
  /** Picker state, owned by AppFrame so there is exactly one usePeek. */
  peekActive:    boolean
  peekCtx:       PeekCtx | null
  onPickStart:   () => void
  onPickStop:    () => void
  onPeekConsumed: () => void
}

/**
 * The coder chat, docked beside the running app rather than laid over it.
 *
 * Docking is the whole point: the conversation is ABOUT the app on screen, so
 * the app has to stay visible and clickable while you talk. AppFrame shrinks
 * the iframe by the panel's width through --frame-dock-width, the same way
 * Applications.tsx docks BugPanel.
 */
export function CoderPanel(props: Props) {
  const { slug, appName, open, onClose, top, width = 460, canRelease } = props
  const s = useCoderSession(slug, open)
  const [tab, setTab]   = useState<'chat' | 'changes'>('chat')
  const [draft, setDraft] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)
  const scrollRef = useRef<HTMLDivElement>(null)
  const wasStreaming = useRef(false)

  // A picked element becomes a prefix on the next prompt, and the composer
  // takes focus so the user can just keep typing.
  const taRef = useRef<HTMLTextAreaElement>(null)
  useEffect(() => {
    if (!open || !props.peekCtx) return
    setDraft(d => peekToPromptPrefix(props.peekCtx!) + d)
    props.onPeekConsumed()
    taRef.current?.focus()
  }, [props.peekCtx, open]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [s.entries.length, s.entries[s.entries.length - 1]?.text])

  // Re-read the change set whenever a turn ends — that is exactly when the
  // workspace has new files in it.
  useEffect(() => {
    if (wasStreaming.current && !s.streaming) setRefreshKey(k => k + 1)
    wasStreaming.current = s.streaming
  }, [s.streaming])

  if (!open) return null

  const canSend = !!s.sessionId && !s.streaming && s.status !== 'paused'
  const send = () => {
    const text = draft.trim()
    if (!text || !canSend) return
    void s.send(text)
    setDraft('')
  }

  return (
    <aside className="coder-panel" style={{ width, top }}>
      <header className="coder-head">
        <Icon.Sparkles size={14} />
        <span className="coder-title">Coder</span>
        <span className="coder-app">{appName}</span>
        <span className="coder-head-right">
          <span className={`coder-pill coder-pill-${s.status}`}>
            {s.streaming && <i className="coder-dot" />}
            {s.queueAhead ? `queued · ${s.queueAhead} ahead` : s.status}
          </span>
          <button type="button" className="coder-close" onClick={onClose} title="Close">×</button>
        </span>
      </header>

      {s.sessionId && (
        <nav className="coder-tabs">
          <button
            type="button"
            className={'coder-tab' + (tab === 'chat' ? ' active' : '')}
            onClick={() => setTab('chat')}
          >Chat</button>
          <button
            type="button"
            className={'coder-tab' + (tab === 'changes' ? ' active' : '')}
            onClick={() => setTab('changes')}
          >Changes</button>
          {s.costCents > 0 && (
            <span className="coder-cost">${(s.costCents / 100).toFixed(2)}</span>
          )}
        </nav>
      )}

      {tab === 'changes' && s.sessionId ? (
        <div className="coder-body">
          <CoderChanges
            slug={slug}
            sessionId={s.sessionId}
            canRelease={canRelease}
            refreshKey={refreshKey}
          />
        </div>
      ) : (
        <>
          <div className="coder-body" ref={scrollRef}>
            {s.phase === 'loading' && <div className="coder-note">Looking for a session…</div>}

            {s.phase === 'absent' && (
              <div className="coder-start">
                <p className="coder-note">
                  Start a coder session to work on <strong>{appName}</strong>. AppCrane
                  opens a container on this app’s repository; you describe the change,
                  review what it wrote, then release the files you want to sandbox.
                </p>
                {s.error && <CoderRefusal error={s.error} />}
                <button
                  type="button"
                  className="coder-btn coder-btn-primary"
                  disabled={s.starting}
                  onClick={() => void s.start()}
                >{s.starting ? 'Starting…' : 'Start a session'}</button>
              </div>
            )}

            {s.phase === 'failed' && <CoderRefusal error={s.error} />}

            {s.phase === 'ready' && s.entries.length === 0 && (
              <div className="coder-note">
                Session ready on <code>{s.session?.branch_name}</code>. Describe what you
                want changed.
              </div>
            )}

            {s.entries.map(e => <Bubble key={e.key} e={e} />)}

            {s.status === 'paused' && (
              <div className="coder-paused">
                This session is paused — its container was evicted.
                <button type="button" className="coder-btn coder-btn-xs" onClick={() => void s.resume()}>
                  Resume
                </button>
              </div>
            )}
            {s.phase === 'ready' && s.error && <CoderRefusal error={s.error} />}
          </div>

          {s.sessionId && (
            <div className="coder-composer">
              <textarea
                ref={taRef}
                className="coder-textarea"
                rows={3}
                value={draft}
                placeholder="Describe the change… (↩ send · ⇧↩ newline)"
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
                }}
                disabled={!canSend}
              />
              <div className="coder-composer-row">
                <button
                  type="button"
                  className={'coder-btn coder-btn-xs' + (props.peekActive ? ' active' : '')}
                  onClick={() => (props.peekActive ? props.onPickStop() : props.onPickStart())}
                  title="Point at an element in the app to attach its context"
                >{props.peekActive ? 'Pick…' : 'Point at element'}</button>
                <span className="coder-spacer" />
                {s.streaming
                  ? <button type="button" className="coder-btn coder-btn-danger" onClick={() => void s.stop()}>Stop</button>
                  : <button
                      type="button"
                      className="coder-btn coder-btn-primary"
                      disabled={!draft.trim() || !canSend}
                      onClick={send}
                    >Send</button>}
              </div>
            </div>
          )}
        </>
      )}
    </aside>
  )
}

function Bubble({ e }: { e: Entry }) {
  if (e.kind === 'tool') {
    return (
      <div className="coder-tool">
        <span className="coder-tool-name">{e.tool}</span>
        <span className="coder-tool-arg">{e.text}</span>
      </div>
    )
  }
  if (e.kind === 'note')  return <div className="coder-note">{e.text}</div>
  if (e.kind === 'error') return <div className="coder-error">{e.text}</div>
  return <div className={`coder-msg coder-msg-${e.kind}`}>{e.text}</div>
}
