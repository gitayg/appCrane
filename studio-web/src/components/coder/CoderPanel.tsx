import { useEffect, useRef, useState } from 'react'
import { peekToPromptPrefix, type PeekCtx } from '../../hooks/usePeek'
import { Icon } from '../icons'
import { CoderChanges } from './CoderChanges'
import { CoderRefusal } from './CoderRefusal'
import { CoderUnavailable } from './CoderUnavailable'
import type { CoderAvailability } from './api'
import { fileToDataUrl, useCoderSession, type Entry } from './useCoderSession'

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
  /**
   * The server's answer to "can this user use the coder here?", or null while
   * it is loading. When it says no, the panel explains why instead of starting
   * a session the server has already told us it would refuse.
   */
  availability: CoderAvailability | null
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
  const { slug, appName, open, onClose, top, width = 460, availability } = props
  // Unknown until availability loads, then the server's verdict. Starting a
  // session before we know would just produce the refusal we are about to
  // explain better, so the session hook stays inert until the answer is yes.
  const usable = availability?.available === true
  // The server's can_release is the truth; the role-derived prop is only a
  // placeholder for the moment before availability arrives.
  const canRelease = availability ? availability.can_release : props.canRelease
  const s = useCoderSession(slug, open && usable)
  const [tab, setTab]   = useState<'chat' | 'changes'>('chat')
  const [draft, setDraft] = useState('')
  // Files waiting to go with the next message: pasted, dropped or picked.
  const [files, setFiles] = useState<File[]>([])
  const [fileNote, setFileNote] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
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

  // A running turn no longer disables the composer: the message is queued
  // server-side and dispatched when the turn ends. A paused session accepts it
  // too — send() resumes the container first, then runs it. Only an in-flight
  // resume blocks the composer.
  const canSend = !!s.sessionId && !s.resumingSince
  const send = () => {
    const text = draft.trim()
    if (!text || !canSend) return
    void s.send(text, undefined, files)
    setDraft('')
    setFiles([])
    setFileNote(null)
  }
  // Checked here as well as on the server so the reason shows before sending.
  const addFiles = (incoming: File[]) => {
    if (!incoming.length) return
    const tooBig = incoming.filter(f => f.size > MAX_FILE_BYTES)
    const ok = incoming.filter(f => f.size <= MAX_FILE_BYTES)
    const room = MAX_FILES - files.length
    const notes: string[] = []
    if (tooBig.length) notes.push(`${tooBig.map(f => f.name).join(', ')}: over ${MAX_FILE_BYTES / 1048576} MB`)
    if (ok.length > room) notes.push(`at most ${MAX_FILES} files per message`)
    setFileNote(notes.length ? `Not attached — ${notes.join('; ')}.` : null)
    setFiles(prev => [...prev, ...ok.slice(0, Math.max(0, room))])
  }

  return (
    <aside className="coder-panel" style={{ width, top }}>
      <header className="coder-head">
        <Icon.Sparkles size={14} />
        <span className="coder-title">Coder</span>
        <span className="coder-app">{appName}</span>
        <span className="coder-head-right">
          {availability && !usable ? (
            <span className="coder-pill coder-pill-unavailable">unavailable</span>
          ) : (
            <span className={`coder-pill coder-pill-${s.status}`}>
              {s.streaming && <i className="coder-dot" />}
              {s.queueAhead ? `queued · ${s.queueAhead} ahead` : s.status}
            </span>
          )}
          <button type="button" className="coder-close" onClick={onClose} title="Close">×</button>
        </span>
      </header>

      {availability && !usable && (
        <CoderUnavailable gaps={availability.gaps} appName={appName} />
      )}

      {usable && s.sessionId && (
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

      {!usable ? null : tab === 'changes' && s.sessionId ? (
        <div className="coder-body">
          <CoderChanges
            slug={slug}
            sessionId={s.sessionId}
            canRelease={canRelease}
            refreshKey={refreshKey}
            deploys={s.deploys}
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

            {s.followups.map(f => (
              <div key={`f${f.id}`} className="coder-msg coder-msg-user" style={{ opacity: 0.62, borderStyle: 'dashed' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 10, letterSpacing: '0.06em', textTransform: 'uppercase', opacity: 0.85 }}>
                    Pending{f.model ? ` · ${f.model}` : ''}{f.mode && f.mode !== 'auto' ? ` · ${modeLabel(s.modes, f.mode)}` : ''}{fileCount(f.attachments) ? ` · ${fileCount(f.attachments)} file${fileCount(f.attachments) === 1 ? '' : 's'}` : ''}
                  </span>
                  <span className="coder-spacer" />
                  <button
                    type="button"
                    className="coder-btn coder-btn-xs"
                    title="Cancel this queued message before it starts"
                    onClick={() => void s.cancelFollowup(f.id)}
                  >Cancel</button>
                </div>
                {f.prompt}
              </div>
            ))}

            {s.status === 'paused' && (
              s.resumingSince
                ? <ResumeProgress since={s.resumingSince} />
                : (
                  <div className="coder-paused">
                    This session is paused — its container was stopped. Resume it, or just send a message and it will resume first.
                    <button type="button" className="coder-btn coder-btn-xs" onClick={() => void s.resume()}>
                      Resume
                    </button>
                  </div>
                )
            )}
            {s.phase === 'ready' && s.error && <CoderRefusal error={s.error} />}
          </div>

          {s.sessionId && (
            <div
              className="coder-composer"
              onDragOver={e => { if (e.dataTransfer.types.includes('Files')) e.preventDefault() }}
              onDrop={e => {
                if (!e.dataTransfer.files.length) return
                e.preventDefault()
                addFiles(Array.from(e.dataTransfer.files))
              }}
            >
              {files.length > 0 && (
                <div className="coder-attachments">
                  {files.map((f, i) => (
                    <AttachmentChip key={`${f.name}-${i}`} file={f} onRemove={() => setFiles(prev => prev.filter((_, j) => j !== i))} />
                  ))}
                </div>
              )}
              {fileNote && <div className="coder-note">{fileNote}</div>}
              <textarea
                ref={taRef}
                className="coder-textarea"
                rows={3}
                value={draft}
                placeholder={s.streaming
                  ? 'Type the next instruction — it runs when this turn ends…'
                  : s.status === 'paused'
                    ? 'Type an instruction — the session resumes first, then runs it'
                    : 'Describe the change… (↩ send · ⇧↩ newline)'}
                onChange={e => setDraft(e.target.value)}
                onPaste={e => {
                  // Screenshots and copied files arrive as clipboard files;
                  // plain text keeps the browser's own paste.
                  const pasted = Array.from(e.clipboardData.files)
                  if (!pasted.length) return
                  e.preventDefault()
                  addFiles(pasted)
                }}
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
                <button
                  type="button"
                  className="coder-btn coder-btn-xs"
                  onClick={() => fileInputRef.current?.click()}
                  title="Attach a file or image (or paste / drop one into the message)"
                  aria-label="Attach file"
                >Attach</button>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  hidden
                  onChange={e => { addFiles(Array.from(e.target.files || [])); e.target.value = '' }}
                />
                {s.models.length > 0 && (
                  <select
                    className="coder-btn coder-btn-xs"
                    aria-label="Model"
                    title="Which model answers the next message"
                    value={s.model}
                    onChange={e => s.setModel(e.target.value)}
                  >
                    {s.models.map(m => (
                      <option key={m.id} value={m.id}>
                        {m.label}{m.is_default ? ' · default' : ''}
                      </option>
                    ))}
                  </select>
                )}
                {s.modes.length > 0 && (
                  <select
                    className="coder-btn coder-btn-xs"
                    aria-label="Mode"
                    title={s.modes.find(m => m.id === s.mode)?.description || 'How much the coder may do on its own'}
                    value={s.mode}
                    onChange={e => s.setMode(e.target.value)}
                  >
                    {s.modes.map(m => (
                      <option key={m.id} value={m.id} title={m.description}>{m.label}</option>
                    ))}
                  </select>
                )}
                <span className="coder-spacer" />
                {/* Stop stays beside Send while a turn runs, rather than
                    replacing it — the whole point is being able to type the
                    next instruction without waiting. */}
                {s.streaming && (
                  <button type="button" className="coder-btn coder-btn-danger" onClick={() => void s.stop()}>Stop</button>
                )}
                <button
                  type="button"
                  className="coder-btn coder-btn-primary"
                  disabled={!draft.trim() || !canSend}
                  onClick={send}
                >{s.streaming ? 'Queue' : 'Send'}</button>
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
  return (
    <div className={`coder-msg coder-msg-${e.kind}`}>
      {e.kind === 'assistant' && e.model && (
        <div style={{ fontSize: 10, opacity: 0.6, marginBottom: 3, letterSpacing: '0.04em' }}>
          {e.model}{e.mode && e.mode !== 'auto' ? ` · ${e.mode === 'edits' ? 'Edits only' : e.mode === 'plan' ? 'Plan' : e.mode}` : ''}
        </div>
      )}
      {e.text}
      {e.files && e.files.length > 0 && (
        <div className="coder-attachments coder-attachments-sent">
          {e.files.map((f, i) => (
            f.preview
              ? <img key={i} className="coder-attachment-thumb" src={f.preview} alt={f.name} title={f.name} />
              : <span key={i} className="coder-attachment-chip" title={f.name}>{f.is_image ? 'Image' : 'File'} · {f.name}</span>
          ))}
        </div>
      )}
    </div>
  )
}


/**
 * Resume can take a while and must say so. It recreates the container, and the
 * first time after an upgrade it rebuilds the agent image before that. The
 * elapsed counter is the point: a number that keeps moving is the difference
 * between "working" and "broken" when nothing else on screen changes.
 */
function ResumeProgress({ since }: { since: number }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  const secs = Math.max(0, Math.round((now - since) / 1000))
  return (
    <div className="coder-paused coder-resuming" role="status" aria-live="polite">
      <span className="coder-resuming-line">
        <i className="coder-dot" /> Resuming — starting a fresh container… <b>{secs}s</b>
      </span>
      {secs >= 15 && (
        <span className="coder-resuming-note">
          Still going. The first resume after an AppCrane upgrade rebuilds the agent image, which can take a
          couple of minutes. If it fails you'll see why here.
        </span>
      )}
    </div>
  )
}

function modeLabel(modes: { id: string; label: string }[], id: string) {
  return modes.find(m => m.id === id)?.label || id
}

const MAX_FILE_BYTES = 10 * 1024 * 1024
const MAX_FILES = 10

function AttachmentChip({ file, onRemove }: { file: File; onRemove: () => void }) {
  const isImage = file.type.startsWith('image/')
  const [url, setUrl] = useState<string | null>(null)
  // data: URL — the admin CSP blocks blob: images.
  useEffect(() => {
    if (!isImage) return
    let live = true
    fileToDataUrl(file).then(u => { if (live) setUrl(u) }).catch(() => {})
    return () => { live = false }
  }, [file, isImage])
  return (
    <span className="coder-attachment-chip" title={file.name}>
      {url && <img className="coder-attachment-thumb" src={url} alt="" />}
      <span className="coder-attachment-name">{file.name}</span>
      <button type="button" className="coder-attachment-remove" onClick={onRemove} aria-label={`Remove ${file.name}`}>×</button>
    </span>
  )
}

function fileCount(raw?: string | null) {
  if (!raw) return 0
  try { return (JSON.parse(raw) as unknown[]).length } catch { return 0 }
}
