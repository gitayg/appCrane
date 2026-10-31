import { useState } from 'react'
import { Link } from 'react-router-dom'
import { type CoderRequest } from './api'
import { MAX_CODER_BATCH } from './SendToCoderBar'
import { isOpenRequest } from './useCoderRequests'

interface Props {
  requests:     CoderRequest[] | null
  loadError:    string | null
  showClosed:   boolean
  onShowClosed: (v: boolean) => void
  /** Why the picked requests cannot go to the coder right now, or null. */
  blockedReason: string | null
  /** No session on screen: sending starts one. */
  startsSession: boolean
  /** The session on screen, to mark requests already sent to it. */
  sessionId:    string | null
  /** Sends the picked ids, in order; resolves to the ids sent, or throws the refusal. */
  onSend:       (ids: number[]) => Promise<number[]>
  /** Puts `#id` into the message box. */
  onMention:    (id: number) => void
  onSent:       () => void
}

const BUCKET_LABEL: Record<CoderRequest['bucket'], string> = {
  triage: 'New', in_progress: 'In progress', shipped: 'Shipped', validated: 'Validated',
}

function shortDate(s: string) {
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s.replace(' ', 'T')}Z`)
  return Number.isNaN(d.getTime()) ? s : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

/**
 * The app's requests, beside the coder chat: pick some and send them to the
 * coder (fenced as request text, never pasted in as yours), or mention one in
 * your own message ("do #123 but use blue").
 */
export function CoderRequests(props: Props) {
  const { requests, blockedReason } = props
  const [picked, setPicked] = useState<number[]>([])
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState<number[]>([])

  const toggle = (id: number) => {
    setError(null)
    setPicked(p => (p.includes(id) ? p.filter(x => x !== id) : p.length >= MAX_CODER_BATCH ? p : [...p, id]))
  }

  async function send() {
    if (!picked.length || blockedReason) return
    setSending(true)
    setError(null)
    try {
      const ids = await props.onSend(picked)
      setSent(ids)
      setPicked([])
      props.onSent()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSending(false)
    }
  }

  const n = picked.length
  return (
    <section className="coder-reqs" aria-label="This app's requests">
      <div className="coder-reqs-head">
        <span>Requests</span>
        <label className="coder-reqs-filter">
          <input type="checkbox" checked={props.showClosed} onChange={e => props.onShowClosed(e.target.checked)} />
          Show shipped
        </label>
      </div>

      <div className="coder-reqs-list">
        {props.loadError && <div className="coder-error">Couldn't load the requests: {props.loadError}</div>}
        {!requests && !props.loadError && <div className="coder-note">Loading requests…</div>}
        {requests && requests.length === 0 && (
          <div className="coder-note">No open requests for this app.</div>
        )}
        {requests?.map(r => {
          const open = isOpenRequest(r)
          const order = picked.indexOf(r.id)
          const full = order < 0 && n >= MAX_CODER_BATCH
          const inThisSession = !!props.sessionId && r.coder_session_id === props.sessionId
          return (
            <div key={r.id} className={'coder-req' + (order >= 0 ? ' picked' : '')}>
              <input
                type="checkbox"
                aria-label={`Pick request #${r.id}`}
                checked={order >= 0}
                disabled={!open || full || sending}
                title={!open ? 'Already shipped' : full ? `At most ${MAX_CODER_BATCH} at once` : 'Pick to send to the coder'}
                onChange={() => toggle(r.id)}
              />
              <div className="coder-req-main">
                <div className="coder-req-meta">
                  {order >= 0 && <span className="coder-req-order">{order + 1}</span>}
                  <Link to={`/requests/${r.id}`} target="_blank" rel="noopener" title="Open the full request in a new tab">#{r.id}</Link>
                  <span className={`coder-req-bucket coder-req-bucket-${r.bucket}`}>{BUCKET_LABEL[r.bucket]}</span>
                  {r.kind === 'vulnerability' && <span className="coder-req-kind">Dependency scan</span>}
                  {sent.includes(r.id) ? <span className="coder-req-sent">Sent</span>
                    : inThisSession ? <span className="coder-req-sent">In this session</span> : null}
                  <span className="coder-req-by">{r.user_name || 'Unknown'} · {shortDate(r.created_at)}</span>
                </div>
                <div className="coder-req-text">{r.excerpt}{r.truncated ? '…' : ''}</div>
              </div>
              <button
                type="button"
                className="coder-btn coder-btn-xs"
                disabled={!open}
                title={open ? `Put #${r.id} in your message. The coder gets the request's text with it.` : 'Already shipped'}
                onClick={() => props.onMention(r.id)}
              >Mention</button>
            </div>
          )
        })}
      </div>

      <div className="coder-reqs-foot">
        {sent.length > 0 && n === 0 && !error && (
          <div className="coder-reqs-done" role="status">Sent {sent.map(i => `#${i}`).join(', ')} to the coder.</div>
        )}
        {error && <div className="coder-error">{error}</div>}
        {n > 0 && blockedReason && <div className="coder-note" role="status">{blockedReason}</div>}
        <div className="coder-composer-row">
          <span className="coder-note">
            {n === 0
              ? `Pick up to ${MAX_CODER_BATCH}.`
              : `${n} picked${n > 1 ? ', worked in the order you picked them' : ''}.`}
          </span>
          <span className="coder-spacer" />
          {n > 0 && <button type="button" className="coder-btn coder-btn-xs" disabled={sending} onClick={() => setPicked([])}>Clear</button>}
          <button
            type="button"
            className="coder-btn coder-btn-xs coder-btn-primary"
            disabled={n === 0 || sending || !!blockedReason}
            title={blockedReason || undefined}
            onClick={() => void send()}
          >{sending ? 'Sending…' : props.startsSession ? 'Start a session and send' : 'Send to coder'}</button>
        </div>
      </div>
    </section>
  )
}
