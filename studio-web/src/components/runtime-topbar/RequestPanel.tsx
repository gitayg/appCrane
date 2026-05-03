import { useEffect, useState } from 'react'
import { useMe, isAdmin } from '../../hooks/useMe'
import { usePlanFlow } from '../../hooks/usePlanFlow'
import { usePeek, PeekChip, peekToPromptPrefix } from '../../hooks/usePeek'

interface Props {
  slug:    string | null | undefined
  appName: string
  open:    boolean
  onClose: () => void
  width?:  number
  iframeRef?: React.RefObject<HTMLIFrameElement | null>
}

/**
 * Right drawer for "Request" — file an enhancement request, watch the
 * planner stream the plan inline, then click Build to confirm. Mirrors
 * the portal's planPanel UX (sendPlanRequest → _streamPlan → buildFromPlan).
 *
 * Pick-element (🎯) injects a hover/click overlay into the embedded
 * iframe and captures CSS-selector + text context to prepend to the
 * prompt. Same-origin only (AppCrane apps live under the same host).
 */
export function RequestPanel({ slug, appName, open, onClose, width = 420, iframeRef }: Props) {
  const me = useMe()
  const canBuild = isAdmin(me)
  const [text, setText] = useState('')
  const plan = usePlanFlow(slug)
  const peek = usePeek(iframeRef ?? { current: null })

  useEffect(() => {
    if (!open) { setText(''); peek.stop(); peek.clear(); plan.reset() }
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!open) return null

  function onSubmit() {
    if (!text.trim() || plan.state.busy) return
    const prefix = peek.ctx ? peekToPromptPrefix(peek.ctx) : ''
    // After a plan is ready and BEFORE Build is clicked, Send refines
    // the same enhancement instead of creating a new one. After Build
    // (or if no plan exists yet), Send creates a fresh request.
    if (plan.state.planReady && !plan.state.built) {
      plan.refine(prefix + text.trim())
    } else {
      plan.submit(prefix + text.trim())
    }
    setText('')
    peek.clear()
  }

  const w = plan.state.working

  return (
    <div className="ask-panel open" style={{ width }}>
      <div className="ask-header">
        <span>💡 Request</span>
        <span className="ask-app-label">{appName}</span>
        <div className="ask-header-right">
          <button
            type="button"
            className={'ask-sessions-btn' + (peek.active ? ' active' : '')}
            onClick={() => peek.toggle()}
            title="Point at an element in the app to add it as context"
          >🎯</button>
          <button type="button" className="ask-close" onClick={onClose}>×</button>
        </div>
      </div>

      <div className="ask-messages">
        {!plan.state.busy && !plan.state.planReady && !plan.state.error && (
          <div className="ask-empty">
            Describe an enhancement or feature you want for this app. AppCrane
            will plan it, then you can click <strong>Build</strong> to generate
            the code and open a PR.
          </div>
        )}

        {(plan.state.busy || w.elapsedSec > 0) && (
          <div className="ask-msg assistant plan-working">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '.82rem' }}>
              <span className="az-spinner" />
              <span>{w.text || 'Working…'}</span>
              {w.elapsedSec > 0 && <span style={{ color: 'var(--dim)', marginLeft: 'auto' }}>{w.elapsedSec}s</span>}
            </div>
            {plan.state.activity.length > 0 && (
              <ul className="plan-activity">
                {plan.state.activity.slice(-8).map((line, i) => (
                  <li key={`${plan.state.activity.length - 8 + i}-${line}`}>{line}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        {plan.state.planText && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%' }}>
            <div style={{ fontWeight: 600, fontSize: '.78rem', color: 'var(--dim)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.5px' }}>
              Plan #{plan.state.enhId}
            </div>
            <pre style={{ whiteSpace: 'pre-wrap', margin: 0, fontFamily: 'inherit', fontSize: '.85rem', lineHeight: 1.45 }}>{plan.state.planText}</pre>
          </div>
        )}

        {plan.state.error && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%', borderColor: '#ef4444' }}>
            ⚠️ {plan.state.error}
          </div>
        )}

        {plan.state.built && !plan.state.error && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%' }}>
            ✅ Build queued — track progress in the 📋 Jobs panel.
          </div>
        )}
      </div>

      <div className="ask-input-area">
        {peek.ctx && <PeekChip ctx={peek.ctx} onClear={peek.clear} />}
        {plan.state.planReady && canBuild && !plan.state.built && (
          <div className="ask-input-row" style={{ justifyContent: 'flex-end', padding: '0 0 6px' }}>
            <button
              type="button"
              className="ask-send plan-build-btn"
              onClick={() => plan.build()}
              disabled={plan.state.built}
            >🔨 Build</button>
          </div>
        )}
        <div className="ask-input-row">
          <textarea
            className="ask-textarea"
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSubmit() }
            }}
            placeholder={plan.state.planReady ? 'Refine the plan or describe a new request…' : 'Describe the enhancement or feature you want…'}
            rows={3}
            disabled={plan.state.busy}
          />
          <button
            type="button"
            className="ask-send"
            onClick={onSubmit}
            disabled={plan.state.busy || !text.trim()}
            title={
              plan.state.planReady && !plan.state.built
                ? 'Send refinement — Claude will re-plan with this feedback'
                : canBuild
                  ? 'Plan first — review the proposal, then Build.'
                  : 'Submit for review by an admin'
            }
          >{
            plan.state.busy ? '…'
            : plan.state.planReady && !plan.state.built ? '🔁 Refine'
            : canBuild ? '📋 Plan'
            : '📤 Submit'
          }</button>
        </div>
      </div>
    </div>
  )
}
