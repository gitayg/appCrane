import { useEffect, useState } from 'react'
import { useEnhancementSubmit } from '../../hooks/useEnhancementSubmit'

interface Props {
  slug:    string | null | undefined
  appName: string
  open:    boolean
  onClose: () => void
  width?:  number
}

/**
 * Right drawer for "Report a bug" — same backend path as Request, but the
 * form prompts for what specifically went wrong. The submitted message is
 * wrapped with a [BUG] header + structured fields so the planner agent
 * has the context it needs and the AppStudio triage list can spot it.
 *
 * Uses the existing useEnhancementSubmit hook — no new server endpoint.
 * Bugs flow through the same Plan → Code → Build → Open PR pipeline.
 */
export function BugPanel({ slug, appName, open, onClose, width = 460 }: Props) {
  const { submit, busy, last, reset } = useEnhancementSubmit(slug)
  const [what, setWhat]       = useState('')
  const [steps, setSteps]     = useState('')
  const [expected, setExpected] = useState('')

  useEffect(() => {
    if (!open) { setWhat(''); setSteps(''); setExpected(''); reset() }
  }, [open, reset])

  if (!open) return null

  const empty = !what.trim()

  async function onSubmit() {
    if (empty || busy) return
    const lines = [
      '[BUG]',
      what.trim(),
    ]
    if (steps.trim())    lines.push('', '## Steps to reproduce', steps.trim())
    if (expected.trim()) lines.push('', '## Expected behavior', expected.trim())
    const r = await submit(lines.join('\n'))
    if (r.ok) { setWhat(''); setSteps(''); setExpected('') }
  }

  return (
    <div className="ask-panel open" style={{ width }}>
      <div className="ask-header">
        <span>🐛 Report bug</span>
        <span className="ask-app-label">{appName}</span>
        <div className="ask-header-right">
          <button type="button" className="ask-close" onClick={onClose}>×</button>
        </div>
      </div>

      <div className="ask-messages" style={{ display: 'block', padding: '14px 16px' }}>
        <div className="ask-empty" style={{ marginTop: 0, textAlign: 'left', marginBottom: 14 }}>
          Found something broken? Describe what went wrong. AppCrane will plan a
          fix, generate the code, and open a PR — same pipeline as feature
          requests; track it in the 📋 Jobs panel.
        </div>

        {last && last.ok && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%', marginBottom: 12 }}>
            ✅ Bug report {last.enhancementId ? `#${last.enhancementId} ` : ''}submitted.
            <div style={{ fontSize: '.78rem', color: 'var(--dim)', marginTop: 6 }}>
              Track its progress in the 📋 Jobs panel.
            </div>
          </div>
        )}
        {last && !last.ok && last.message && (
          <div className="ask-msg assistant" style={{ alignSelf: 'stretch', maxWidth: '100%', borderColor: '#ef4444', marginBottom: 12 }}>
            ⚠️ {last.message}
          </div>
        )}

        <label style={fieldLabel}>What went wrong? <span style={req}>required</span></label>
        <textarea
          className="ask-textarea" rows={3}
          value={what} onChange={e => setWhat(e.target.value)}
          placeholder="Briefly describe the bug — what you saw vs what you expected"
          disabled={busy}
          style={{ width: '100%', marginBottom: 10 }}
        />

        <label style={fieldLabel}>Steps to reproduce <span style={opt}>optional</span></label>
        <textarea
          className="ask-textarea" rows={3}
          value={steps} onChange={e => setSteps(e.target.value)}
          placeholder="1. Go to …&#10;2. Click …&#10;3. Observe …"
          disabled={busy}
          style={{ width: '100%', marginBottom: 10 }}
        />

        <label style={fieldLabel}>Expected behavior <span style={opt}>optional</span></label>
        <textarea
          className="ask-textarea" rows={2}
          value={expected} onChange={e => setExpected(e.target.value)}
          placeholder="What should have happened instead?"
          disabled={busy}
          style={{ width: '100%', marginBottom: 10 }}
        />
      </div>

      <div className="ask-input-area">
        <div className="ask-input-row" style={{ justifyContent: 'flex-end' }}>
          <button
            type="button"
            className="ask-send"
            onClick={onSubmit}
            disabled={busy || empty}
          >{busy ? 'Submitting…' : '🐛 Report bug'}</button>
        </div>
      </div>
    </div>
  )
}

const fieldLabel: React.CSSProperties = {
  display: 'block', fontSize: '.78rem', fontWeight: 600,
  color: 'var(--dim)', marginBottom: 4,
}
const req: React.CSSProperties = { color: '#ef4444', fontWeight: 500, marginLeft: 4, fontSize: '.7rem' }
const opt: React.CSSProperties = { color: 'var(--dim)', fontWeight: 400, marginLeft: 4, fontSize: '.7rem', fontStyle: 'italic' }
