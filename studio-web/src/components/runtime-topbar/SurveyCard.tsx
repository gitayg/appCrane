import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'

// A small survey card over the app's corner (GET /api/surveys/pending). It never
// takes keyboard focus: the app keeps whatever the person was doing, and the
// card is reached with Tab or the mouse like any other control. "Not now" and
// the close button snooze it server-side; an answer is stored once per round.

export interface SurveyQuestion {
  id: number
  kind: 'nps' | 'scale' | 'choice' | 'text'
  prompt: string
  required: boolean
  scale_min: number | null
  scale_max: number | null
  low_label: string | null
  high_label: string | null
  options: string[] | null
  max_length: number | null
}

export interface PendingSurvey {
  id: number
  name: string
  questions: SurveyQuestion[]
}

interface Props {
  slug: string | null | undefined
  appName?: string
}

type Value = number | string
type Phase = 'idle' | 'open' | 'sending' | 'thanks' | 'gone'

const STYLES = `
.crane-survey {
  position: fixed; right: 16px; bottom: 16px; z-index: 940;
  width: min(360px, calc(100vw - 32px)); max-height: calc(100vh - 96px); overflow: auto;
  box-sizing: border-box; padding: 14px 16px 12px;
  background: var(--surface, #1f2230); color: var(--text, #e4e4e7);
  border: 1px solid var(--border, #2a2d3a); border-radius: 8px;
  box-shadow: 0 10px 30px rgba(0,0,0,.35);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; font-size: .84rem;
}
@media (prefers-reduced-motion: no-preference) {
  .crane-survey { animation: crane-survey-in .18s ease-out; }
  @keyframes crane-survey-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
}
.crane-survey-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
.crane-survey-title { font-weight: 600; font-size: .8rem; color: var(--dim, #a1a1aa); }
.crane-survey-x { background: transparent; border: 0; color: var(--dim, #a1a1aa); cursor: pointer; font-size: 1.1rem; line-height: 1; padding: 2px 6px; border-radius: 4px; }
.crane-survey-q { margin: 0 0 12px; border: 0; padding: 0; min-width: 0; }
.crane-survey-q legend, .crane-survey-q label.crane-survey-prompt { display: block; padding: 0; margin: 0 0 6px; font-weight: 500; line-height: 1.35; }
.crane-survey-scale { display: flex; flex-wrap: wrap; gap: 4px; }
.crane-survey-scale button, .crane-survey-choice button {
  min-width: 26px; padding: 4px 6px; border-radius: 4px; cursor: pointer; font: inherit; font-size: .78rem;
  background: var(--surface2, #2a2d3a); color: var(--text, #e4e4e7); border: 1px solid var(--border, #2a2d3a);
}
.crane-survey-choice { display: flex; flex-wrap: wrap; gap: 6px; }
.crane-survey-choice button { padding: 4px 10px; }
.crane-survey-scale button[aria-pressed="true"], .crane-survey-choice button[aria-pressed="true"] {
  background: var(--accent, #3b82f6); border-color: var(--accent, #3b82f6); color: #fff;
}
.crane-survey-ends { display: flex; justify-content: space-between; margin-top: 3px; font-size: .7rem; color: var(--dim, #a1a1aa); }
.crane-survey textarea {
  width: 100%; box-sizing: border-box; min-height: 56px; resize: vertical; font: inherit; font-size: .8rem;
  background: var(--surface2, #2a2d3a); color: var(--text, #e4e4e7); border: 1px solid var(--border, #2a2d3a); border-radius: 4px; padding: 6px;
}
.crane-survey-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px; }
.crane-survey-actions button { font: inherit; font-size: .78rem; border-radius: 5px; padding: 5px 12px; cursor: pointer; }
.crane-survey-later { background: transparent; color: var(--dim, #a1a1aa); border: 1px solid var(--border, #2a2d3a); }
.crane-survey-send { background: var(--accent, #3b82f6); color: #fff; border: 1px solid var(--accent, #3b82f6); }
.crane-survey-send:disabled { opacity: .5; cursor: default; }
.crane-survey-err { color: #fca5a5; font-size: .76rem; margin: 0 0 8px; }
.crane-survey button:focus-visible, .crane-survey textarea:focus-visible { outline: 2px solid var(--accent, #3b82f6); outline-offset: 1px; }
.crane-survey-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
`

function range(min: number, max: number): number[] {
  const out: number[] = []
  for (let i = min; i <= max; i++) out.push(i)
  return out
}

function missingRequired(questions: SurveyQuestion[], values: Record<number, Value>): boolean {
  return questions.some(q => q.required && (values[q.id] === undefined || values[q.id] === ''))
}

export function SurveyCard({ slug, appName }: Props) {
  const [survey, setSurvey] = useState<PendingSurvey | null>(null)
  const [values, setValues] = useState<Record<number, Value>>({})
  const [phase, setPhase] = useState<Phase>('idle')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setSurvey(null); setValues({}); setPhase('idle'); setError(null)
    if (!slug) return
    let alive = true
    adminApi.get<{ survey: PendingSurvey | null }>(`/api/surveys/pending?app=${encodeURIComponent(slug)}`)
      .then(r => { if (alive && r.survey) { setSurvey(r.survey); setPhase('open') } })
      .catch(() => {})
    return () => { alive = false }
  }, [slug])

  useEffect(() => {
    if (phase !== 'thanks') return
    const t = setTimeout(() => setPhase('gone'), 2500)
    return () => clearTimeout(t)
  }, [phase])

  if (!slug || !survey || phase === 'idle' || phase === 'gone') return null

  const set = (id: number, v: Value) => setValues(prev => ({ ...prev, [id]: v }))

  async function later() {
    setPhase('gone')
    try { await adminApi.post(`/api/surveys/${survey!.id}/snooze`, { app: slug }) } catch { /* shown again next visit */ }
  }

  async function send() {
    if (!survey || phase === 'sending') return
    setPhase('sending'); setError(null)
    const answers: Record<string, Value> = {}
    for (const q of survey.questions) {
      const v = values[q.id]
      if (v === undefined) continue
      if (typeof v === 'string' && !v.trim()) continue
      answers[String(q.id)] = v
    }
    try {
      await adminApi.post(`/api/surveys/${survey.id}/responses`, { app: slug, answers })
      setPhase('thanks')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not send your answer')
      setPhase('open')
    }
  }

  const label = survey.name || `${appName || 'App'} survey`

  return (
    <section className="crane-survey" role="region" aria-label={label}>
      <style>{STYLES}</style>
      <div className="crane-survey-head">
        <span className="crane-survey-title">{label}</span>
        <button type="button" className="crane-survey-x" onClick={later} aria-label="Close survey and ask me later" title="Not now">×</button>
      </div>
      {phase === 'thanks' ? (
        <p role="status" style={{ margin: '4px 0 6px' }}>Thanks, your answer was sent to the app's owners.</p>
      ) : (
        <form onSubmit={e => { e.preventDefault(); void send() }}>
          {survey.questions.map(q => <Question key={q.id} q={q} value={values[q.id]} onChange={v => set(q.id, v)} />)}
          {error && <p className="crane-survey-err" role="alert">{error}</p>}
          <div className="crane-survey-actions">
            <button type="button" className="crane-survey-later" onClick={later}>Not now</button>
            <button type="submit" className="crane-survey-send" disabled={phase === 'sending' || missingRequired(survey.questions, values)}>
              {phase === 'sending' ? 'Sending…' : 'Send'}
            </button>
          </div>
        </form>
      )}
    </section>
  )
}

function Question({ q, value, onChange }: { q: SurveyQuestion; value: Value | undefined; onChange: (v: Value) => void }) {
  const req = q.required ? '' : ' (optional)'
  if (q.kind === 'text') {
    const id = `crane-survey-q-${q.id}`
    return (
      <div className="crane-survey-q">
        <label className="crane-survey-prompt" htmlFor={id}>{q.prompt}{req}</label>
        <textarea id={id} maxLength={q.max_length ?? 1000} value={typeof value === 'string' ? value : ''} onChange={e => onChange(e.target.value)} />
      </div>
    )
  }
  if (q.kind === 'choice') {
    return (
      <fieldset className="crane-survey-q">
        <legend>{q.prompt}{req}</legend>
        <div className="crane-survey-choice">
          {(q.options ?? []).map(o => (
            <button key={o} type="button" aria-pressed={value === o} onClick={() => onChange(o)}>{o}</button>
          ))}
        </div>
      </fieldset>
    )
  }
  const min = q.scale_min ?? 0
  const max = q.scale_max ?? 10
  return (
    <fieldset className="crane-survey-q">
      <legend>{q.prompt}{req}</legend>
      <div className="crane-survey-scale">
        {range(min, max).map(n => (
          <button key={n} type="button" aria-pressed={value === n} onClick={() => onChange(n)}>
            {n}<span className="crane-survey-sr">{n === min && q.low_label ? `, ${q.low_label}` : n === max && q.high_label ? `, ${q.high_label}` : ''}</span>
          </button>
        ))}
      </div>
      {(q.low_label || q.high_label) && (
        <div className="crane-survey-ends" aria-hidden="true"><span>{q.low_label}</span><span>{q.high_label}</span></div>
      )}
    </fieldset>
  )
}
