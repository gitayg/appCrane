import { useCallback, useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import type { SurveyQuestion } from '../runtime-topbar/SurveyCard'

// Platform admins define the surveys the app top bar shows (/api/surveys/admin):
// the questions, the apps, how often one person is asked, and on/off.

export interface SurveyDef {
  id: number
  name: string
  enabled: boolean
  all_apps: boolean
  apps: { slug: string; name: string }[]
  frequency_days: number
  min_visits: number
  min_days: number
  snooze_days: number
  responses: number
  questions: SurveyQuestion[]
}

type Kind = SurveyQuestion['kind']

interface DraftQuestion {
  kind: Kind
  prompt: string
  required: boolean
  scale_min: number
  scale_max: number
  low_label: string
  high_label: string
  options: string
  max_length: number
}

interface Draft {
  id: number | null
  name: string
  enabled: boolean
  all_apps: boolean
  apps: string[]
  frequency_days: number
  min_visits: number
  min_days: number
  snooze_days: number
  questions: DraftQuestion[]
}

const DEFAULT_NPS = 'How likely are you to recommend {app} to a colleague?'

function newQuestion(kind: Kind): DraftQuestion {
  return {
    kind,
    prompt: kind === 'nps' ? DEFAULT_NPS : '',
    required: kind === 'nps',
    scale_min: 1, scale_max: 5,
    low_label: kind === 'nps' ? 'Not likely' : '',
    high_label: kind === 'nps' ? 'Very likely' : '',
    options: '',
    max_length: 1000,
  }
}

const EMPTY: Draft = {
  id: null, name: 'NPS', enabled: false, all_apps: true, apps: [],
  frequency_days: 90, min_visits: 3, min_days: 0, snooze_days: 7,
  questions: [newQuestion('nps'), { ...newQuestion('text'), prompt: 'What is the main reason for your score?' }],
}

function toDraft(s: SurveyDef): Draft {
  return {
    id: s.id, name: s.name, enabled: s.enabled, all_apps: s.all_apps, apps: s.apps.map(a => a.slug),
    frequency_days: s.frequency_days, min_visits: s.min_visits, min_days: s.min_days, snooze_days: s.snooze_days,
    questions: s.questions.map(q => ({
      kind: q.kind, prompt: q.prompt, required: q.required,
      scale_min: q.scale_min ?? 1, scale_max: q.scale_max ?? 5,
      low_label: q.low_label ?? '', high_label: q.high_label ?? '',
      options: (q.options ?? []).join('\n'), max_length: q.max_length ?? 1000,
    })),
  }
}

function toBody(d: Draft) {
  return {
    name: d.name, enabled: d.enabled, all_apps: d.all_apps, apps: d.apps,
    frequency_days: d.frequency_days, min_visits: d.min_visits, min_days: d.min_days, snooze_days: d.snooze_days,
    questions: d.questions.map(q => {
      const base = { kind: q.kind, prompt: q.prompt, required: q.required }
      if (q.kind === 'nps') return { ...base, low_label: q.low_label, high_label: q.high_label }
      if (q.kind === 'scale') return { ...base, scale_min: q.scale_min, scale_max: q.scale_max, low_label: q.low_label, high_label: q.high_label }
      if (q.kind === 'choice') return { ...base, options: q.options.split('\n').map(o => o.trim()).filter(Boolean) }
      return { ...base, max_length: q.max_length }
    }),
  }
}

const KIND_LABEL: Record<Kind, string> = { nps: 'NPS (0-10)', scale: 'Score', choice: 'Single choice', text: 'Free text' }

function describe(s: SurveyDef): string {
  const where = s.all_apps ? 'all apps' : s.apps.map(a => a.name).join(', ')
  const again = s.frequency_days === 0 ? 'asked once' : `asked again after ${s.frequency_days} days`
  return `${where} · after ${s.min_visits} visits${s.min_days ? ` and ${s.min_days} days` : ''} · ${again} · "Not now" waits ${s.snooze_days} days`
}

export function SurveyAdmin() {
  const [surveys, setSurveys] = useState<SurveyDef[]>([])
  const [apps, setApps] = useState<{ slug: string; name: string }[]>([])
  const [draft, setDraft] = useState<Draft | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    adminApi.get<{ surveys: SurveyDef[] }>('/api/surveys/admin')
      .then(r => { setSurveys(r.surveys); setError(null) })
      .catch(e => setError(e instanceof Error ? e.message : 'Could not load surveys'))
  }, [])

  useEffect(() => {
    load()
    adminApi.get<{ apps: { slug: string; name: string }[] }>('/api/apps')
      .then(r => setApps((r.apps || []).map(a => ({ slug: a.slug, name: a.name })).sort((a, b) => a.name.localeCompare(b.name))))
      .catch(() => setApps([]))
  }, [load])

  async function save() {
    if (!draft) return
    setBusy(true); setError(null)
    try {
      if (draft.id) await adminApi.put(`/api/surveys/admin/${draft.id}`, toBody(draft))
      else await adminApi.post('/api/surveys/admin', toBody(draft))
      setDraft(null)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the survey')
    } finally { setBusy(false) }
  }

  async function remove(s: SurveyDef) {
    if (!confirm(`Delete "${s.name}" and its ${s.responses} answers?`)) return
    try { await adminApi.del(`/api/surveys/admin/${s.id}`); load() } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not delete the survey')
    }
  }

  async function toggle(s: SurveyDef) {
    try {
      await adminApi.put(`/api/surveys/admin/${s.id}`, toBody({ ...toDraft(s), enabled: !s.enabled }))
      load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not change the survey') }
  }

  const patch = (p: Partial<Draft>) => setDraft(d => (d ? { ...d, ...p } : d))
  const patchQ = (i: number, p: Partial<DraftQuestion>) =>
    setDraft(d => (d ? { ...d, questions: d.questions.map((q, j) => (j === i ? { ...q, ...p } : q)) } : d))
  const moveQ = (i: number, by: number) => setDraft(d => {
    if (!d) return d
    const qs = [...d.questions]
    const j = i + by
    if (j < 0 || j >= qs.length) return d
    ;[qs[i], qs[j]] = [qs[j], qs[i]]
    return { ...d, questions: qs }
  })
  const num = (v: string) => (v === '' ? 0 : Math.max(0, Math.floor(Number(v)) || 0))

  return (
    <div>
      <p style={{ color: 'var(--dim)', marginTop: 0 }}>
        Surveys appear as a small card in the app's AppCrane top bar for signed-in people on Production.
        Every answer is e-mailed to the app's owners and the platform admins. Use <code>{'{app}'}</code> in a question for the app's name.
      </p>
      {error && <div role="alert" style={{ padding: '8px 12px', borderRadius: 6, marginBottom: 12, border: '1px solid var(--red)', color: 'var(--red)' }}>{error}</div>}

      {!draft && (
        <>
          <div style={{ marginBottom: 12 }}>
            <button className="btn btn-accent" onClick={() => setDraft({ ...EMPTY, questions: EMPTY.questions.map(q => ({ ...q })) })}>New survey</button>
          </div>
          {surveys.length === 0 && <p style={{ color: 'var(--dim)' }}>No surveys yet.</p>}
          {surveys.map(s => (
            <div key={s.id} className="am-card" style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <strong>{s.name}</strong>
                <span className={'badge ' + (s.enabled ? 'badge-live' : '')}>{s.enabled ? 'On' : 'Off'}</span>
                <span style={{ color: 'var(--dim)', fontSize: '.8rem' }}>{s.questions.length} questions · {s.responses} answers</span>
                <span style={{ flex: 1 }} />
                <button className="btn btn-xs" onClick={() => toggle(s)}>{s.enabled ? 'Turn off' : 'Turn on'}</button>
                <button className="btn btn-xs" onClick={() => setDraft(toDraft(s))}>Edit</button>
                <button className="btn btn-xs btn-red" onClick={() => remove(s)}>Delete</button>
              </div>
              <div style={{ color: 'var(--dim)', fontSize: '.8rem', marginTop: 6 }}>{describe(s)}</div>
            </div>
          ))}
        </>
      )}

      {draft && (
        <form className="am-card" onSubmit={e => { e.preventDefault(); void save() }} style={{ display: 'grid', gap: 12 }}>
          <label>Name<br />
            <input value={draft.name} maxLength={120} onChange={e => patch({ name: e.target.value })} style={{ width: '100%', maxWidth: 360 }} />
          </label>
          <label><input type="checkbox" checked={draft.enabled} onChange={e => patch({ enabled: e.target.checked })} /> On (shown to people when due)</label>

          <fieldset style={{ border: '1px solid var(--border)', borderRadius: 6, padding: 10 }}>
            <legend>Apps</legend>
            <label><input type="radio" checked={draft.all_apps} onChange={() => patch({ all_apps: true })} /> All apps</label>{' '}
            <label><input type="radio" checked={!draft.all_apps} onChange={() => patch({ all_apps: false })} /> Chosen apps</label>
            {!draft.all_apps && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 14px', marginTop: 8, maxHeight: 180, overflow: 'auto' }}>
                {apps.map(a => (
                  <label key={a.slug} style={{ fontSize: '.85rem' }}>
                    <input type="checkbox" checked={draft.apps.includes(a.slug)}
                      onChange={e => patch({ apps: e.target.checked ? [...draft.apps, a.slug] : draft.apps.filter(x => x !== a.slug) })} /> {a.name}
                  </label>
                ))}
              </div>
            )}
          </fieldset>

          <fieldset style={{ border: '1px solid var(--border)', borderRadius: 6, padding: 10, display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
            <legend>How often</legend>
            <label>First ask after this many visits<br /><input type="number" min={0} max={1000} value={draft.min_visits} onChange={e => patch({ min_visits: num(e.target.value) })} /></label>
            <label>...and this many days after first use<br /><input type="number" min={0} max={3650} value={draft.min_days} onChange={e => patch({ min_days: num(e.target.value) })} /></label>
            <label>Ask again after (days, 0 = only once)<br /><input type="number" min={0} max={3650} value={draft.frequency_days} onChange={e => patch({ frequency_days: num(e.target.value) })} /></label>
            <label>"Not now" waits (days)<br /><input type="number" min={1} max={365} value={draft.snooze_days} onChange={e => patch({ snooze_days: Math.max(1, num(e.target.value)) })} /></label>
          </fieldset>

          <fieldset style={{ border: '1px solid var(--border)', borderRadius: 6, padding: 10, display: 'grid', gap: 10 }}>
            <legend>Questions</legend>
            {draft.questions.map((q, i) => (
              <div key={i} style={{ borderBottom: '1px solid var(--border)', paddingBottom: 10, display: 'grid', gap: 6 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: '.8rem' }}>{i + 1}. {KIND_LABEL[q.kind]}</strong>
                  <label style={{ fontSize: '.8rem' }}><input type="checkbox" checked={q.required} onChange={e => patchQ(i, { required: e.target.checked })} /> Required</label>
                  <span style={{ flex: 1 }} />
                  <button type="button" className="btn btn-xs" onClick={() => moveQ(i, -1)} disabled={i === 0} aria-label="Move up">↑</button>
                  <button type="button" className="btn btn-xs" onClick={() => moveQ(i, 1)} disabled={i === draft.questions.length - 1} aria-label="Move down">↓</button>
                  <button type="button" className="btn btn-xs btn-red" onClick={() => patch({ questions: draft.questions.filter((_, j) => j !== i) })}>Remove</button>
                </div>
                <input value={q.prompt} maxLength={300} placeholder="Question" aria-label={`Question ${i + 1}`} onChange={e => patchQ(i, { prompt: e.target.value })} />
                {q.kind === 'scale' && (
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <label>From <select value={q.scale_min} onChange={e => patchQ(i, { scale_min: Number(e.target.value) })}><option value={0}>0</option><option value={1}>1</option></select></label>
                    <label>to <select value={q.scale_max} onChange={e => patchQ(i, { scale_max: Number(e.target.value) })}>
                      {[2, 3, 4, 5, 6, 7, 8, 9, 10].map(n => <option key={n} value={n}>{n}</option>)}
                    </select></label>
                  </div>
                )}
                {(q.kind === 'scale' || q.kind === 'nps') && (
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <input value={q.low_label} maxLength={60} placeholder="Low end label" aria-label="Low end label" onChange={e => patchQ(i, { low_label: e.target.value })} />
                    <input value={q.high_label} maxLength={60} placeholder="High end label" aria-label="High end label" onChange={e => patchQ(i, { high_label: e.target.value })} />
                  </div>
                )}
                {q.kind === 'choice' && (
                  <textarea rows={3} value={q.options} placeholder="One option per line (2 to 10)" aria-label="Options" onChange={e => patchQ(i, { options: e.target.value })} />
                )}
                {q.kind === 'text' && (
                  <label style={{ fontSize: '.8rem' }}>Longest answer (characters) <input type="number" min={1} max={2000} value={q.max_length} onChange={e => patchQ(i, { max_length: Math.min(2000, Math.max(1, num(e.target.value))) })} /></label>
                )}
              </div>
            ))}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {(['nps', 'scale', 'choice', 'text'] as Kind[]).map(k => (
                <button key={k} type="button" className="btn btn-xs"
                  disabled={draft.questions.length >= 10 || (k === 'nps' && draft.questions.some(q => q.kind === 'nps'))}
                  onClick={() => patch({ questions: [...draft.questions, newQuestion(k)] })}>+ {KIND_LABEL[k]}</button>
              ))}
            </div>
          </fieldset>

          <div style={{ display: 'flex', gap: 8 }}>
            <button type="submit" className="btn btn-accent" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
            <button type="button" className="btn" onClick={() => setDraft(null)}>Cancel</button>
          </div>
        </form>
      )}
    </div>
  )
}
