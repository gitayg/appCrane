import { useCallback, useEffect, useState } from 'react'
import { adminApi, ApiError } from '../adminApi'
import { useMe } from '../hooks/useMe'
import { SurveyAdmin } from '../components/surveys/SurveyAdmin'
import { Distribution, StatTiles, Trend, npsText, type NpsStats } from '../components/surveys/NpsCharts'

// NPS & surveys: results for the apps the caller may see (platform admins: all;
// app owners: their own -- GET /api/surveys/results enforces it), and, for
// platform admins, the survey definitions.

interface Results {
  bucket: 'week' | 'month'
  overall: NpsStats
  apps: ({ slug: string; name: string } & NpsStats)[]
  trend: ({ period: string } & NpsStats)[]
  distribution: { score: number; count: number }[]
}

interface ResponseRow {
  id: number
  submitted_at: string
  nps_score: number | null
  app_slug: string
  app_name: string
  survey_name: string
  user_name: string | null
  user_email: string | null
  answers: { question_id: number; kind: string; prompt: string; value: number | string }[]
}

function formatWhen(raw: string): string {
  const d = new Date(raw.includes('T') ? raw : raw.replace(' ', 'T') + 'Z')
  return isNaN(d.getTime()) ? raw : d.toLocaleString()
}

function initialApp(): string {
  try { return new URLSearchParams(window.location.search).get('app') || '' } catch { return '' }
}

export function Surveys() {
  const me = useMe()
  const isPlatformAdmin = me?.user?.role === 'platform_admin'
  const [tab, setTab] = useState<'results' | 'configure'>(() => (window.location.hash === '#configure' ? 'configure' : 'results'))
  const [app, setApp] = useState(initialApp)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [bucket, setBucket] = useState<'month' | 'week'>('month')
  const [results, setResults] = useState<Results | null>(null)
  const [responses, setResponses] = useState<ResponseRow[]>([])
  const [appOptions, setAppOptions] = useState<{ slug: string; name: string }[]>([])
  const [error, setError] = useState<string | null>(null)
  const [forbidden, setForbidden] = useState(false)
  const [loading, setLoading] = useState(false)

  const query = useCallback((extra: Record<string, string> = {}) => {
    const q = new URLSearchParams()
    if (app) q.set('app', app)
    if (from) q.set('from', from)
    if (to) q.set('to', to)
    for (const [k, v] of Object.entries(extra)) q.set(k, v)
    const s = q.toString()
    return s ? `?${s}` : ''
  }, [app, from, to])

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      adminApi.get<Results>(`/api/surveys/results${query({ bucket })}`),
      adminApi.get<{ responses: ResponseRow[] }>(`/api/surveys/responses${query()}`),
    ]).then(([r, l]) => {
      setResults(r); setResponses(l.responses); setError(null); setForbidden(false)
      if (!app) setAppOptions(r.apps.map(a => ({ slug: a.slug, name: a.name })))
    }).catch(e => {
      if (e instanceof ApiError && e.status === 403 && !app) setForbidden(true)
      else setError(e instanceof Error ? e.message : 'Could not load results')
    }).finally(() => setLoading(false))
  }, [query, bucket, app])

  useEffect(() => { if (tab === 'results') load() }, [load, tab])

  async function exportCsv() {
    try {
      const csv = await adminApi.getText(`/api/surveys/responses.csv${query()}`)
      const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
      const a = document.createElement('a')
      a.href = url; a.download = 'survey-responses.csv'; a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (e) { setError(e instanceof Error ? e.message : 'Export failed') }
  }

  const pick = (t: 'results' | 'configure') => { window.location.hash = t === 'configure' ? 'configure' : ''; setTab(t) }

  return (
    <div className="container">
      <h2>NPS &amp; surveys</h2>
      {isPlatformAdmin && (
        <div className="phase-tab-strip" role="tablist" style={{ marginBottom: 12 }}>
          {(['results', 'configure'] as const).map(t => (
            <button key={t} role="tab" aria-selected={tab === t} className={'phase-tab' + (tab === t ? ' active' : '')} onClick={() => pick(t)}>
              {t === 'results' ? 'Results' : 'Configure'}
            </button>
          ))}
        </div>
      )}

      {tab === 'configure' && isPlatformAdmin && <SurveyAdmin />}

      {tab === 'results' && forbidden && (
        <p style={{ color: 'var(--dim)' }}>Survey results are shown to app owners (for their apps) and platform admins.</p>
      )}

      {tab === 'results' && !forbidden && (
        <>
          <div className="filter-row">
            <select value={app} onChange={e => setApp(e.target.value)} aria-label="Filter by app">
              <option value="">All your apps</option>
              {appOptions.map(a => <option key={a.slug} value={a.slug}>{a.name}</option>)}
              {app && !appOptions.some(a => a.slug === app) && <option value={app}>{app}</option>}
            </select>
            <label style={{ fontSize: '.82rem' }}>From <input type="date" value={from} onChange={e => setFrom(e.target.value)} /></label>
            <label style={{ fontSize: '.82rem' }}>To <input type="date" value={to} onChange={e => setTo(e.target.value)} /></label>
            <select value={bucket} onChange={e => setBucket(e.target.value as 'month' | 'week')} aria-label="Trend by">
              <option value="month">By month</option>
              <option value="week">By week</option>
            </select>
            <button className="btn" onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</button>
            <button className="btn" onClick={exportCsv} disabled={!responses.length}>Export CSV</button>
          </div>

          {error && <div role="alert" style={{ padding: '8px 12px', borderRadius: 6, margin: '8px 0', border: '1px solid var(--red)', color: 'var(--red)' }}>{error}</div>}

          {results && (
            <>
              <StatTiles s={results.overall} />
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
                <div className="am-card">
                  <h3 style={{ marginTop: 0, fontSize: '.95rem' }}>Score distribution</h3>
                  <Distribution rows={results.distribution} />
                </div>
                <div className="am-card">
                  <h3 style={{ marginTop: 0, fontSize: '.95rem' }}>NPS over time</h3>
                  <Trend rows={results.trend} />
                </div>
              </div>

              {results.apps.length > 1 && (
                <>
                  <h3 style={{ fontSize: '.95rem' }}>By app</h3>
                  <table>
                    <thead><tr><th>App</th><th>Answers</th><th>NPS</th><th>Promoters</th><th>Passives</th><th>Detractors</th></tr></thead>
                    <tbody>
                      {results.apps.map(a => (
                        <tr key={a.slug} style={{ cursor: 'pointer' }} onClick={() => setApp(a.slug)}>
                          <td>{a.name}</td><td>{a.total}</td><td style={{ fontWeight: 600 }}>{npsText(a.nps)}</td>
                          <td>{a.promoters}</td><td>{a.passives}</td><td>{a.detractors}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </>
          )}

          <h3 style={{ fontSize: '.95rem' }}>Answers{responses.length ? ` (${responses.length})` : ''}</h3>
          {!responses.length && !loading && <p style={{ color: 'var(--dim)' }}>No answers yet.</p>}
          {responses.length > 0 && (
            <table>
              <thead><tr><th>When</th><th>App</th><th>Who</th><th>NPS</th><th>Answers</th></tr></thead>
              <tbody>
                {responses.map(r => (
                  <tr key={r.id}>
                    <td style={{ whiteSpace: 'nowrap', color: 'var(--dim)', fontSize: '.8rem' }}>{formatWhen(r.submitted_at)}</td>
                    <td>{r.app_name}</td>
                    <td>{r.user_name || '–'}{r.user_email && <div style={{ color: 'var(--dim)', fontSize: '.75rem' }}>{r.user_email}</div>}</td>
                    <td style={{ fontWeight: 600 }}>{r.nps_score ?? '–'}</td>
                    <td style={{ fontSize: '.82rem' }}>
                      {r.answers.filter(a => a.kind !== 'nps').map(a => (
                        <div key={a.question_id}><span style={{ color: 'var(--dim)' }}>{a.prompt}</span> {String(a.value)}</div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  )
}
