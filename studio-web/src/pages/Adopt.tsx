import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { AdoptDone } from '../components/adopt/AdoptDone'
import { AdoptForm } from '../components/adopt/AdoptForm'
import { ReportView } from '../components/adopt/ReportView'
import { SourceStep } from '../components/adopt/SourceStep'
import type { AdoptResult, Analysis, SourceGuide } from '../components/adopt/adoptTypes'

/**
 * Adopt an app: bring a project built with Lovable, Bolt, v0, Replit, Figma
 * Make (or any GitHub repo or zip) onto this AppCrane. Source, then the
 * adoption report, then env vars and intake, then a sandbox deploy.
 */
export function Adopt() {
  const [guides, setGuides] = useState<SourceGuide[]>([])
  const [maxBytes, setMaxBytes] = useState<number | null>(null)
  const [denied, setDenied] = useState('')
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [result, setResult] = useState<AdoptResult | null>(null)

  useEffect(() => {
    adminApi.get<{ tools: SourceGuide[]; limits: { max_archive_bytes: number } }>('/api/adopt/sources')
      .then(r => { setGuides(r.tools); setMaxBytes(r.limits.max_archive_bytes) })
      .catch(e => setDenied(e instanceof Error ? e.message : String(e)))
  }, [])

  const reset = () => { setAnalysis(null); setResult(null) }

  return (
    <div className="container" style={{ maxWidth: 960 }}>
      <h2 style={{ margin: '0 0 4px' }}>Adopt an app</h2>
      <p style={{ color: 'var(--dim)', marginTop: 0, fontSize: '.85rem' }}>
        Bring an app built with Lovable, Bolt, v0, Replit or Figma Make onto this server: behind your sign-in, scanned for exposed keys, deployed to a sandbox.
      </p>
      {denied && <div className="card" style={{ padding: 16, color: '#fca5a5' }}>{denied}</div>}
      {!denied && !analysis && <SourceStep guides={guides} maxBytes={maxBytes} onAnalyzed={setAnalysis} />}
      {!denied && analysis && !result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <ReportView analysis={analysis} />
          <AdoptForm analysis={analysis} onAdopted={setResult} />
          <div><button type="button" className="btn btn-sm" onClick={reset}>Start over</button></div>
        </div>
      )}
      {result && <AdoptDone result={result} onAnother={reset} />}
    </div>
  )
}
