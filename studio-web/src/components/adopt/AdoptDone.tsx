import { Link } from 'react-router-dom'
import type { AdoptResult } from './adoptTypes'

export function AdoptDone({ result, onAnother }: { result: AdoptResult; onAnother: () => void }) {
  const deploy = result.deployments[0]
  return (
    <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <h2 style={{ margin: 0, fontSize: '1.1rem' }}>{result.app.name} is adopted</h2>
      <div style={{ fontSize: '.85rem' }}>
        {result.files_committed} files committed{result.scaffold.length ? `, including ${result.scaffold.join(', ')} added by AppCrane` : ''}.
        {result.env_keys_set.length ? ` Sandbox env vars set: ${result.env_keys_set.join(', ')}.` : ''}
      </div>
      <div style={{ fontSize: '.85rem' }}>
        {deploy ? `Sandbox deploy #${deploy.deployment_id} started.` : 'No deploy started yet.'}{' '}
        Intake: {result.intake.submitted ? 'submitted' : `not recorded${result.intake.reason ? ` (${result.intake.reason})` : ''}`}.
        {result.requests.length ? ` ${result.requests.length} request(s) opened for the coder.` : ''}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
        <a className="btn btn-accent" href={result.sandbox_url} target="_blank" rel="noreferrer">Open the sandbox</a>
        <Link className="btn" to={`/app?slug=${encodeURIComponent(result.app.slug)}`}>Manage the app</Link>
        <Link className="btn" to="/requests">Requests and the coder</Link>
        <button type="button" className="btn" onClick={onAnother}>Adopt another app</button>
      </div>
    </div>
  )
}
