import { useCallback, useEffect, useState } from 'react'
import { coderApi, type ChangedFile, type ReleaseResult } from './api'
import { CoderRefusal } from './CoderRefusal'

interface Props {
  slug:       string
  sessionId:  string
  /**
   * Whether the caller holds admin/owner on this app. POST .../release is
   * gated on exactly that (coder.js requireAppAdmin), so a user without it is
   * not offered the button — a control whose only outcome is a 403 is worse
   * than no control.
   */
  canRelease: boolean
  /** Bumped by the panel when a turn finishes, so the list re-reads itself. */
  refreshKey: number
}

const STATUS_LABEL: Record<ChangedFile['status'], string> = {
  added: 'A', modified: 'M', deleted: 'D',
}

export function CoderChanges({ slug, sessionId, canRelease, refreshKey }: Props) {
  const [files,    setFiles]    = useState<ChangedFile[] | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [openDiff, setOpenDiff] = useState<string | null>(null)
  const [message,  setMessage]  = useState('')
  const [busy,     setBusy]     = useState(false)
  const [error,    setError]    = useState<unknown>(null)
  const [result,   setResult]   = useState<ReleaseResult | null>(null)

  const load = useCallback(() => {
    setError(null)
    coderApi.changes(slug, sessionId)
      .then(r => {
        const list = r.files || []
        setFiles(list)
        // Default to everything selected, but never resurrect a path that has
        // since left the change set (a release removes it from the listing).
        setSelected(prev => new Set(
          list.filter(f => prev.size === 0 || prev.has(f.path)).map(f => f.path),
        ))
      })
      .catch(e => { setFiles([]); setError(e) })
  }, [slug, sessionId])

  useEffect(() => { load() }, [load, refreshKey])

  const toggle = (path: string) => setSelected(prev => {
    const next = new Set(prev)
    if (next.has(path)) next.delete(path); else next.add(path)
    return next
  })

  async function release() {
    const paths = (files || []).filter(f => selected.has(f.path)).map(f => f.path)
    if (!paths.length || busy) return
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const r = await coderApi.release(slug, sessionId, paths, message.trim() || undefined)
      setResult(r)
      setMessage('')
      setSelected(new Set())
      load()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  if (files === null) return <div className="coder-note">Reading changes…</div>

  return (
    <div className="coder-changes">
      <div className="coder-changes-head">
        <span>{files.length} changed file{files.length === 1 ? '' : 's'}</span>
        <button type="button" className="coder-btn coder-btn-xs" onClick={load}>Refresh</button>
      </div>

      {files.length === 0 && !result && (
        <div className="coder-note">
          Nothing changed in this session’s workspace yet.
        </div>
      )}

      {files.map(f => (
        <div key={f.path} className="coder-file">
          <label className="coder-file-row">
            <input
              type="checkbox"
              checked={selected.has(f.path)}
              onChange={() => toggle(f.path)}
              disabled={!canRelease || busy}
            />
            <span className={`coder-file-st coder-file-st-${f.status}`}>{STATUS_LABEL[f.status]}</span>
            <span className="coder-file-path" title={f.path}>{f.path}</span>
            <button
              type="button"
              className="coder-btn coder-btn-xs"
              onClick={() => setOpenDiff(d => (d === f.path ? null : f.path))}
            >{openDiff === f.path ? 'Hide' : 'Diff'}</button>
          </label>
          {openDiff === f.path && (
            <pre className="coder-diff">{f.diff || '(no diff available)'}</pre>
          )}
        </div>
      ))}

      {result && (
        <div className="coder-release-result">
          <div className="coder-release-sha">
            Released <code>{result.commit.sha.slice(0, 12)}</code>
          </div>
          {!!result.released.length && (
            <div className="coder-release-line">{result.released.length} file(s) committed</div>
          )}
          {!!result.deleted.length && (
            <div className="coder-release-line">{result.deleted.length} file(s) deleted</div>
          )}
          <div className="coder-release-line">{describeDeploy(result)}</div>
        </div>
      )}

      {error != null && <CoderRefusal error={error} />}

      {canRelease ? (
        files.length > 0 && (
          <div className="coder-release-box">
            <input
              className="coder-input"
              value={message}
              placeholder="What changed? (optional)"
              onChange={e => setMessage(e.target.value)}
              disabled={busy}
            />
            <button
              type="button"
              className="coder-btn coder-btn-primary"
              disabled={busy || selected.size === 0}
              onClick={release}
            >{busy ? 'Releasing…' : `Release ${selected.size} to sandbox`}</button>
          </div>
        )
      ) : (
        files.length > 0 && (
          <div className="coder-note">
            Releasing needs admin or owner on this app. Ask an app admin to review
            and release these changes.
          </div>
        )
      )}
    </div>
  )
}

/** Turn deployTrigger's `{action, triggered[]}` into one readable sentence. */
function describeDeploy(r: ReleaseResult): string {
  const d = r.deploy
  if (!d) return 'No deploy was triggered.'
  if (d.action === 'deploy_triggered' && d.triggered?.length) {
    return `Deploying: ${d.triggered.map(t => `${t.env} #${t.deployment_id}`).join(', ')}`
  }
  if (d.action === 'skipped_no_config' || d.action === 'skipped_no_auto') {
    return 'Committed. Deploy-on-push is off for this app, so nothing was deployed.'
  }
  if (d.action === 'skipped_superseded') {
    return 'Committed, but the branch moved on — no deploy was started.'
  }
  return `Committed. Deploy: ${d.action ?? 'none'}.`
}
