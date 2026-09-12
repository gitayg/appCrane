import { useEffect, useState } from 'react'

/**
 * The second confirmation on a redeploy that destroys state.
 *
 * A deploy runs `docker rm -f` and builds a new container. Anything the app
 * persists at a path AppCrane is not mounting goes with the old one — the
 * server measures exactly which paths those are
 * (server/services/redeployRisk.js) and this renders the answer.
 *
 * THREE THINGS THIS DELIBERATELY IS NOT:
 *
 *  1. Not a second "are you sure?". A dialog that carries no information is one
 *     people learn to dismiss without reading, and then it is worse than
 *     nothing: it has trained the reflex that clears it. Every path is named,
 *     the surviving ones next to the doomed ones, because "which of my data
 *     does this keep" is the actual question and a yes/no box never answers it.
 *  2. Not shown to everyone. The server returns at_risk=false for an app whose
 *     declared volumes cover everything its image declares, and for an app with
 *     no container at all — a first deploy, and the catalogue's
 *     install-then-deploy flow, are silent. Nagging a safe app is how the
 *     warning stops meaning anything on the app where it matters.
 *  3. Not dismissible by clicking. The confirm button stays disabled until the
 *     app's own slug is typed, so the gesture cannot be muscle memory. That is
 *     the point of the exercise: the operator has to have read far enough to
 *     know which app they are about to do this to.
 *
 * The typed-slug gate is a UI affordance, not the enforcement. The server
 * refuses an unacknowledged deploy with 409 DATA_LOSS_NOT_ACKNOWLEDGED whatever
 * the browser does.
 */

export interface RedeployRisk {
  at_risk: boolean
  unknown: boolean
  app: string
  env: string
  container: string
  at_risk_paths: string[]
  /**
   * Paths the app WROTE that no mount covers, found with `docker diff` rather
   * than from the image's VOLUME list. A Laravel app persisting to
   * /var/www/html/storage declares no VOLUME at all, so at_risk_paths is empty
   * for it and this is the only list with anything in it.
   */
  written_paths?: string[]
  writable_layer_unknown?: boolean
  persisted_paths: string[]
  always_persisted: string[]
  reason: string
  summary: string
  acknowledge_with: string
}

const CSS = `
.rw-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:10600;display:flex;align-items:center;justify-content:center;padding:16px}
.rw-modal{width:min(620px,96vw);max-height:88vh;background:var(--surface);color:var(--text);border:1px solid #ef444455;border-radius:8px;box-shadow:0 16px 48px rgba(0,0,0,.55);display:flex;flex-direction:column;overflow:hidden}
.rw-hdr{display:flex;align-items:baseline;gap:9px;padding:12px 16px;border-bottom:1px solid var(--border);background:#ef44441a}
.rw-hdr h3{margin:0;font-size:.95rem;font-weight:600;color:var(--red)}
.rw-hdr span{font-size:.74rem;color:var(--dim);font-family:'SF Mono',Monaco,monospace}
.rw-body{overflow-y:auto;padding:14px 16px;flex:1;display:flex;flex-direction:column;gap:14px}
.rw-lead{font-size:.84rem;line-height:1.55;margin:0}
.rw-cols{display:flex;gap:10px;flex-wrap:wrap}
.rw-col{flex:1 1 240px;border-radius:7px;padding:10px 12px;border:1px solid var(--border);background:var(--surface2)}
.rw-col.lost{border-color:#ef444455;background:#ef44440f}
.rw-col.kept{border-color:#22c55e44;background:#22c55e0f}
.rw-col h4{margin:0 0 6px;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.rw-col.lost h4{color:var(--red)}
.rw-col.kept h4{color:var(--green)}
.rw-col ul{margin:0;padding-left:0;list-style:none;display:flex;flex-direction:column;gap:4px}
.rw-col li{font-family:'SF Mono',Monaco,monospace;font-size:.78rem;word-break:break-all}
.rw-col p{margin:6px 0 0;font-size:.72rem;color:var(--dim);line-height:1.5}
.rw-why{font-size:.75rem;color:var(--dim);line-height:1.55;margin:0;border-left:2px solid var(--border);padding-left:10px}
.rw-gate{display:flex;flex-direction:column;gap:6px}
.rw-gate label{font-size:.78rem;color:var(--dim)}
.rw-gate code{font-family:'SF Mono',Monaco,monospace;color:var(--text)}
.rw-gate input{background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:7px 10px;font-family:'SF Mono',Monaco,monospace;font-size:.82rem}
.rw-gate input:focus{outline:none;border-color:var(--red)}
.rw-foot{display:flex;gap:8px;justify-content:flex-end;padding:12px 16px;border-top:1px solid var(--border);background:var(--surface2)}
.rw-danger{background:var(--red);color:#fff;border:none;border-radius:6px;padding:7px 14px;font-weight:600;font-size:.82rem;cursor:pointer}
.rw-danger:disabled{opacity:.4;cursor:not-allowed}
`

/**
 * Fetch the verdict for one app + env.
 *
 * A failure to reach the endpoint returns null, and the caller treats null as
 * "cannot show a warning" rather than as "safe" — see the call site in
 * AppManager: a null falls back to a text confirmation that says the risk could
 * not be read. The server's 409 is still there underneath either way.
 */
export async function fetchRedeployRisk(
  api: { get: <T>(p: string) => Promise<T> },
  slug: string,
  env: string,
): Promise<RedeployRisk | null> {
  try {
    const r = await api.get<{ risk: RedeployRisk }>(`/api/apps/${slug}/deploy/${env}/risk`)
    return r?.risk ?? null
  } catch (_) {
    return null
  }
}

export function RedeployWarning({ risk, onCancel, onConfirm }: {
  risk: RedeployRisk
  onCancel: () => void
  onConfirm: () => void
}) {
  const [typed, setTyped] = useState('')
  const armed = typed.trim() === risk.app

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onCancel() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onCancel])

  const written = risk.written_paths ?? []
  // Both kinds of loss, for the remediation sentence and the typed-slug gate.
  // Keeping them separate in the Lost column matters because the explanation
  // differs -- an anonymous volume and a writable-layer write are lost for
  // different reasons -- but the fix is the same for both: declare the path.
  const lost = [...risk.at_risk_paths, ...written]
  const kept = [...risk.always_persisted, ...risk.persisted_paths]

  return (
    <div className="rw-overlay" onClick={onCancel}>
      <style>{CSS}</style>
      <div className="rw-modal" onClick={e => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="rw-hdr">
          <h3>This redeploy destroys data</h3>
          <span>{risk.app} / {risk.env}</span>
        </div>
        <div className="rw-body">
          <p className="rw-lead">
            Deploying replaces the container <code>{risk.container}</code>. It is not restarted — it is
            deleted and rebuilt, and only the paths AppCrane mounts survive that.
          </p>

          <div className="rw-cols">
            <div className="rw-col lost">
              <h4>Lost</h4>
              {risk.unknown ? (
                <p>
                  AppCrane could not read this container, so which of its paths are persisted is
                  unknown. Treated as at-risk rather than as safe.
                </p>
              ) : (
                <>
                  {risk.at_risk_paths.length > 0 && (
                    <>
                      <ul>{risk.at_risk_paths.map(p => <li key={p}>{p}</li>)}</ul>
                      <p>Held in anonymous volumes the replacement container will not be given.</p>
                    </>
                  )}
                  {written.length > 0 && (
                    <>
                      <ul>{written.map(p => <li key={p}>{p}</li>)}</ul>
                      <p>
                        Written by the app itself, in the container&rsquo;s writable layer, which no
                        mount covers. Its image declares no volume here, so nothing marks it as
                        state — but it is.
                      </p>
                    </>
                  )}
                  {risk.writable_layer_unknown && (
                    <p>
                      AppCrane could not read what this container has written, so anything outside
                      the paths on the right is treated as at-risk rather than as safe.
                    </p>
                  )}
                </>
              )}
            </div>
            <div className="rw-col kept">
              <h4>Kept</h4>
              <ul>{kept.map(p => <li key={p}>{p}</li>)}</ul>
              <p>Bind-mounted into this app&rsquo;s own directory, which outlives any container.</p>
            </div>
          </div>

          {!risk.unknown && lost.length > 0 && (
            <p className="rw-why">
              To keep {lost.join(', ')} across future deploys, add
              {lost.length > 1 ? ' them' : ' it'} to this app&rsquo;s volume paths first.
              Doing that does not rescue what is in {lost.length > 1 ? 'them' : 'it'} now &mdash;
              only the next deploy after that starts persisting it.
            </p>
          )}

          <div className="rw-gate">
            <label htmlFor="rw-slug">
              Type <code>{risk.app}</code> to confirm you accept losing the paths listed above.
            </label>
            <input
              id="rw-slug"
              autoFocus
              autoComplete="off"
              spellCheck={false}
              value={typed}
              placeholder={risk.app}
              onChange={e => setTyped(e.target.value)}
            />
          </div>
        </div>
        <div className="rw-foot">
          <button className="btn btn-sm" onClick={onCancel}>Cancel</button>
          <button className="rw-danger" disabled={!armed} onClick={onConfirm}>
            Deploy and lose that data
          </button>
        </div>
      </div>
    </div>
  )
}

export default RedeployWarning
