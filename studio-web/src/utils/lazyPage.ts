import { lazy, type ComponentType } from 'react'

const RELOAD_KEY = 'cc_chunk_reload_at'

// React.lazy for a page module's named export. A tab opened before a deploy
// asks for chunk names the new build no longer has; reload once to pick up the
// new index.html instead of rendering a broken route (once per 30 s, so a chunk
// that is really missing still surfaces as an error rather than a reload loop).
export function lazyPage<M extends Record<K, ComponentType<any>>, K extends string>(load: () => Promise<M>, name: K) {
  return lazy(() => load().then(m => ({ default: m[name] }), (err) => {
    let last = 0
    try { last = Number(sessionStorage.getItem(RELOAD_KEY)) || 0 } catch { /* storage blocked */ }
    if (Date.now() - last < 30_000) throw err
    try { sessionStorage.setItem(RELOAD_KEY, String(Date.now())) } catch { /* storage blocked */ }
    window.location.reload()
    return new Promise<never>(() => {})
  }))
}
