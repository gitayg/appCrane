// setInterval that stops while the tab is hidden and, when it is shown again,
// runs `fn` at once and resumes. Returns the cleanup, so an effect can
// `return setVisibleInterval(load, 15_000)`.
export function setVisibleInterval(fn: () => void, ms: number): () => void {
  let id: number | null = null
  const start = () => { if (id === null) id = window.setInterval(fn, ms) }
  const stop = () => { if (id !== null) { window.clearInterval(id); id = null } }
  const onVisibility = () => {
    if (document.hidden) { stop(); return }
    if (id === null) { fn(); start() }
  }
  if (!document.hidden) start()
  document.addEventListener('visibilitychange', onVisibility)
  return () => { stop(); document.removeEventListener('visibilitychange', onVisibility) }
}
