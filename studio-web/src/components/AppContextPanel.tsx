import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'

interface Props {
  slug:    string | null
  appName: string
  open:    boolean
  onClose: () => void
}

/**
 * Right-docked drawer showing the per-app system context that the AI
 * agents (Builder, Improve, Ask) all consume. Loaded lazily on first
 * open per slug, edited in-place, saved via PUT /api/appstudio/context/:slug.
 *
 * This is the per-app material that used to live in the standalone
 * Library tab — surfaced here so a builder driver can read & tweak it
 * without leaving the session.
 */
export function AppContextPanel({ slug, appName, open, onClose }: Props) {
  const [content, setContent] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [savedAt, setSavedAt] = useState<number | null>(null)
  const [dirty, setDirty] = useState(false)
  const loadedSlugRef = useRef<string | null>(null)

  // Lazy-load on (re)open or slug change
  useEffect(() => {
    if (!open || !slug) return
    if (loadedSlugRef.current === slug && loaded) return
    setLoading(true)
    setLoaded(false)
    setDirty(false)
    setSavedAt(null)
    adminApi.get<{ content?: string }>(`/api/appstudio/context/${encodeURIComponent(slug)}`)
      .then(r => { setContent(r?.content ?? ''); loadedSlugRef.current = slug; setLoaded(true) })
      .catch(() => { setContent(''); loadedSlugRef.current = slug; setLoaded(true) })
      .finally(() => setLoading(false))
  }, [open, slug, loaded])

  // Reset cached content when the underlying app changes
  useEffect(() => {
    if (loadedSlugRef.current && loadedSlugRef.current !== slug) {
      loadedSlugRef.current = null
      setLoaded(false)
      setContent('')
      setDirty(false)
      setSavedAt(null)
    }
  }, [slug])

  if (!open) return null

  async function save() {
    if (!slug || saving) return
    setSaving(true)
    try {
      await adminApi.put(`/api/appstudio/context/${encodeURIComponent(slug)}`, { content })
      setSavedAt(Date.now())
      setDirty(false)
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const recentSave = savedAt && (Date.now() - savedAt) < 2500

  return (
    <div className="ctx-panel">
      <div className="ctx-header">
        <span className="ctx-title">📚 Context</span>
        <span className="ctx-app">{appName}</span>
        <div style={{ flex: 1 }} />
        <button
          type="button"
          className="ctx-save"
          disabled={!dirty || saving || !loaded}
          onClick={save}
          title="Save (Cmd/Ctrl+S)"
        >
          {saving ? 'Saving…' : recentSave && !dirty ? 'Saved ✓' : 'Save'}
        </button>
        <button type="button" className="ctx-close" onClick={onClose} title="Close panel">×</button>
      </div>
      <div className="ctx-hint">
        System context, coding guidelines, and notes the Builder / Ask / Improve agents
        load every time they touch this app. Stored at <code>/api/appstudio/context/{slug}</code>.
      </div>
      <textarea
        className="ctx-editor"
        value={content}
        disabled={!loaded || loading}
        onChange={e => { setContent(e.target.value); setDirty(true) }}
        onKeyDown={e => {
          if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
            e.preventDefault(); save()
          }
        }}
        placeholder={loading ? 'Loading…' : 'Paste system context, coding guidelines, or notes for this app…'}
      />
    </div>
  )
}
