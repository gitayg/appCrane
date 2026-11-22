import { useEffect, useState } from 'react'
import { adminApi } from '../../adminApi'
import { errText } from './format'
import type { ManageCtx } from './types'

/** Name, description and tag (any app admin, as on the apps list), and the slug rename (owner or platform admin). */
export function AppDetailsCard({ ctx }: { ctx: ManageCtx }) {
  const { app, slug } = ctx
  const [name, setName] = useState(app.name)
  const [desc, setDesc] = useState(app.description || '')
  const [tag, setTag] = useState(app.category || '')
  const [newSlug, setNewSlug] = useState(slug)
  useEffect(() => { setName(app.name); setDesc(app.description || ''); setTag(app.category || ''); setNewSlug(slug) }, [app.name, app.description, app.category, slug])
  const canRename = !!ctx.detail?.app?.can_rename
  const dirty = name.trim() !== app.name || desc.trim() !== (app.description || '') || tag.trim() !== (app.category || '')

  async function save() {
    if (!name.trim()) return ctx.onMsg({ text: 'Name is required', ok: false })
    try {
      await adminApi.put(`/api/apps/${slug}`, { name: name.trim(), description: desc.trim() || null, category: tag.trim() })
      ctx.patchApp({ name: name.trim(), description: desc.trim(), category: tag.trim() || undefined })
      ctx.onMsg({ text: 'Saved', ok: true })
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  async function rename() {
    const s = newSlug.trim()
    if (s === slug) return ctx.onMsg({ text: 'Slug unchanged', ok: false })
    if (!/^[a-z0-9][a-z0-9-]*$/.test(s)) return ctx.onMsg({ text: 'Slug must be lowercase letters, numbers, and dashes', ok: false })
    if (!confirm(`Rename /${slug} → /${s}?\n\nThe old path will redirect to the new one. Both environments will be redeployed.`)) return
    try {
      await adminApi.post(`/api/apps/${slug}/rename`, { new_slug: s, redirect: true })
      window.location.assign(`/app?slug=${encodeURIComponent(s)}`)
    } catch (e) { ctx.onMsg({ text: errText(e), ok: false }) }
  }

  return (
    <div className="am-card">
      <h3 style={{ marginBottom: 10 }}>App details</h3>
      <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
        <label className="am2-small am2-dim">Name
          <input className="am2-input" style={{ display: 'block', width: '100%', marginTop: 4 }} value={name} onChange={e => setName(e.target.value)} />
        </label>
        <label className="am2-small am2-dim">Tag
          <input className="am2-input" style={{ display: 'block', width: '100%', marginTop: 4 }} value={tag} placeholder="—" onChange={e => setTag(e.target.value)} />
        </label>
      </div>
      <label className="am2-small am2-dim" style={{ display: 'block', marginTop: 10 }}>Description
        <textarea className="am2-input" rows={2} style={{ display: 'block', width: '100%', marginTop: 4, resize: 'vertical' }} value={desc} onChange={e => setDesc(e.target.value)} />
      </label>
      <button className="btn btn-sm" style={{ marginTop: 10 }} disabled={!dirty} onClick={save}>Save</button>
      {canRename && (
        <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <label className="am2-small am2-dim">URL slug (path)</label>
          <div className="am2-row" style={{ marginTop: 4 }}>
            <input className="am2-input am2-mono" maxLength={48} style={{ flex: 1, minWidth: 160 }} value={newSlug} onChange={e => setNewSlug(e.target.value)} aria-label="URL slug" />
            <button className="btn btn-sm" onClick={rename} disabled={newSlug.trim() === slug}>Rename</button>
          </div>
          <p className="am2-small am2-dim" style={{ marginTop: 5 }}>Old path keeps redirecting to the new one and stays reserved for this app. Triggers a redeploy. At most 3 renames a day.</p>
        </div>
      )}
    </div>
  )
}
