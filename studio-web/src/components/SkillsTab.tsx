import { useEffect, useState } from 'react'
import { adminApi } from '../adminApi'
import { parseFrontmatter } from '../lib/parseFrontmatter'

interface Skill {
  id: number
  slug: string
  name: string
  description: string | null
  enabled: 0 | 1
  uploaded_at: string
}

export function SkillsTab() {
  const [skills, setSkills] = useState<Skill[]>([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [description, setDescription] = useState('')
  const [content, setContent] = useState('')
  const [bundle, setBundle] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [autoFilled, setAutoFilled] = useState<{ name?: boolean; slug?: boolean; description?: boolean }>({})

  // Pre-fill empty form fields from a SKILL.md frontmatter. Operator-typed
  // values always win — we only touch fields that are blank OR were
  // previously auto-filled by us (so re-picking a different file updates).
  function applyFrontmatter(text: string) {
    const fm = parseFrontmatter(text)
    if (!Object.keys(fm).length) return
    const next: typeof autoFilled = {}
    if (fm.name && (!name || autoFilled.name))                       { setName(fm.name); next.name = true }
    if (fm.slug && (!slug || autoFilled.slug))                       { setSlug(fm.slug); next.slug = true }
    if (fm.description && (!description || autoFilled.description))  { setDescription(fm.description); next.description = true }
    setAutoFilled(prev => ({ ...prev, ...next }))
  }

  function onPickFile(file: File | null) {
    setBundle(file)
    if (!file) return
    const lower = file.name.toLowerCase()
    if (!(lower.endsWith('.md') || lower.endsWith('.markdown'))) return // .zip not parsed client-side
    file.text().then(applyFrontmatter).catch(() => {})
  }

  function load() {
    setLoading(true)
    adminApi.get<{ skills: Skill[] }>('/api/skills')
      .then(d => setSkills(d.skills || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  function flash(text: string, ok: boolean) {
    setMsg({ text, ok })
    setTimeout(() => setMsg(null), 5000)
  }

  async function toggle(s: Skill) {
    try {
      await adminApi.put(`/api/skills/${s.slug}`, { enabled: s.enabled === 0 })
      setSkills(prev => prev.map(p => p.slug === s.slug ? { ...p, enabled: s.enabled === 0 ? 1 : 0 } : p))
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

  async function remove(s: Skill) {
    if (!confirm(`Delete skill "${s.name}"? This removes its files from disk.`)) return
    try {
      await adminApi.del(`/api/skills/${s.slug}`)
      setSkills(prev => prev.filter(p => p.slug !== s.slug))
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

  async function upload(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) { flash('Name required', false); return }
    if (!content.trim() && !bundle) { flash('Either paste SKILL.md content OR pick a .md or .zip file', false); return }
    setUploading(true)
    try {
      if (bundle) {
        const fd = new FormData()
        fd.append('bundle', bundle)
        fd.append('name', name.trim())
        if (slug.trim())        fd.append('slug', slug.trim())
        if (description.trim()) fd.append('description', description.trim())
        const r = await fetch('/api/skills', { method: 'POST', headers: adminApi.authHeaders(), body: fd })
        if (!r.ok) {
          const body = await r.json().catch(() => ({}))
          throw new Error(body?.error?.message || `HTTP ${r.status}`)
        }
      } else {
        await adminApi.post('/api/skills', {
          name: name.trim(),
          slug: slug.trim() || undefined,
          description: description.trim() || undefined,
          content,
        })
      }
      setName(''); setSlug(''); setDescription(''); setContent(''); setBundle(null); setAutoFilled({})
      flash('Skill uploaded', true)
      load()
    } catch (e) {
      flash((e as Error).message, false)
    } finally {
      setUploading(false)
    }
  }

  return (
    <div>
      <h2>Skills</h2>
      <p style={{ color: 'var(--dim)', fontSize: '.85rem', marginBottom: 16 }}>
        Anthropic-style skill bundles loaded by every CLI agent (Builder chat, Ask, enhancement coder, planner, contextBuilder)
        via the Claude Code CLI's native <code>~/.claude/skills/</code> loader. Toggle to enable/disable globally — toggle changes
        affect new dispatches; live Builder/Ask sessions need a pause + resume to pick up changes.
      </p>

      {msg && (
        <div style={{
          padding: '8px 12px', borderRadius: 6, marginBottom: 12, fontSize: '.85rem',
          background: msg.ok ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
          color: msg.ok ? 'var(--green)' : 'var(--red)',
          border: `1px solid ${msg.ok ? 'var(--green)' : 'var(--red)'}`,
        }}>{msg.text}</div>
      )}

      <h3 style={{ marginTop: 24, marginBottom: 8, fontSize: '.95rem' }}>Installed skills</h3>
      {loading ? <div style={{ color: 'var(--dim)' }}>Loading…</div> :
       skills.length === 0 ? <div style={{ color: 'var(--dim)' }}>No skills installed yet.</div> :
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left',  padding: 6, borderBottom: '1px solid var(--border)' }}>Enabled</th>
              <th style={{ textAlign: 'left',  padding: 6, borderBottom: '1px solid var(--border)' }}>Name</th>
              <th style={{ textAlign: 'left',  padding: 6, borderBottom: '1px solid var(--border)' }}>Slug</th>
              <th style={{ textAlign: 'left',  padding: 6, borderBottom: '1px solid var(--border)' }}>Description</th>
              <th style={{ textAlign: 'right', padding: 6, borderBottom: '1px solid var(--border)' }}></th>
            </tr>
          </thead>
          <tbody>
            {skills.map(s => (
              <tr key={s.slug}>
                <td style={{ padding: 6 }}>
                  <input type="checkbox" checked={s.enabled === 1} onChange={() => toggle(s)} />
                </td>
                <td style={{ padding: 6 }}>{s.name}</td>
                <td style={{ padding: 6, fontFamily: 'monospace', fontSize: '.82rem', color: 'var(--dim)' }}>{s.slug}</td>
                <td style={{ padding: 6, color: 'var(--dim)', fontSize: '.85rem' }}>{s.description || '—'}</td>
                <td style={{ padding: 6, textAlign: 'right' }}>
                  <button className="btn btn-red" onClick={() => remove(s)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      }

      <h3 style={{ marginTop: 32, marginBottom: 8, fontSize: '.95rem' }}>Add a skill</h3>
      <form onSubmit={upload} style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 640 }}>
        <input
          className="editable" placeholder="Name" value={name}
          onChange={e => { setName(e.target.value); setAutoFilled(p => ({ ...p, name: false })) }}
        />
        <input
          className="editable" placeholder="Slug (auto-generated if empty)" value={slug}
          onChange={e => { setSlug(e.target.value); setAutoFilled(p => ({ ...p, slug: false })) }}
        />
        <input
          className="editable" placeholder="Description (optional)" value={description}
          onChange={e => { setDescription(e.target.value); setAutoFilled(p => ({ ...p, description: false })) }}
        />
        <textarea
          className="editable" rows={8}
          placeholder="Paste SKILL.md content here, OR upload a .md / .zip file below"
          value={content}
          onChange={e => { setContent(e.target.value); applyFrontmatter(e.target.value) }}
          style={{ fontFamily: 'monospace', fontSize: '.85rem' }}
        />
        <div>
          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>or upload a .md file (single skill) or .zip bundle (multi-file skill):</label><br/>
          <input type="file" accept=".md,.markdown,.zip" onChange={e => onPickFile(e.target.files?.[0] || null)} />
          {bundle && <span style={{ marginLeft: 8, fontSize: '.82rem', color: 'var(--dim)' }}>{bundle.name}</span>}
        </div>
        <div>
          <button type="submit" className="btn btn-primary" disabled={uploading}>
            {uploading ? 'Uploading…' : 'Add skill'}
          </button>
        </div>
      </form>
    </div>
  )
}
