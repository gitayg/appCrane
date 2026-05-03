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
  apps?: string[]
  files?: string[]
}

interface AppOption {
  slug: string
  name: string
}

export function SkillsTab() {
  const [skills, setSkills] = useState<Skill[]>([])
  const [apps, setApps] = useState<AppOption[]>([])
  const [editingSkill, setEditingSkill] = useState<Skill | null>(null)
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [description, setDescription] = useState('')
  const [content, setContent] = useState('')
  const [url, setUrl] = useState('')
  const [bundle, setBundle] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [autoFilled, setAutoFilled] = useState<{ name?: boolean; slug?: boolean; description?: boolean }>({})
  const [renamingSkill, setRenamingSkill] = useState<Skill | null>(null)
  const [updatingSkill, setUpdatingSkill] = useState<Skill | null>(null)

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
    Promise.all([
      adminApi.get<{ skills: Skill[] }>('/api/skills').catch(() => ({ skills: [] })),
      adminApi.get<{ apps: AppOption[] }>('/api/apps').catch(() => ({ apps: [] })),
    ]).then(([sRes, aRes]) => {
      setSkills(sRes.skills || [])
      setApps((aRes.apps || []).map(a => ({ slug: a.slug, name: a.name })))
    }).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function saveAssignment(skillSlug: string, appSlugs: string[]) {
    try {
      const r = await adminApi.put<{ apps: string[] }>(`/api/skills/${skillSlug}/apps`, { app_slugs: appSlugs })
      setSkills(prev => prev.map(s => s.slug === skillSlug ? { ...s, apps: r.apps || [] } : s))
      setEditingSkill(null)
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

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
    if (!content.trim() && !bundle && !url.trim()) {
      flash('Provide one of: paste SKILL.md, pick a .md/.zip file, or paste a URL', false); return
    }
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
          content: content.trim() || undefined,
          url:     url.trim()     || undefined,
        })
      }
      setName(''); setSlug(''); setDescription(''); setContent(''); setUrl(''); setBundle(null); setAutoFilled({})
      flash('Skill uploaded', true)
      load()
    } catch (e) {
      flash((e as Error).message, false)
    } finally {
      setUploading(false)
    }
  }

  async function saveRename(skillSlug: string, newName: string, newDescription: string) {
    try {
      await adminApi.put(`/api/skills/${skillSlug}`, {
        name: newName,
        description: newDescription,
      })
      setRenamingSkill(null)
      load()
    } catch (e) {
      flash((e as Error).message, false)
    }
  }

  async function saveContentReplace(skillSlug: string, body: { content?: string; url?: string; bundle?: File | null }) {
    try {
      if (body.bundle) {
        const fd = new FormData()
        fd.append('bundle', body.bundle)
        const r = await fetch(`/api/skills/${skillSlug}/content`, {
          method: 'PUT', headers: adminApi.authHeaders(), body: fd,
        })
        if (!r.ok) {
          const errBody = await r.json().catch(() => ({}))
          throw new Error(errBody?.error?.message || `HTTP ${r.status}`)
        }
      } else {
        await adminApi.put(`/api/skills/${skillSlug}/content`, {
          content: body.content?.trim() || undefined,
          url:     body.url?.trim()     || undefined,
        })
      }
      setUpdatingSkill(null)
      flash('Skill content updated', true)
      load()
    } catch (e) {
      flash((e as Error).message, false)
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
              <th style={{ textAlign: 'left',  padding: 6, borderBottom: '1px solid var(--border)' }}>Apps</th>
              <th style={{ textAlign: 'right', padding: 6, borderBottom: '1px solid var(--border)' }}></th>
            </tr>
          </thead>
          <tbody>
            {skills.map(s => (
              <tr key={s.slug}>
                <td style={{ padding: 6 }}>
                  <input type="checkbox" checked={s.enabled === 1} onChange={() => toggle(s)} />
                </td>
                <td style={{ padding: 6 }}>
                  {s.name}
                  {s.files && s.files.filter(f => f !== 'SKILL.md').length > 0 && (
                    <span
                      title={s.files.filter(f => f !== 'SKILL.md').join('\n')}
                      style={{
                        marginLeft: 8, fontSize: '.7rem', padding: '1px 6px',
                        borderRadius: 4, background: 'var(--surface2)',
                        border: '1px solid var(--border)', color: 'var(--dim)',
                        cursor: 'help', verticalAlign: 'middle',
                      }}
                    >📎 {s.files.filter(f => f !== 'SKILL.md').length} file{s.files.filter(f => f !== 'SKILL.md').length === 1 ? '' : 's'}</span>
                  )}
                </td>
                <td style={{ padding: 6, fontFamily: 'monospace', fontSize: '.82rem', color: 'var(--dim)' }}>{s.slug}</td>
                <td style={{ padding: 6, color: 'var(--dim)', fontSize: '.85rem' }}>{s.description || '—'}</td>
                <td style={{ padding: 6, fontSize: '.82rem' }}>
                  {s.apps && s.apps.length
                    ? <span style={{ color: 'var(--text)' }}>{s.apps.join(', ')}</span>
                    : <span style={{ color: 'var(--dim)', fontStyle: 'italic' }}>none</span>}
                  {' '}
                  <button
                    className="btn btn-xs"
                    style={{ marginLeft: 6 }}
                    onClick={() => setEditingSkill(s)}
                  >Edit</button>
                </td>
                <td style={{ padding: 6, textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <button className="btn btn-xs" onClick={() => setRenamingSkill(s)} title="Rename or update description">Edit</button>
                  {' '}
                  <button className="btn btn-xs" onClick={() => setUpdatingSkill(s)} title="Replace SKILL.md content / bundle">Update file</button>
                  {' '}
                  <button className="btn btn-xs btn-red" onClick={() => remove(s)}>Delete</button>
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
          <label style={{ fontSize: '.85rem', color: 'var(--dim)' }}>or fetch from URL (raw SKILL.md or .zip — GitHub blob URLs are auto-rewritten):</label><br/>
          <input
            className="editable" value={url} onChange={e => setUrl(e.target.value)}
            placeholder="https://raw.githubusercontent.com/owner/repo/main/skills/foo/SKILL.md"
            style={{ width: '100%', fontFamily: 'monospace', fontSize: '.8rem' }}
          />
        </div>
        <div>
          <button type="submit" className="btn btn-primary" disabled={uploading}>
            {uploading ? 'Uploading…' : 'Add skill'}
          </button>
        </div>
      </form>

      {editingSkill && (
        <AssignAppsModal
          skill={editingSkill}
          allApps={apps}
          onSave={(slugs) => saveAssignment(editingSkill.slug, slugs)}
          onCancel={() => setEditingSkill(null)}
        />
      )}

      {renamingSkill && (
        <RenameSkillModal
          skill={renamingSkill}
          onSave={(n, d) => saveRename(renamingSkill.slug, n, d)}
          onCancel={() => setRenamingSkill(null)}
        />
      )}

      {updatingSkill && (
        <UpdateContentModal
          skill={updatingSkill}
          onSave={(body) => saveContentReplace(updatingSkill.slug, body)}
          onCancel={() => setUpdatingSkill(null)}
        />
      )}
    </div>
  )
}

interface RenameProps {
  skill: Skill
  onSave: (name: string, description: string) => void
  onCancel: () => void
}

function RenameSkillModal({ skill, onSave, onCancel }: RenameProps) {
  const [n, setN] = useState(skill.name)
  const [d, setD] = useState(skill.description ?? '')
  return (
    <div style={modalBackdrop} onClick={onCancel}>
      <div style={modalCard} onClick={e => e.stopPropagation()}>
        <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: '1rem' }}>Rename <code>{skill.slug}</code></h3>
        <p style={{ color: 'var(--dim)', fontSize: '.78rem', marginBottom: 12 }}>
          Slug stays <code>{skill.slug}</code> (it's referenced by app assignments + on-disk paths).
        </p>
        <label style={modalLabel}>Name</label>
        <input className="editable" value={n} onChange={e => setN(e.target.value)} style={{ width: '100%', marginBottom: 10 }} />
        <label style={modalLabel}>Description</label>
        <textarea className="editable" rows={3} value={d} onChange={e => setD(e.target.value)} style={{ width: '100%', marginBottom: 14, fontFamily: 'inherit' }} />
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button className="btn btn-primary" disabled={!n.trim()} onClick={() => onSave(n.trim(), d.trim())}>Save</button>
        </div>
      </div>
    </div>
  )
}

interface UpdateProps {
  skill: Skill
  onSave: (body: { content?: string; url?: string; bundle?: File | null }) => void
  onCancel: () => void
}

function UpdateContentModal({ skill, onSave, onCancel }: UpdateProps) {
  const [c, setC] = useState('')
  const [u, setU] = useState('')
  const [f, setF] = useState<File | null>(null)
  const empty = !c.trim() && !u.trim() && !f
  return (
    <div style={modalBackdrop} onClick={onCancel}>
      <div style={modalCard} onClick={e => e.stopPropagation()}>
        <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: '1rem' }}>Replace content for <code>{skill.slug}</code></h3>
        <p style={{ color: 'var(--dim)', fontSize: '.78rem', marginBottom: 12 }}>
          Replaces the on-disk bundle (SKILL.md + any extra files). The skill row, app assignments, and enabled state are preserved.
          Description re-syncs from the new SKILL.md frontmatter.
        </p>
        <label style={modalLabel}>Paste SKILL.md content</label>
        <textarea
          className="editable" rows={6} value={c} onChange={e => setC(e.target.value)}
          placeholder="---&#10;name: my-skill&#10;description: …&#10;---&#10;&#10;Body goes here."
          style={{ width: '100%', marginBottom: 10, fontFamily: 'monospace', fontSize: '.82rem' }}
        />
        <label style={modalLabel}>or upload a .md / .zip</label>
        <input type="file" accept=".md,.markdown,.zip" onChange={e => setF(e.target.files?.[0] || null)} style={{ marginBottom: 10 }} />
        {f && <span style={{ marginLeft: 8, fontSize: '.78rem', color: 'var(--dim)' }}>{f.name}</span>}
        <label style={modalLabel}>or fetch from URL</label>
        <input
          className="editable" value={u} onChange={e => setU(e.target.value)}
          placeholder="https://raw.githubusercontent.com/… or GitHub blob URL"
          style={{ width: '100%', marginBottom: 14, fontFamily: 'monospace', fontSize: '.78rem' }}
        />
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button
            className="btn btn-primary"
            disabled={empty}
            onClick={() => onSave({ content: c, url: u, bundle: f })}
          >Replace</button>
        </div>
      </div>
    </div>
  )
}

const modalBackdrop: React.CSSProperties = {
  position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 200,
  display: 'flex', alignItems: 'center', justifyContent: 'center',
}
const modalCard: React.CSSProperties = {
  background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
  padding: 20, minWidth: 360, maxWidth: 560, maxHeight: '85vh', overflow: 'auto',
}
const modalLabel: React.CSSProperties = {
  display: 'block', fontSize: '.75rem', color: 'var(--dim)', marginBottom: 4, fontWeight: 600,
}

interface AssignProps {
  skill: Skill
  allApps: AppOption[]
  onSave: (appSlugs: string[]) => void
  onCancel: () => void
}

function AssignAppsModal({ skill, allApps, onSave, onCancel }: AssignProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set(skill.apps || []))

  function toggle(slug: string) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(slug)) next.delete(slug); else next.add(slug)
      return next
    })
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 200,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onCancel}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
        padding: 20, minWidth: 320, maxWidth: 480, maxHeight: '80vh', overflow: 'auto',
      }} onClick={e => e.stopPropagation()}>
        <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: '1rem' }}>
          Assign apps to <code>{skill.slug}</code>
        </h3>
        <p style={{ color: 'var(--dim)', fontSize: '.8rem', marginBottom: 12 }}>
          The skill loads into each selected app's Builder, Improve, and Ask containers.
          Apps not selected get nothing.
        </p>

        {allApps.length === 0
          ? <div style={{ color: 'var(--dim)', fontSize: '.85rem' }}>No apps registered yet.</div>
          : <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 14 }}>
              {allApps.map(a => (
                <label key={a.slug} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 6px', borderRadius: 4, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={selected.has(a.slug)}
                    onChange={() => toggle(a.slug)}
                  />
                  <span>{a.name}</span>
                  <span style={{ marginLeft: 'auto', fontFamily: 'monospace', fontSize: '.75rem', color: 'var(--dim)' }}>{a.slug}</span>
                </label>
              ))}
            </div>
        }

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button className="btn btn-primary" onClick={() => onSave([...selected])}>Save</button>
        </div>
      </div>
    </div>
  )
}
