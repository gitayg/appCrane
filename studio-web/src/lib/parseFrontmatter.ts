// Mirror of server/services/skills.js parseSkillFrontmatter — same shape,
// runs in the browser so the skill upload form can pre-fill name / slug /
// description when the user picks a .md file or pastes SKILL.md content.
//
// Anthropic skill format is flat top-level scalars only. Supports plain
// `key: value`, single/double quoted values, and `|` / `>` block scalars.

export type Frontmatter = Record<string, string>

export function parseFrontmatter(content: string): Frontmatter {
  if (typeof content !== 'string') return {}
  const m = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  if (!m) return {}
  const out: Frontmatter = {}
  const lines = m[1].split(/\r?\n/)
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (!line.trim() || line.trim().startsWith('#')) { i++; continue }
    const kv = line.match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/)
    if (!kv) { i++; continue }
    const key = kv[1]
    let val = kv[2]
    if (val === '|' || val === '>') {
      const fold = val === '>'
      const buf: string[] = []
      i++
      while (i < lines.length && /^\s+/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s+/, ''))
        i++
      }
      val = fold ? buf.join(' ').trim() : buf.join('\n').trim()
    } else {
      i++
      const q = val.match(/^(['"])([\s\S]*)\1$/)
      if (q) val = q[2]
      val = val.trim()
    }
    out[key] = val
  }
  return out
}
