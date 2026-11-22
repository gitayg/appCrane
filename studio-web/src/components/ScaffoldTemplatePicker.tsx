// Template choice for the "+ New App" Managed Code prompt.
//
// The ids mirror SCAFFOLD_TEMPLATE_IDS in server/services/scaffoldTemplates.js
// and the `template` enum of appcrane_create_managed_app;
// test/scaffold-templates.test.js fails when they drift apart.

export type ScaffoldTemplateId = 'node-react' | 'python-fastapi' | 'static-site'

export const SCAFFOLD_TEMPLATES: { id: ScaffoldTemplateId; label: string; blurb: string }[] = [
  { id: 'node-react', label: 'Node + React', blurb: 'Express API and a Vite React UI, managed Postgres, MCP tools' },
  { id: 'python-fastapi', label: 'Python FastAPI', blurb: 'FastAPI in its own Dockerfile, managed Postgres, MCP tools' },
  { id: 'static-site', label: 'Static site', blurb: 'HTML/CSS/JS with admin-only pages, no database' },
]

const STACK_PHRASE = /Pick a small Vite \+ React \+\s+TS stack, /

/** The Managed Code prompt with the chosen template written into it; unchanged for null. */
export function applyScaffoldTemplate(prompt: string, id: ScaffoldTemplateId | null): string {
  if (!id) return prompt
  const line = `Create the app with appcrane_create_managed_app template="${id}" so it starts from\n  AppCrane's ${id} template (verified sign-in, roles, health check and tests\n  already wired), and follow the CLAUDE.md it commits. `
  return STACK_PHRASE.test(prompt) ? prompt.replace(STACK_PHRASE, line) : `${prompt}\n\n  ${line.trim()}`
}

export default function ScaffoldTemplatePicker({ value, onChange }: { value: ScaffoldTemplateId | null; onChange: (id: ScaffoldTemplateId | null) => void }) {
  const option = (id: ScaffoldTemplateId | null, label: string, blurb: string) => {
    const on = value === id
    return (
      <label
        key={id ?? 'none'}
        style={{
          display: 'flex', gap: 8, alignItems: 'flex-start', cursor: 'pointer', padding: '6px 10px', borderRadius: 7,
          border: `1px solid ${on ? 'var(--accent)' : 'var(--border)'}`, background: on ? 'rgba(59,130,246,.08)' : 'transparent',
        }}
      >
        <input type="radio" name="scaffold-template" checked={on} onChange={() => onChange(id)} style={{ marginTop: 3 }} />
        <span>
          <span style={{ fontWeight: 600, fontSize: '.82rem' }}>{label}</span>
          <span style={{ display: 'block', fontSize: '.74rem', color: 'var(--dim)' }}>{blurb}</span>
        </span>
      </label>
    )
  }
  return (
    <fieldset style={{ border: 'none', padding: 0, margin: '0 0 10px' }}>
      <legend style={{ fontSize: '.78rem', color: 'var(--dim)', marginBottom: 6 }}>Starter template</legend>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 6 }}>
        {SCAFFOLD_TEMPLATES.map((t) => option(t.id, t.label, t.blurb))}
        {option(null, 'No template', 'The agent picks a stack and writes everything')}
      </div>
    </fieldset>
  )
}
