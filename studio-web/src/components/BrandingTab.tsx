import { useEffect, useRef, useState } from 'react'
import { adminApi } from '../adminApi'
import { useFlash, FocusTextarea } from './formHelpers'

/**
 * Brand context tab — moved out of Settings into AppStudio in v1.27.27
 * because the agents read this verbatim before generating any app code
 * (GET /api/settings/branding). It's AI-pipeline context, not chrome.
 */
export function BrandingTab() {
  const [guidelines, setGuidelines] = useState('')
  const [saved, flashSaved] = useFlash()
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    adminApi.get<{ value?: string }>('/api/settings/branding')
      .then(r => { if (r?.value) setGuidelines(r.value) }).catch(() => {})
  }, [])

  async function save() {
    await adminApi.put('/api/settings/branding', { value: guidelines }).catch(() => {})
    flashSaved()
  }

  function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => { setGuidelines(ev.target?.result as string) }
    reader.readAsText(file)
    e.target.value = ''
  }

  return (
    <div className="setting-card">
      <h3>Brand Guidelines</h3>
      <p>Paste your brand guidelines here — AI agents read this via <code>GET /api/settings/branding</code> before building apps.</p>
      <FocusTextarea
        value={guidelines}
        onChange={e => setGuidelines(e.target.value)}
        style={{ minHeight: 220 }}
      />
      <input ref={fileRef} type="file" accept=".txt,.md" style={{ display: 'none' }} onChange={onFileChange} />
      <div className="save-row">
        <button className="btn" onClick={() => fileRef.current?.click()}>Import from file</button>
        <button className="btn btn-accent" onClick={save}>Save Guidelines</button>
        {saved && <span className="saved-msg">Saved ✓</span>}
      </div>
    </div>
  )
}
