import { useState } from 'react'

// Shown once, right after enrollment or regeneration. Only hashes are stored.
export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone?: () => void }) {
  const [copied, setCopied] = useState(false)
  const text = codes.join('\n')
  async function copy() {
    try { await navigator.clipboard.writeText(text); setCopied(true) } catch { setCopied(false) }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'appcrane-recovery-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <div>
      <p style={{ fontSize: '.85rem', margin: '8px 0' }}>
        Save these recovery codes somewhere safe. Each one signs you in once if you lose your authenticator.
        They will not be shown again.
      </p>
      <pre style={{ fontFamily: 'monospace', fontSize: '.95rem', lineHeight: 1.6, padding: 12, background: 'var(--surface, #1e2130)', borderRadius: 6, columns: 2 }}>{text}</pre>
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <button type="button" className="btn" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
        <button type="button" className="btn" onClick={download}>Download</button>
        {onDone && <button type="button" className="btn btn-accent" onClick={onDone}>I saved them</button>}
      </div>
    </div>
  )
}
