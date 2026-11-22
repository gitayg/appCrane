import { authHeaders } from '../../adminApi'

/** Fetch an authenticated document and hand it to the browser as a file. */
export async function downloadAuthed(path: string, fileName: string) {
  const r = await fetch(path, { headers: authHeaders() })
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    throw new Error(body?.error?.message || `HTTP ${r.status}`)
  }
  const url = URL.createObjectURL(await r.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
