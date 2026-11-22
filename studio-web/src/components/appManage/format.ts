import { serverDate } from '../../utils/serverDate'

export function fmtBytes(n?: number | null): string {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(0)} KB`
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`
  return `${(n / 1073741824).toFixed(2)} GB`
}

/** A server timestamp ("YYYY-MM-DD HH:MM:SS" UTC) or an ISO string, as "3h ago". */
export function relTime(s?: string | null): string {
  if (!s) return ''
  const t = s.includes('T') ? new Date(s).getTime() : serverDate(s).getTime()
  const sec = Math.floor((Date.now() - t) / 1000)
  if (sec < 60) return 'just now'
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`
  return `${Math.floor(sec / 86400)}d ago`
}

export function fmtDuration(ms?: number | null): string {
  if (ms == null) return '—'
  const m = Math.floor(ms / 60000)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}

export function fmtUptime(ms?: number): string {
  if (!ms) return '—'
  return fmtDuration(ms)
}

export function fmtNum(n?: number | null, digits = 0): string {
  if (n == null) return '—'
  return n.toLocaleString(undefined, { maximumFractionDigits: digits })
}

export const errText = (e: unknown) => (e as Error)?.message || String(e)
