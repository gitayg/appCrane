import { useEffect, type ReactNode } from 'react'

export function Modal({ title, onClose, children, width }: { title: string; onClose: () => void; children: ReactNode; width?: number }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="am2-modal-back" onClick={onClose}>
      <div className="am2-modal" style={width ? { width: `min(${width}px, 92vw)` } : undefined} role="dialog" aria-label={title} onClick={e => e.stopPropagation()}>
        <div className="am2-modal-head">
          <span>{title}</span>
          <button className="btn btn-xs" onClick={onClose}>Close</button>
        </div>
        <div className="am2-modal-body">{children}</div>
      </div>
    </div>
  )
}
